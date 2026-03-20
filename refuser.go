package refuser

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/log"
	"github.com/miekg/dns"
)

// CacheEntry 缓存条目结构 (仅在缓存启用时使用)
type CacheEntry struct {
	HitTTL   uint8 // 缓存条目产生拒绝时，原始TTL被丢弃，引入单独的 HitTTL 控制缓存生存时间
	InList   bool  // v0.3.2加入变量，表达是否命中列表，根据黑白名单模式，对应拦截或放行动作
	NotMatch uint8 // 仅在热更新外部列表文件时，标记与上一个列表不吻合的条目
}

// Refuser 插件的主结构体。
type Refuser struct {
	Next plugin.Handler // 将 DNS 查询请求透传给 Corefile 文件中 refuser 配置下方的插件
	mu   sync.RWMutex   // 锁用于保护内部状态 (规则/缓存/计数器)

	// 配置字段 (Config)
	Mode           string
	ConfigZones    []string // listzone 规则 (配置中定义)
	ListFile       string   // 列表文件路径 (空白配置时为空字符串)
	ExceptionZones []string // exceptzone 规则 (配置中定义)
	ExceptionsFile string   // 例外文件路径 (空白配置时为空字符串)
	Debug          bool
	ReloadInterval time.Duration // 热重载周期 (0: 禁用)

	// 限制字段 (默认均为 0，禁用)
	MaxRegexRules    int
	MaxWildcardRules int
	CacheRecordLimit int32 // 缓存记录上限 (0: 禁用缓存)
	CacheLimitFactor float64
	CacheFuseCycles  int32

	// 控制字段
	HitDecayInterval time.Duration

	// 运行时状态字段 (零开销优化: 仅 FQDN Trie 结构是核心)
	RulesList  *Trie // FQDN 规则 Trie (只有配置了 ListFile 才会被加载)
	Exceptions *Trie // 例外规则 Trie (只有配置了 ExceptionsFile 才会被加载)

	// 零开销优化：只有 Max...Rules > 0 时，这些切片才会被填充。
	WildcardRules []*rule          // 编译后的通配符规则列表
	RegexMatchers []*regexp.Regexp // 编译后的正则规则列表

	// 零开销优化：只有 CacheRecordLimit > 0 时，Cache 才会被初始化 (非 nil)
	Cache       map[string]*CacheEntry // 缓存 map
	CacheCount  int32
	IsFusing    bool
	FuseCounter int32

	// 分桶删除控制
	LastNotMatchCRC8        uint8 // 最后一个 NotMatch 标记的 CRC8 值 (用于确定删除起始点和随机延迟)
	LastNotMatchCRC8Low3Bit uint8
	CurrentDeleteBucket     int   // 注意此变量相关函数不符合需求，删除起点暂时考虑FirstNotMatchCRC8
	DeleteBucketCount       uint8 // 每秒删除的桶数量 (1-255, 默认 16)

	// 热加载和定时器
	ReloadTicker *time.Ticker
	DecayTicker  *time.Ticker
}

// ServeDNS 是插件的核心处理方法
func (r *Refuser) ServeDNS(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) (int, error) {
	if len(req.Question) == 0 {
		return dns.RcodeSuccess, nil
	}
	qname := req.Question[0].Name

	// 1. 检查缓存
	if r.Cache != nil {
		hit, code := r.cacheLookup(qname)
		if hit {
			if code == dns.RcodeRefused {
				// 缓存命中，拒绝
				r.logEvent(fmt.Sprintf("Cache hit, refusing: %s", qname))
				return r.writeRefused(w, req)
			}
			return plugin.NextOrFailure(r.Name(), r.Next, ctx, w, req)
		}
	}

	// 2. 决策响应
	responseCode := r.decideResponse(qname)

	switch responseCode {
	case dns.RcodeRefused:
		// 规则命中，决定拒绝
		if r.Cache != nil && !r.IsFusing {
			r.cacheInsert(qname, req.Id)
		}

		// r.logEvent(fmt.Sprintf("规则命中，拒绝: %s", qname))
		r.logEvent(fmt.Sprintf("Rule matched, refusing: %s", qname))
		return r.writeRefused(w, req)

	case dns.RcodeSuccess:
		// 规则决定放行
		return plugin.NextOrFailure(r.Name(), r.Next, ctx, w, req)

	default:
		return plugin.NextOrFailure(r.Name(), r.Next, ctx, w, req)
	}
}

// matchNonFqdnRules 检查 qname 是否匹配通配符或正则规则 (用于低频规则)
func (r *Refuser) matchNonFqdnRules(qname string) bool {
	// 归一化 qname (与 rules.go/rule.Match 保持一致)
	qname = strings.TrimSuffix(qname, ".")
	lowQname := strings.ToLower(qname)

	// 1. 正则匹配 (r.RegexMatchers)
	if r.MaxRegexRules > 0 && r.RegexMatchers != nil {
		for _, re := range r.RegexMatchers {
			// 正则表达式匹配
			if re.MatchString(lowQname) {
				// r.logEvent(fmt.Sprintf("%s 匹配正则规则: %s", lowQname, re.String()))
				r.logEvent(fmt.Sprintf("%s matched regex rule: %s", lowQname, re.String()))
				return true
			}
		}
	}

	// 2. 通配符匹配 (r.WildcardRules)
	if r.MaxWildcardRules > 0 && r.WildcardRules != nil {
		for _, rule := range r.WildcardRules {
			// rule.Match 实现了 V0.1 兼容的通配符逻辑
			if rule.Match(lowQname) {
				// r.logEvent(fmt.Sprintf("%s 匹配通配符规则: %s", lowQname, rule.raw))
				r.logEvent(fmt.Sprintf("%s matched wildcard rule: %s", lowQname, rule.raw))
				return true
			}
		}
	}

	return false
}

// decideResponse 检查 qname 是否匹配规则或例外，并返回 DNS Rcode
func (r *Refuser) decideResponse(qname string) int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// 调用 classify 函数对于列表的查找结果
	isRule, isException := r.classify(qname)

	// 黑名单模式,优先处理例外：命中例外 -> 必须放行 (PASS)
	if r.Mode == "blacklist" {
		if isException {
			// 命中例外规则 Trie (黑名单)，放行
			r.logEvent(fmt.Sprintf("Matched exception rule (blacklist mode), allowing: %s", qname))
			return dns.RcodeSuccess
		}
		// 否则，命中规则则拒绝
		if isRule {
			return dns.RcodeRefused
		}
		// 否则放行 (透传)
		return dns.RcodeSuccess
	}

	// whitelist
	// 命中规则 AND 未命中例外 -> PASS
	if isRule && !isException {
		// 命中主规则且未命中例外 (白名单)，放行
		r.logEvent(fmt.Sprintf("Matched main rule and not in exceptions (whitelist mode), allowing: %s", qname))
		return dns.RcodeSuccess
	}
	// 白名单模式其他所有情况都拒绝 (包括：1未命中规则；2命中规则 AND 命中例外；3仅命中例外)
	return dns.RcodeRefused
}

// Init 负责插件的最终初始化：首次加载规则和启动定时器
func (r *Refuser) Init() {
	// 1. 首次加载规则 (会根据 ListFile/ExceptionsFile 是否为空来决定是否构建 Trie)
	r.reloadList()

	// 2. 启动定时器 (零开销 CPU 优化: 只有满足条件才启动)
	if r.ReloadInterval > 0 || r.CacheRecordLimit > 0 {
		// r.logEvent("启动周期性定时器...")
		r.logEvent("Starting periodic timers...")
		go r.startTimers()
	} else {
		// r.logEvent("未配置定时重载或缓存，不启动周期性定时器")
		r.logEvent("No reload interval or cache enabled, periodic timers not started")
	}
}

// startTimers 启动周期性任务 (零开销 CPU 优化)
func (r *Refuser) startTimers() {
	// 只有在 CacheRecordLimit > 0 时，才启动 DecayTicker (核心时钟)
	if r.CacheRecordLimit > 0 {
		r.DecayTicker = time.NewTicker(r.HitDecayInterval)
	}

	// 只有在 ReloadInterval > 0 时，才启动 ReloadTicker
	if r.ReloadInterval > 0 {
		r.ReloadTicker = time.NewTicker(r.ReloadInterval)
	}

	for {
		select {
		// 监听 DecayTicker (缓存核心时钟和分桶删除)
		case t, ok := <-r.DecayTicker.C:
			if !ok {
				return
			} // Ticker 被 Stop
			// r.logEvent(fmt.Sprintf("Decay Ticker 触发: %v", t))
			r.logEvent(fmt.Sprintf("Decay ticker triggered: %v", t))
			r.decayTTL()

			// 分桶删除 (在核心时钟后错峰执行)
			go func() {
				time.Sleep(100 * time.Millisecond)
				r.deleteBuckets()
			}()

		// 监听 ReloadTicker (规则热重载)
		case t, ok := <-r.ReloadTicker.C:
			if !ok {
				return
			} // Ticker 被 Stop
			// r.logEvent(fmt.Sprintf("Reload Ticker 触发: %v", t))
			r.logEvent(fmt.Sprintf("Reload ticker triggered: %v", t))
			// 规则热重载
			go func() {
				time.Sleep(100 * time.Millisecond)
				r.reloadList()
			}()

			// 如果 DecayTicker 或 ReloadTicker 为 nil，对应的 case 将被跳过，
			// 从而 select 会等待两个 Ticker 中的一个。如果两个都为 nil，
			// 则此 goroutine 实际上永远不会启动（但我们在 Init 中已经确保至少有一个会启动）。
			// 为确保退出机制，最好监听一个 Context，但此处简化处理。
		}
	}
}

// logEvent 辅助函数 (六、日志与调试 - 零开销优化)
// 仅在 r.Debug=true 时，记录 DEBUG 级别的日志
func (r *Refuser) logEvent(event string) {
	if r.Debug {
		// 修正：直接调用 log 包提供的 Debugf 函数
		log.Debugf("[refuser] %s", event)
	}
}

// Name 返回插件名称
func (r *Refuser) Name() string { return "refuser" }

// writeRefused 构造并发送 REFUSED 响应
func (r *Refuser) writeRefused(w dns.ResponseWriter, req *dns.Msg) (int, error) {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeRefused)
	m.Authoritative = true
	w.WriteMsg(m)
	return dns.RcodeRefused, nil // 返回 Rcode，Metrics 插件会自动抓取到这个值
}
