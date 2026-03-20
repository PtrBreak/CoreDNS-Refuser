package refuser

import (
	"strconv" 
	"time"
	
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	// "github.com/miekg/dns"
)

func init() { plugin.Register("refuser", setup) }

// Syntax in Corefile:
//
// refuser {
//		mode blacklist|whitelist	# 默认: blacklist
//
//		# Corefile 内静态域名规则，优先级高于文件
//		listzone fqdn.name 			# 静态规则域名
//		exceptzone fqdn.name		# 静态例外域名
//
//		listfile /path/to/rules.txt	# 规则列表文件 (替代 blacklist/whitelist)
//		exceptions /path/to/exc.txt	# 例外文件路径
//
//		# --- 规则限制 ---
//		max_regex_rules limit		# 正则规则数量限制 (int)
//		max_wildcard_rules limit	# 通配符规则数量限制 (int)
//
//		# --- 缓存控制 ---
//		cache_record_limit limit	# 缓存最大记录数 (int)
//		cache_limit_factor factor	# 熔断阈值比例 (float)
//		cache_fuse_cycles cycles	# 熔断周期数 (int)
//		decay_interval seconds		# 缓存衰减间隔 (秒)
//		delete_bucket_count count	# 分桶删除数量 (1-255)
//
//		# --- 通用参数 ---
//		reload seconds				# 热重载周期 (默认 0，禁用)
//		debug true|false			# 额外日志输出
// }
//
func setup(c *caddy.Controller) error {
	r := new(Refuser)
	
	// --------------------------------------------------------
	// 📌 默认值设置
	// --------------------------------------------------------
	r.Mode = "blacklist" 
	r.Debug = false
	r.CacheRecordLimit = 0
	r.ListFile = ""
	r.ExceptionsFile = ""
	r.MaxRegexRules = 0
	r.MaxWildcardRules = 0
	r.ReloadInterval = 0 * time.Second

	r.HitDecayInterval = 10 * time.Second
	r.CacheLimitFactor = 2.0
	r.CacheFuseCycles = 30
	r.DeleteBucketCount = 16
	r.ConfigZones = []string{}		// V0.3.1 初始化
	r.ExceptionZones = []string{}	// V0.3.1 初始化
	
	// --------------------------------------------------------
	// 📌 配置解析
	// --------------------------------------------------------
	
	for c.Next() {
		for c.NextBlock() {
			switch c.Val() {
			case "mode":
				if !c.NextArg() { return c.ArgErr() }
				r.Mode = c.Val()
				if r.Mode != "blacklist" && r.Mode != "whitelist" {
					return c.Errf("refuser: mode must be 'blacklist' or 'whitelist', got '%s'", r.Mode)
				}
			
			// V0.3.1 新增：静态 FQDN 规则
			case "listzone":
				if !c.NextArg() { return c.ArgErr() }
				r.ConfigZones = append(r.ConfigZones, c.Val())
				
			case "exceptzone":
				if !c.NextArg() { return c.ArgErr() }
				r.ExceptionZones = append(r.ExceptionZones, c.Val())
			
			// V0.3 文件配置
			case "listfile":
				if !c.NextArg() { return c.ArgErr() }
				r.ListFile = c.Val()
				
			case "exceptions":
				if !c.NextArg() { return c.ArgErr() }
				r.ExceptionsFile = c.Val()
				
			// --- 规则限制参数 ---
			case "max_regex_rules":
				if !c.NextArg() { return c.ArgErr() }
				v, err := parseIntParam(c.Val())
				if err != nil { return plugin.Error("refuser", c.Errf("invalid max_regex_rules value: %v", err)) }
				r.MaxRegexRules = v
				
			case "max_wildcard_rules":
				if !c.NextArg() { return c.ArgErr() }
				v, err := parseIntParam(c.Val())
				if err != nil { return plugin.Error("refuser", c.Errf("invalid max_wildcard_rules value: %v", err)) }
				r.MaxWildcardRules = v
				
			// --- 缓存参数 ---
			case "cache_record_limit":
				if !c.NextArg() { return c.ArgErr() }
				v, err := parseIntParam(c.Val())
				if err != nil { return plugin.Error("refuser", c.Errf("invalid cache_record_limit: %v", err)) }
				r.CacheRecordLimit = int32(v)
				
			case "cache_limit_factor":
				if !c.NextArg() { return c.ArgErr() }
				v, err := parseFloatParam(c.Val())
				if err != nil { return plugin.Error("refuser", c.Errf("invalid cache_limit_factor: %v", err)) }
				if v <= 0.0 { return c.Err("refuser: cache_limit_factor must be positive") }
				r.CacheLimitFactor = v
				
			case "cache_fuse_cycles":
				if !c.NextArg() { return c.ArgErr() }
				v, err := parseIntParam(c.Val())
				if err != nil { return plugin.Error("refuser", c.Errf("invalid cache_fuse_cycles: %v", err)) }
				r.CacheFuseCycles = int32(v)
				
			case "decay_interval":
				if !c.NextArg() { return c.ArgErr() }
				v, err := parseIntParam(c.Val())
				if err != nil { return plugin.Error("refuser", c.Errf("invalid decay_interval: %v", err)) }
				r.HitDecayInterval = time.Duration(v) * time.Second 
				
			case "delete_bucket_count":
				if !c.NextArg() { return c.ArgErr() }
				v, err := parseIntParam(c.Val())
				if err != nil { return plugin.Error("refuser", c.Errf("invalid delete_bucket_count: %v", err)) }
				if v < 1 || v > 255 {
					return c.Err("refuser: delete_bucket_count must be between 1 and 255")
				}
				r.DeleteBucketCount = uint8(v)

			// --- 通用参数 ---
			case "reload": 
				if !c.NextArg() { return c.ArgErr() }
				v, err := parseIntParam(c.Val())
				if err != nil { return plugin.Error("refuser", c.Errf("invalid reload value: %v", err)) }
				r.ReloadInterval = time.Duration(v) * time.Second 
				
			case "debug":
				if !c.NextArg() { return c.ArgErr() }
				r.Debug = (c.Val() == "true")
				
			// --- 废弃/旧版参数兼容性检查 ---
			case "blacklist", "whitelist", "follow_subdomains", "cache_ttl", "reload_interval":
				// 兼容性检查和日志输出 (r.logEvent 在 Init/setup 之后才可用，此处仅消耗参数并由用户代码处理警告)
				if c.NextArg() { /* 消耗掉参数 */ }
				// 实际的 warning 或 error 应当在 setup 之前或之后通过其他机制报告，此处仅返回 caddy error
				// return c.Errf("refuser: '%s' is deprecated and ignored in V0.3.", c.Val()) 
			
			default:
				return c.Errf("unknown property '%s'", c.Val())
			}
		}
	}
	
	// --------------------------------------------------------
	// 📌 运行时初始化和插件链设置 (标准 CoreDNS 模式)
	// --------------------------------------------------------

	// 1. 缓存初始化 (零开销内存优化: 只有启用时才分配 map)
	if r.CacheRecordLimit > 0 {
		r.Cache = make(map[string]*CacheEntry)
	}
	
	// 2. 插件链设置 (修正：使用标准的插件注册模式)
	cfg := dnsserver.GetConfig(c) // 获取当前 server 块的配置 [cite: 20]
	cfg.AddPlugin(func(next plugin.Handler) plugin.Handler {
		r.Next = next
		// 调用 Init() 方法进行初始化和定时器启动
		r.Init()
		return r

	})
	
	return nil
}

// 辅助函数：解析整数参数 (负数视为 0)
func parseIntParam(s string) (int, error) {
	v, err := strconv.Atoi(s)
	if err != nil { return 0, err }
	if v < 0 { return 0, nil }
	return v, nil
}

// 辅助函数：解析浮点数参数 (负数视为 0.0)
func parseFloatParam(s string) (float64, error) {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil { return 0.0, err }
	if v < 0.0 { return 0.0, nil }
	return v, nil
}