package refuser

import (
	"context"
	"regexp"
	"sync"
	"testing"
	"time"

	_ "github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

// RcodePass 是一个测试常量
const RcodePass = 0

// MockHandler 实现 plugin.Handler 接口
type MockHandler struct{}

func (h *MockHandler) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	return 0, nil
}
func (h *MockHandler) Name() string { return "mock" }

// -----------------------------------------------------------------------------
// 测试辅助函数
// -----------------------------------------------------------------------------

func setupRefuserForTest(mode string, rules []string, exceptions []string) *Refuser {
	const testBucketCount = 16
	const testDecayInterval = 10 * time.Second
	const testLimitFactor = 2.0
	const testFuseCycles = 30

	r := &Refuser{
		Cache: make(map[string]*CacheEntry),
		mu:    sync.RWMutex{},

		Mode: mode,
		Next: &MockHandler{},

		CacheRecordLimit: 0,
		Debug:            false,

		DeleteBucketCount:       testBucketCount,
		CurrentDeleteBucket:     1,
		HitDecayInterval:        testDecayInterval,
		CacheLimitFactor:        testLimitFactor,
		CacheFuseCycles:         testFuseCycles,
		IsFusing:                false,
		FuseCounter:             0,
		LastNotMatchCRC8:        0,
		LastNotMatchCRC8Low3Bit: 0,

		ReloadTicker: nil,
		DecayTicker:  nil,
	}

	// 初始化规则 Trie
	rulesTrie := NewTrie()
	for _, fqdn := range rules {
		rulesTrie.Insert(fqdn)
	}
	r.RulesList = rulesTrie

	// 初始化例外 Trie
	exTrie := NewTrie()
	for _, fqdn := range exceptions {
		exTrie.Insert(fqdn)
	}
	r.Exceptions = exTrie

	// 初始化非 FQDN 规则
	r.WildcardRules = make([]*rule, 0)
	r.RegexMatchers = make([]*regexp.Regexp, 0)

	return r
}

// -----------------------------------------------------------------------------
// v0.3.2 新增测试：classify() 语义验证
// -----------------------------------------------------------------------------

func TestClassify_Basic(t *testing.T) {
	r := setupRefuserForTest("blacklist",
		[]string{"example.com"},
		[]string{"safe.com"},
	)

	isRule, isExc := r.classify("www.example.com")
	if !isRule || isExc {
		t.Fatalf("www.example.com 期望 isRule=true, isException=false，实际: %v %v", isRule, isExc)
	}

	isRule, isExc = r.classify("safe.com")
	if isRule || !isExc {
		t.Fatalf("safe.com 期望 isRule=false, isException=true，实际: %v %v", isRule, isExc)
	}
}

// -----------------------------------------------------------------------------
// v0.3.2 新增测试：缓存命中语义（Mode + InList → Rcode）
// -----------------------------------------------------------------------------

func TestCacheLookup_WithInListAndMode(t *testing.T) {
	r := setupRefuserForTest("blacklist", nil, nil)
	r.CacheRecordLimit = 100

	fqdn := "test.example.com."

	// 手工插入缓存条目
	r.Cache[fqdn] = &CacheEntry{
		HitTTL:   0x3F,
		InList:   true,
		NotMatch: 0x00,
	}

	// 黑名单模式：InList=true → Refused
	hit, code := r.cacheLookup(fqdn)
	if !hit || code != dns.RcodeRefused {
		t.Fatalf("blacklist + InList=true 期望 Refused，实际 hit=%v code=%d", hit, code)
	}

	// 切换模式为 whitelist
	r.Mode = "whitelist"
	hit, code = r.cacheLookup(fqdn)
	if !hit || code != dns.RcodeSuccess {
		t.Fatalf("whitelist + InList=true 期望 Success，实际 hit=%v code=%d", hit, code)
	}

	// 再测试 InList=false
	r.Cache[fqdn].InList = false

	r.Mode = "blacklist"
	hit, code = r.cacheLookup(fqdn)
	if !hit || code != dns.RcodeSuccess {
		t.Fatalf("blacklist + InList=false 期望 Success，实际 hit=%v code=%d", hit, code)
	}

	r.Mode = "whitelist"
	hit, code = r.cacheLookup(fqdn)
	if !hit || code != dns.RcodeRefused {
		t.Fatalf("whitelist + InList=false 期望 Refused，实际 hit=%v code=%d", hit, code)
	}
}

// -----------------------------------------------------------------------------
// v0.3.2 新增测试：热更新差异标记 markNotMatch()
// -----------------------------------------------------------------------------

func TestMarkNotMatch_OnRuleChange(t *testing.T) {
	r := setupRefuserForTest("blacklist", []string{"example.com"}, nil)
	r.CacheRecordLimit = 100
	r.Cache = make(map[string]*CacheEntry)

	fqdn := "www.example.com"

	// 初始缓存条目：InList=true
	r.Cache[fqdn] = &CacheEntry{
		HitTTL:   0x3F,
		InList:   true,
		NotMatch: 0x00,
	}

	// 新规则：空（example.com 被移除）
	newRules := NewTrie()
	newExceptions := NewTrie()

	r.markNotMatch(newRules, newExceptions)

	entry := r.Cache[fqdn]
	if entry.NotMatch == 0x00 {
		t.Fatalf("规则变化后，缓存条目应被标记 NotMatch，实际仍为 0x00")
	}
}

// -----------------------------------------------------------------------------
// v0.3.1 原有测试：缓存衰减与删除（保持不变）
// -----------------------------------------------------------------------------

func TestCacheDecayAndDeletion(t *testing.T) {
	r := setupRefuserForTest("blacklist", []string{}, []string{})
	r.CacheRecordLimit = 100

	fqdn1 := "a.com"

	r.cacheInsert(fqdn1, 1)
	if r.CacheCount != 1 {
		t.Fatalf("CacheCount 期望 1，实际 %d", r.CacheCount)
	}

	r.decayTTL()
	e1, exists1 := r.Cache[fqdn1]
	if !exists1 || e1 == nil {
		t.Fatalf("衰减测试失败：条目 %s 消失", fqdn1)
	}
	if e1.HitTTL != 0x1F {
		t.Errorf("Decay #1 失败: TTL 期望 0x1F，实际 %x", e1.HitTTL)
	}

	for i := 0; i < 4; i++ {
		r.decayTTL()
	}

	e1Final, existsFinal := r.Cache[fqdn1]
	if !existsFinal || e1Final == nil {
		t.Fatalf("错误：5 次衰减后 %s 意外被删除", fqdn1)
	}
	if e1Final.HitTTL == 0 {
		t.Errorf("Decay 耗尽失败: TTL 不应为 0")
	}

	e1Final.NotMatch = 0x01
	initialCount := r.CacheCount
	for i := 0; i < 16; i++ {
		r.deleteBuckets()
	}

	t.Logf("分桶删除完成。初始数量: %d, 最终数量: %d", initialCount, r.CacheCount)
}

// -----------------------------------------------------------------------------
// v0.3.1 原有测试：决策语义（保持不变）
// -----------------------------------------------------------------------------

func TestDecideResponse_Semantics(t *testing.T) {
	rules := []string{"example.com", "banned.net"}
	exceptions := []string{"safe.com", "local.banned.net"}

	testCases := []struct {
		name      string
		mode      string
		queryFQDN string
		expected  int
	}{
		{"B01_命中规则-应拒绝", "blacklist", "www.example.com", dns.RcodeRefused},
		{"B02_未命中规则-应透传", "blacklist", "www.safe.net", RcodePass},
		{"B03_例外优先级-应透传", "blacklist", "mail.safe.com", RcodePass},
		{"B04_规则命中但被例外覆盖-应透传", "blacklist", "test.local.banned.net", RcodePass},

		{"W01_命中规则-应透传", "whitelist", "example.com", RcodePass},
		{"W02_子域名命中规则-应透传", "whitelist", "mail.example.com", RcodePass},
		{"W03_未命中规则-应拒绝", "whitelist", "unknown.net", dns.RcodeRefused},
		{"W04_命中规则且命中例外-应拒绝", "whitelist", "local.banned.net", dns.RcodeRefused},
		{"W05_仅命中例外-应拒绝", "whitelist", "safe.com", dns.RcodeRefused},
		{"W06_大小写透传", "whitelist", "MAIL.example.com.", RcodePass},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := setupRefuserForTest(tc.mode, rules, exceptions)
			result := r.decideResponse(tc.queryFQDN)

			if tc.expected == dns.RcodeRefused {
				if result != dns.RcodeRefused {
					t.Errorf("期望 REFUSED，实际 %d", result)
				}
			} else {
				if result == dns.RcodeRefused {
					t.Errorf("期望 PASS，实际 %d", result)
				}
			}
		})
	}
}
