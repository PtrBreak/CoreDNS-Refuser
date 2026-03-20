package refuser

import (
	"testing"
)

func TestTrieLookup_SuffixMatching(t *testing.T) {
	// 1. 创建 Trie 并插入规则
	trie := NewTrie()
	if trie.Root == nil {
		t.Fatalf("NewTrie() 应该返回一个非空的 Root 节点")
	}

	rulesToInsert := []string{
		"example.com",
		"sub.example.net.", // 包含末尾点
		"GOOgle.cn",        // 包含大写
		"a.b.c.d",
	}

	for _, rule := range rulesToInsert {
		trie.Insert(rule)
	}

	// 2. 查找测试 (Lookup)
	testCases := []struct {
		name     string
		fqdn     string
		expected bool // 预期是否命中
	}{
		// --- 命中测试 (Expected TRUE) ---
		{"T01_精确匹配", "example.com", true},
		{"T02_子域名匹配", "www.example.com", true},
		{"T03_多级子域名匹配", "mail.www.example.com.", true},
		{"T04_末尾点子域名", "mail.sub.example.net", true},
		{"T05_多级精确匹配", "a.b.c.d.", true},
		{"T06_大小写不敏感", "QUERY.GOOgle.cn", true},
		{"T07_子域名匹配多级规则", "x.a.b.c.d", true},
		{"T08_大小写混合子域名", "x.y.Example.com", true},

		// --- 未命中测试 (Expected FALSE) ---
		{"T10_完全不匹配", "baidu.com", false},
		{"T11_部分匹配-长", "ex.example.co", false}, // 规则中没有 example.co
		{"T12_非子域名", "com.example", false},   // 确保不是简单的字符串包含
		{"T13_更深层级但不匹配", "x.x.y.z.w", false},
		{"T14_规则的一部分", "example", false}, // 确保只插入了 example.com，查询 example 不命中
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := trie.Lookup(tc.fqdn)
			if result != tc.expected {
				t.Errorf("Lookup(%q) 期望结果: %t, 实际结果: %t", tc.fqdn, tc.expected, result)
			}
		})
	}
}