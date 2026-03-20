package refuser

import (
	"strings"
)

// TrieNode 存储 Trie 中的一个节点。
type TrieNode struct {
	Children map[string]*TrieNode
	IsRule   bool
}

// Trie 是 SuffixTrie 结构的根。
type Trie struct {
	Root *TrieNode
}

// NewTrieNode 创建并初始化一个 TrieNode。
func NewTrieNode() *TrieNode {
	return &TrieNode{
		Children: make(map[string]*TrieNode),
		IsRule:   false,
	}
}

// NewTrie 创建并返回一个新的 Trie 结构。
func NewTrie() *Trie {
	return &Trie{
		Root: NewTrieNode(),
	}
}

// Insert 插入 FQDN 到 Trie
func (t *Trie) Insert(fqdn string) {
	if t.Root == nil {
		t.Root = NewTrieNode()
	}

	// 1. 标准化 FQDN 并按 '.' 分割
	normalizedFQDN := strings.ToLower(strings.TrimSuffix(fqdn, "."))
	parts := strings.Split(normalizedFQDN, ".")

	// 2. 反转 parts 数组以实现后缀匹配 (从顶级域名 TLD 开始匹配)
	current := t.Root
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if part == "" {
			continue // 跳过空部分
		}
		
		node, exists := current.Children[part]
		if !exists {
			node = NewTrieNode()
			current.Children[part] = node
		}
		current = node
	}
	current.IsRule = true // 标记路径的终点为规则
}

// Size 返回 Trie 中规则的数量
func (t *Trie) Size() int {
	if t.Root == nil {
		return 0
	}
	
	// DFS 遍历并计数 IsRule 为 true 的节点
	count := 0
	stack := []*TrieNode{t.Root}
	
	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if node.IsRule {
			count++
		}

		for _, child := range node.Children {
			stack = append(stack, child)
		}
	}
	return count
}

// Lookup 查找 FQDN 是否存在于 Trie 中 (从尾部开始匹配，支持通配符)。
// FQDN 例如 "www.example.com." 会被反转为 "com", "example", "www" 进行匹配。
// 如果 Trie 中存在 ".com" 或 ".example.com" 的规则，则命中。
func (t *Trie) Lookup(fqdn string) bool {
	// 根节点为空，直接返回
	if t.Root == nil {
		return false
	}

	// 1. 标准化 FQDN 并按 '.' 分割
	// 去除末尾的 '.' 并转换为小写，然后分割
	normalizedFQDN := strings.ToLower(strings.TrimSuffix(fqdn, "."))
	parts := strings.Split(normalizedFQDN, ".")

	// 2. 反转 parts 数组以实现后缀匹配 (从顶级域名 TLD 开始匹配)
	// "www.example.com" -> ["com", "example", "www"]
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}

	node := t.Root

	// 3. 遍历 Trie
	for _, part := range parts {
		// 忽略空字符串段 (例如如果 FQDN 是 ".")
		if part == "" {
			continue
		}
		
		// 尝试匹配当前 part
		if nextNode, ok := node.Children[part]; ok {
			node = nextNode
			
			// 如果当前节点 IsRule 为真，则表示命中了一个规则（例如匹配到 "com"）
			if node.IsRule {
				return true
			}
		} else {
			// 路径中断，未找到匹配规则
			return false
		}
	}
	
	// 匹配到最后的节点，检查该节点本身是否被标记为规则
	return node.IsRule
}