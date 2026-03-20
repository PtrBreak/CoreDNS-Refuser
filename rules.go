package refuser

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// -----------------------------------------------------------------------------
// 一、辅助结构体 (Rules Helper Structs)

// rule 结构体 (V0.1 兼容性: 存储通配符规则的必要信息)
type rule struct {
	raw      string // 原始行 (用于 V0.1 的 Match 逻辑)
	pattern  string // 移除了 * 的字符串 (用于 V0.1 的 Match 逻辑)
	wildcard bool   // 标记是否为通配符
}

// Rule 辅助结构体 (用于 FQDN 规则)
type Rule struct {
	Value string
}

// ruleSet 结构体用于收集所有解析后的规则
type ruleSet struct {
	FqdnRules     []Rule
	WildcardRules []*rule
	RegexRules    []*regexp.Regexp
}

// ErrFileNotFound 是规则文件不存在的错误标识
var ErrFileNotFound = errors.New("file not found")

// -----------------------------------------------------------------------------
// 二、通配符匹配逻辑 (V0.1 兼容性)

// Match 检查域名 name 是否匹配 V0.1 风格的通配符规则。
// 仅用于 r.WildcardRules 切片匹配。
func (r *rule) Match(name string) bool {
	if r == nil || !r.wildcard {
		return false
	}

	// FQDN 归一化
	name = strings.TrimSuffix(name, ".")
	lowName := strings.ToLower(name)

	p := r.pattern
	raw := strings.ToLower(r.raw)

	// V0.1 风格的通配符匹配:

	// 1. *foo* 或 *foo?bar* -> contains 匹配
	if strings.HasPrefix(raw, "wildcard:*") && strings.HasSuffix(raw, "*") {
		return strings.Contains(lowName, p)
	}

	// 2. *foo 或 wildcard:*foo -> suffix 匹配
	if strings.HasPrefix(raw, "wildcard:*") {
		return strings.HasSuffix(lowName, p)
	}

	// 3. foo* 或 wildcard:foo* -> prefix 匹配
	if strings.HasSuffix(raw, "*") {
		return strings.HasPrefix(lowName, p)
	}

	// 4. 其他包含 '*' 的情况，回退到 contains 匹配。
	if strings.Contains(raw, "*") {
		return strings.Contains(lowName, p)
	}

	return false
}

// -----------------------------------------------------------------------------
// 三、规则加载和热重载

// buildTrie 辅助函数：根据 FQDN 规则构建 SuffixTrie
func (r *Refuser) buildTrie(rules []Rule) *Trie {
	// 零开销内存优化: 如果没有规则，返回 nil Trie
	if len(rules) == 0 {
		return nil
	}
	trie := NewTrie()
	for _, rule := range rules {
		fqdn := rule.Value
		if strings.HasSuffix(fqdn, ".") {
			fqdn = fqdn[:len(fqdn)-1]
		}

		// 1. 反转标签顺序 (SuffixTrie 核心)
		parts := strings.Split(fqdn, ".")
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}

		// 2. 插入到 Trie
		current := trie.Root
		for _, part := range parts {
			if part == "" {
				continue
			}
			node, exists := current.Children[part]
			if !exists {
				node = NewTrieNode()
				current.Children[part] = node
			}
			current = node
		}
		current.IsRule = true
	}
	return trie
}

// loadRulesFromFile 负责文件 I/O，并根据关键字进行规则分离
func (r *Refuser) loadRulesFromFile(path string) (*ruleSet, error) {
	if path == "" {
		return &ruleSet{}, nil
	}

	// 文件 I/O 逻辑
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return &ruleSet{}, ErrFileNotFound
	}
	if err != nil {
		// r.logEvent(fmt.Sprintf("打开规则文件 %s 失败: %v", path, err))
		r.logEvent(fmt.Sprintf("Failed to open rule file %s: %v", path, err))
		return nil, err
	}
	defer f.Close()

	rules := &ruleSet{}
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 归一化：移除末尾的点
		line = strings.TrimSuffix(line, ".")

		// 规则校验和分离 (使用大写关键字)
		if strings.HasPrefix(line, "REGEX:") {
			// 1. 正则规则
			if r.MaxRegexRules > 0 && len(rules.RegexRules) < r.MaxRegexRules {
				p := line[len("REGEX:"):]
				re, err := regexp.Compile(p)
				if err != nil {
					// r.logEvent(fmt.Sprintf("跳过无效正则规则 '%s': %v", line, err))
					r.logEvent(fmt.Sprintf("Skipping invalid regex rule '%s': %v", line, err))
					continue
				}
				rules.RegexRules = append(rules.RegexRules, re)
			} else {
				// r.logEvent(fmt.Sprintf("跳过正则规则 '%s': 达到上限或未启用", line))
				r.logEvent(fmt.Sprintf("Skipping regex rule '%s': limit reached or regex rules disabled", line))
			}
			continue
		}

		if strings.HasPrefix(line, "WILDCARD:") {
			// 2. 通配符规则
			if r.MaxWildcardRules > 0 && len(rules.WildcardRules) < r.MaxWildcardRules {
				rawPattern := line[len("WILDCARD:"):]
				normalizedPattern := strings.ToLower(rawPattern)

				if !strings.Contains(normalizedPattern, "*") {
					// r.logEvent(fmt.Sprintf("通配符规则 '%s' 中未找到 '*'，跳过", line))
					r.logEvent(fmt.Sprintf("Skipping wildcard rule '%s': no '*' found", line))
					continue
				}

				rules.WildcardRules = append(rules.WildcardRules, &rule{
					raw:      rawPattern,
					pattern:  strings.ReplaceAll(normalizedPattern, "*", ""),
					wildcard: true,
				})
			} else {
				// r.logEvent(fmt.Sprintf("跳过通配符规则 '%s': 达到上限或未启用", line))
				r.logEvent(fmt.Sprintf("Skipping wildcard rule '%s': limit reached or wildcard rules disabled", line))
			}
			continue
		}

		// 3. FQDN 规则 (无前导关键字)
		low := strings.ToLower(line)

		// 零开销检查：丢弃无关键字前导的通配/正则规则
		if strings.Contains(low, "*") || strings.Contains(low, "^") || strings.Contains(low, "$") {
			// r.logEvent(fmt.Sprintf("丢弃无关键字前导的通配/正则规则: %s", line))
			r.logEvent(fmt.Sprintf("Discarding wildcard/regex rule without required prefix: %s", line))
			continue
		}

		// 纯 FQDN 规则，用于构建 Trie
		rules.FqdnRules = append(rules.FqdnRules, Rule{Value: low})
	}

	if err := scanner.Err(); err != nil {
		// r.logEvent(fmt.Sprintf("读取规则文件 %s 失败: %v", path, err))
		r.logEvent(fmt.Sprintf("Failed to read rule file %s: %v", path, err))
		return nil, err
	}
	return rules, nil
}

// 0.3.2 增加
// classify returns:
//
//	isRule:      fqdn is in rules (Trie or wildcard or regex)
//	isException: fqdn is in exceptions (Trie only)
func (r *Refuser) classify(qname string) (bool, bool) {
	lowQname := strings.ToLower(qname)

	// 1. Exception match (Trie only)
	isException := false
	if r.Exceptions != nil {
		isException = r.Exceptions.Lookup(lowQname)
	}

	// 2. Rule match (Trie)
	isRule := false
	if r.RulesList != nil {
		isRule = r.RulesList.Lookup(lowQname)
	}

	// 3. Wildcard / regex match (only if Trie did not match)
	if !isRule {
		isRule = r.matchNonFqdnRules(qname)
	}

	return isRule, isException
}

// reloadList 周期性热重载所有规则和例外 (原子替换逻辑)
func (r *Refuser) reloadList() {

	// 准备新的 Trie (构建新的规则树)
	newRulesTrie := &Trie{}
	newExceptionsTrie := &Trie{}

	// 准备新的非 FQDN 规则列表
	newWildcardRules := make([]*rule, 0)
	newRegexMatchers := make([]*regexp.Regexp, 0)

	// -------------------------------------------------------------------------
	// 1. 核心逻辑：先加载静态配置的 Zones (最高优先级 FQDN 规则)
	// -------------------------------------------------------------------------

	// 1.1 静态规则 (listzone)
	for _, fqdn := range r.ConfigZones {
		normalizedFqdn := strings.ToLower(strings.TrimSuffix(fqdn, "."))
		newRulesTrie.Insert(normalizedFqdn)
		// r.logEvent(fmt.Sprintf("V0.3.1 静态规则: %s", normalizedFqdn))
		r.logEvent(fmt.Sprintf("Corefile rule: %s", normalizedFqdn))
	}

	// 1.2 静态例外 (exceptzone)
	for _, fqdn := range r.ExceptionZones {
		normalizedFqdn := strings.ToLower(strings.TrimSuffix(fqdn, "."))
		newExceptionsTrie.Insert(normalizedFqdn)
		// r.logEvent(fmt.Sprintf("V0.3.1 静态例外: %s", normalizedFqdn))
		r.logEvent(fmt.Sprintf("Corefile exception: %s", normalizedFqdn))
	}

	// -------------------------------------------------------------------------
	// 2. 加载文件中的规则和例外 (loadRulesFromFile 已在内部进行限制检查)
	// -------------------------------------------------------------------------

	// 2.1 加载主规则文件
	if r.ListFile != "" {
		// r.logEvent(fmt.Sprintf("加载主规则文件: %s", r.ListFile))
		r.logEvent(fmt.Sprintf("Loading external rule file: %s", r.ListFile))
		mainRules, err := r.loadRulesFromFile(r.ListFile) // 假设 loadRulesFromFile 返回 *ruleSet

		if err != nil && !errors.Is(err, ErrFileNotFound) {
			// r.logEvent(fmt.Sprintf("加载主规则文件失败: %v", err))
			r.logEvent(fmt.Sprintf("Failed to load external rule file: %v", err))
			// 失败时，不中断流程，只使用已加载的静态规则
		} else if mainRules != nil {
			// 合并 FQDN 规则到 Trie (静态规则在前，文件规则在后)
			for _, rule := range mainRules.FqdnRules {
				// 保持标准化域名计算，确保此变量存在且被使用
				normalizedFqdn := strings.ToLower(strings.TrimSuffix(rule.Value, "."))
				// 使用标准化后的域名
				newRulesTrie.Insert(normalizedFqdn)
			}
			// 合并非 FQDN 规则到 Slices
			newWildcardRules = append(newWildcardRules, mainRules.WildcardRules...)
			newRegexMatchers = append(newRegexMatchers, mainRules.RegexRules...)
		}
	}

	// 2.2 加载例外文件
	if r.ExceptionsFile != "" {
		// r.logEvent(fmt.Sprintf("加载例外文件: %s", r.ExceptionsFile))
		r.logEvent(fmt.Sprintf("Loading exception file: %s", r.ExceptionsFile))
		exceptionRules, eErr := r.loadRulesFromFile(r.ExceptionsFile)

		if eErr != nil && !errors.Is(eErr, ErrFileNotFound) {
			// r.logEvent(fmt.Sprintf("加载例外规则文件失败: %v", eErr))
			r.logEvent(fmt.Sprintf("Failed to load exception file: %v", eErr))
		} else if exceptionRules != nil {
			// 合并例外 FQDN 规则到 Exceptions Trie (静态例外在前，文件例外在后)
			for _, rule := range exceptionRules.FqdnRules {
				// 标准化域名计算
				normalizedFqdn := strings.ToLower(strings.TrimSuffix(rule.Value, "."))
				// 使用标准化后的域名
				newExceptionsTrie.Insert(normalizedFqdn)
			}
		}
	}

	// -------------------------------------------------------------------------

	// 3. 缓存标记 (原子性操作：标记旧缓存中不再匹配新规则的条目)
	if r.Cache != nil {
		// 假设 markNotMatch 接受 Trie 结构
		r.markNotMatch(newRulesTrie, newExceptionsTrie)
	}

	// 4. 原子性替换 (交换指针，完成热重载)
	r.mu.Lock()
	defer r.mu.Unlock()

	r.RulesList = newRulesTrie
	r.Exceptions = newExceptionsTrie
	r.WildcardRules = newWildcardRules
	r.RegexMatchers = newRegexMatchers

	// r.logEvent(fmt.Sprintf("规则加载完成: FQDN=%d, 通配符=%d, 正则=%d, 例外=%d",
	r.logEvent(fmt.Sprintf(
		"Rule loading completed: FQDN=%d, wildcard=%d, regex=%d, exceptions=%d",
		newRulesTrie.Size(), len(newWildcardRules), len(newRegexMatchers), newExceptionsTrie.Size()))
}
