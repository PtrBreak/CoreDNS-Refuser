package refuser

import (
	"fmt"
	"hash/crc32"

	// "strings"

	"github.com/miekg/dns"
)

// -----------------------------------------------------------------------------
// 四、缓存机制 (Cache != nil 守卫)

func (r *Refuser) cacheInsert(fqdn string, id uint16) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// 1. 检查限制
	if r.checkCacheLimit(id) {
		return
	}

	// 2. 插入或更新缓存
	isRule, isException := r.classify(fqdn)
	inList := isRule && !isException

	if entry, exists := r.Cache[fqdn]; exists {
		entry.HitTTL = ((entry.HitTTL << 1) | 1) & 0xFF
		entry.NotMatch = 0x00
		entry.InList = inList
		return
	}

	entry := &CacheEntry{
		HitTTL:   0x3F,
		NotMatch: 0x00,
		InList:   inList,
	}
	r.Cache[fqdn] = entry
	r.CacheCount++
}

// cacheLookup 查找缓存
func (r *Refuser) cacheLookup(fqdn string) (bool, int) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, exists := r.Cache[fqdn]
	if !exists {
		return false, 0
	}

	entry.HitTTL = ((entry.HitTTL << 1) | 1) & 0xFF
	entry.NotMatch = 0x00

	// derive final decision from Mode + InList
	if r.Mode == "blacklist" {
		if entry.InList {
			return true, dns.RcodeRefused
		}
		return true, dns.RcodeSuccess
	}

	// whitelist
	if entry.InList {
		return true, dns.RcodeSuccess
	}
	return true, dns.RcodeRefused
}

// decayTTL 周期性衰减 TTL (核心时钟)
func (r *Refuser) decayTTL() {
	// 零开销 CPU 优化：在 setup.go 中，如果 r.Cache == nil，此函数将不会被定时器调用
	r.mu.Lock()
	defer r.mu.Unlock()

	// 1. 熔断期间处理
	if r.IsFusing {
		r.applyFuse()
	} else {
		burstLimit := int32(float64(r.CacheRecordLimit) * r.CacheLimitFactor)
		if r.CacheCount > burstLimit {
			r.IsFusing = true
			r.FuseCounter = r.CacheFuseCycles
			// 日志记录超过burst，进入熔断状态
			// r.logEvent("达到 burst，缓存熔断")
			r.logEvent("Cache burst threshold reached, entering fuse state")
			r.applyFuse()
		}
	}

	// 2. 衰减 TTL
	r.deleteExpiredEntries()

	// 3. 熔断恢复检查
	if r.IsFusing {
		r.releaseFuse()
	}
}

// deleteExpiredEntries 衰减 TTL 并删除过期条目
func (r *Refuser) deleteExpiredEntries() {
	// 仅在 r.Cache != nil 时执行
	for fqdn, entry := range r.Cache {
		entry.HitTTL >>= 1
		if entry.HitTTL == 0x00 {
			delete(r.Cache, fqdn)
			r.CacheCount--
		}
	}
}

// -----------------------------------------------------------------------------
// 五、缓存熔断

// checkCacheLimit 缓存写入限制检查
func (r *Refuser) checkCacheLimit(id uint16) bool {
	limit := r.CacheRecordLimit

	if r.IsFusing {
		return true
	}

	if r.CacheCount > limit {
		if id&0x01 == 0 {
			// 日志记录缓存超限，丢弃50%写入
			// r.logEvent("超过 limit，随机丢弃 50% 写入")
			r.logEvent("Cache limit exceeded, randomly dropping 50% of insert attempts")
			return true
		}
	}

	return false
}

// applyFuse 熔断触发逻辑
func (r *Refuser) applyFuse() {
	r.FuseCounter--
}

// releaseFuse 熔断解除逻辑
func (r *Refuser) releaseFuse() {
	if r.FuseCounter <= 0 {
		r.IsFusing = false
		r.FuseCounter = 0
		// 日志记录从熔断中恢复
		// r.logEvent("熔断恢复")
		r.logEvent("Fuse state cleared, cache operations restored")
	}
}

// markNotMatch 在规则重载时，根据InList变化来标记缓存条目。
// 签名：接收 *Trie 指针类型，以匹配调用方
func (r *Refuser) markNotMatch(newRules *Trie, newExceptions *Trie) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.Cache == nil {
		return
	}

	for fqdn, entry := range r.Cache {
		oldInList := entry.InList

		// 1. 获取新规则下的最终决策结果
		isRule := newRules.Lookup(fqdn)
		isException := newExceptions.Lookup(fqdn)
		newInList := isRule && !isException

		// 2. 标记条件以CacheEntry结构体InList值为准
		if oldInList != newInList {
			crc8 := r.calculateCRC8(fqdn)
			if crc8 == 0 {
				entry.NotMatch = 0xFF
			} else {
				entry.NotMatch = crc8
			}
		}
	}
}

// deleteBuckets 分桶删除缓存
func (r *Refuser) deleteBuckets() {
	// 零开销 CPU 优化：在 setup.go 中，如果 r.Cache == nil，此函数将不会被定时器调用
	r.mu.Lock()
	defer r.mu.Unlock()

	deletedCount := 0
	bucketCount := int(r.DeleteBucketCount)

	// 直接赋值为 1 (0x01)，消除复杂的计算和类型转换错误
	if r.CurrentDeleteBucket == 0 {
		r.CurrentDeleteBucket = 1 // 确保起始点为 0x01 (int 类型)
	}

	for i := 0; i < bucketCount; i++ {
		targetCRC8 := r.CurrentDeleteBucket
		for fqdn, entry := range r.Cache {
			if entry.NotMatch == uint8(targetCRC8) || (targetCRC8 == 0xFF && entry.NotMatch == 0xFF) {
				delete(r.Cache, fqdn)
				r.CacheCount--
				deletedCount++
			}
		}

		// 使用 if/else 避免 MOD 运算 (消除 DIV 指令开销)
		if r.CurrentDeleteBucket == 255 {
			r.CurrentDeleteBucket = 1 // 从 0xFF (255) 绕回到 0x01 (1)
		} else {
			r.CurrentDeleteBucket++ // 正常推进
		}
	}

	// 日志分桶删除了多少个条目
	// r.logEvent(fmt.Sprintf("分桶删除 %d 个缓存条目", deletedCount))
	r.logEvent(fmt.Sprintf("Bucket deletion removed %d cache entries", deletedCount))
}

// calculateCRC8 辅助函数
func (r *Refuser) calculateCRC8(fqdn string) uint8 {
	h := crc32.NewIEEE()
	h.Write([]byte(fqdn))
	return uint8(h.Sum32() & 0xFF)
}
