package proxy

import (
	"container/list"
	"crypto/tls"
	"hash/fnv"
	"sync"
)

const numShards = 64
const maxEntriesPerShard = 256

type ShardedCertCache struct {
	shards []*certCacheShard
}

type certCacheShard struct {
	cache      map[string]*list.Element
	order      *list.List
	cacheMu    sync.RWMutex
	waitGroups map[string]*sync.WaitGroup
	waitMu     sync.RWMutex
}

type certEntry struct {
	host string
	cert *tls.Certificate
}

func NewShardedCertCache() *ShardedCertCache {
	sc := &ShardedCertCache{
		shards: make([]*certCacheShard, numShards),
	}
	for i := 0; i < numShards; i++ {
		sc.shards[i] = &certCacheShard{
			cache:      make(map[string]*list.Element),
			order:      list.New(),
			waitGroups: make(map[string]*sync.WaitGroup),
		}
	}
	return sc
}

func (sc *ShardedCertCache) getShard(host string) *certCacheShard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(host))
	return sc.shards[h.Sum32()%numShards]
}

func (sc *ShardedCertCache) Get(host string) (*tls.Certificate, bool) {
	shard := sc.getShard(host)
	shard.cacheMu.Lock()
	defer shard.cacheMu.Unlock()
	if elem, ok := shard.cache[host]; ok {
		shard.order.MoveToFront(elem)
		return elem.Value.(*certEntry).cert, true
	}
	return nil, false
}

func (sc *ShardedCertCache) Set(host string, cert *tls.Certificate) {
	shard := sc.getShard(host)
	shard.cacheMu.Lock()
	defer shard.cacheMu.Unlock()
	if elem, ok := shard.cache[host]; ok {
		shard.order.MoveToFront(elem)
		elem.Value.(*certEntry).cert = cert
		return
	}
	entry := &certEntry{host: host, cert: cert}
	elem := shard.order.PushFront(entry)
	shard.cache[host] = elem
	for shard.order.Len() > maxEntriesPerShard {
		oldest := shard.order.Back()
		if oldest != nil {
			shard.order.Remove(oldest)
			delete(shard.cache, oldest.Value.(*certEntry).host)
		}
	}
}

func (sc *ShardedCertCache) GetOrWait(host string) (*tls.Certificate, bool, *sync.WaitGroup) {
	shard := sc.getShard(host)
	shard.cacheMu.RLock()
	if elem, ok := shard.cache[host]; ok {
		shard.cacheMu.RUnlock()
		shard.cacheMu.Lock()
		shard.order.MoveToFront(elem)
		shard.cacheMu.Unlock()
		return elem.Value.(*certEntry).cert, true, nil
	}
	shard.cacheMu.RUnlock()

	shard.waitMu.RLock()
	wg, isGenerating := shard.waitGroups[host]
	shard.waitMu.RUnlock()

	if isGenerating {
		return nil, true, wg
	}

	return nil, false, nil
}

func (sc *ShardedCertCache) StartGeneration(host string) *sync.WaitGroup {
	shard := sc.getShard(host)
	shard.waitMu.Lock()
	defer shard.waitMu.Unlock()
	if _, exists := shard.waitGroups[host]; exists {
		return nil
	}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	shard.waitGroups[host] = wg
	return wg
}

func (sc *ShardedCertCache) FinishGeneration(host string) {
	shard := sc.getShard(host)
	shard.waitMu.Lock()
	delete(shard.waitGroups, host)
	shard.waitMu.Unlock()
}

func (sc *ShardedCertCache) SetWithLock(host string, cert *tls.Certificate) bool {
	shard := sc.getShard(host)
	shard.cacheMu.Lock()
	defer shard.cacheMu.Unlock()
	if _, ok := shard.cache[host]; ok {
		return false
	}
	entry := &certEntry{host: host, cert: cert}
	elem := shard.order.PushFront(entry)
	shard.cache[host] = elem
	for shard.order.Len() > maxEntriesPerShard {
		oldest := shard.order.Back()
		if oldest != nil {
			shard.order.Remove(oldest)
			delete(shard.cache, oldest.Value.(*certEntry).host)
		}
	}
	return true
}

func (sc *ShardedCertCache) Len() int {
	total := 0
	for _, shard := range sc.shards {
		shard.cacheMu.RLock()
		total += shard.order.Len()
		shard.cacheMu.RUnlock()
	}
	return total
}
