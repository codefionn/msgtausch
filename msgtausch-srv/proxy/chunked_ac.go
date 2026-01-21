package proxy

import (
	"sync"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
)

// ChunkedTrie represents a hybrid chunked Aho-Corasick trie structure
// for handling large domain lists (>2048 entries) by splitting them into smaller chunks
type ChunkedTrie struct {
	Chunks          []*ahocorasick.Trie // Multiple AC tries, each containing a chunk of domains
	DomainList      []string            // Complete list of all domains (for debugging)
	ChunkSize       int                 // Number of domains per chunk
	TotalDomains    int                 // Total number of domains
	ChunkBoundaries []int               // Starting indices of each chunk in DomainList
	mutex           sync.RWMutex        // Protects concurrent access
}

// NewChunkedTrie creates a new chunked trie from a list of domains
// If the domain list is small (<= chunkSize), it creates a single trie (non-chunked)
// If the domain list is large (> chunkSize), it splits into multiple chunks
func NewChunkedTrie(domains []string, chunkSize int) *ChunkedTrie {
	if len(domains) == 0 {
		return &ChunkedTrie{
			Chunks:          []*ahocorasick.Trie{},
			DomainList:      domains,
			ChunkSize:       chunkSize,
			TotalDomains:    0,
			ChunkBoundaries: []int{},
		}
	}

	// If domain count is within single chunk limit, create single trie
	if len(domains) <= chunkSize {
		trie := ahocorasick.NewTrieBuilder().AddStrings(domains).Build()
		return &ChunkedTrie{
			Chunks:          []*ahocorasick.Trie{trie},
			DomainList:      domains,
			ChunkSize:       chunkSize,
			TotalDomains:    len(domains),
			ChunkBoundaries: []int{0},
		}
	}

	// For large domain lists, split into chunks
	return buildChunkedTrie(domains, chunkSize)
}

// buildChunkedTrie splits domains into chunks and builds separate tries
func buildChunkedTrie(domains []string, chunkSize int) *ChunkedTrie {
	numChunks := (len(domains) + chunkSize - 1) / chunkSize
	chunks := make([]*ahocorasick.Trie, numChunks)
	chunkBoundaries := make([]int, numChunks)

	logger.Info("Building chunked trie with %d domains split into %d chunks of ~%d domains each",
		len(domains), numChunks, chunkSize)

	for i := 0; i < numChunks; i++ {
		startIdx := i * chunkSize
		endIdx := startIdx + chunkSize
		if endIdx > len(domains) {
			endIdx = len(domains)
		}

		chunkDomains := domains[startIdx:endIdx]
		chunkBoundaries[i] = startIdx

		if len(chunkDomains) > 0 {
			builder := ahocorasick.NewTrieBuilder()
			chunks[i] = builder.AddStrings(chunkDomains).Build()

			memSize := estimateTrieMemorySize(chunks[i], len(chunkDomains))
			logger.Debug("Built chunk %d/%d with %d domains (memory: %s)",
				i+1, numChunks, len(chunkDomains), formatMemorySize(memSize))
		}
	}

	return &ChunkedTrie{
		Chunks:          chunks,
		DomainList:      domains,
		ChunkSize:       chunkSize,
		TotalDomains:    len(domains),
		ChunkBoundaries: chunkBoundaries,
	}
}

// MatchString searches for matches across all chunks
// Returns the first match found (if any) along with the chunk index and pattern index
func (ct *ChunkedTrie) MatchString(text string) (matchFound bool, chunkIdx, patternIdx int) {
	ct.mutex.RLock()
	defer ct.mutex.RUnlock()

	if len(ct.Chunks) == 0 {
		return false, -1, -1
	}

	// Search through each chunk sequentially
	for chunkIdx, chunk := range ct.Chunks {
		if chunk == nil {
			continue
		}

		matches := chunk.MatchString(text)
		if len(matches) > 0 {
			// Return the first match found
			return true, chunkIdx, int(matches[0].Pattern())
		}
	}

	return false, -1, -1
}

// GetMatchedDomain returns the actual domain string for a given pattern index
func (ct *ChunkedTrie) GetMatchedDomain(chunkIdx, patternIdx int) string {
	ct.mutex.RLock()
	defer ct.mutex.RUnlock()

	if chunkIdx < 0 || chunkIdx >= len(ct.ChunkBoundaries) {
		return ""
	}

	baseIdx := ct.ChunkBoundaries[chunkIdx]
	globalIdx := baseIdx + patternIdx

	if globalIdx < 0 || globalIdx >= len(ct.DomainList) {
		return ""
	}

	return ct.DomainList[globalIdx]
}

// GetMemoryUsage returns estimated memory usage of the chunked trie
type ChunkedTrieMemoryStats struct {
	TotalMemory        int64
	PerChunkMemory     []int64
	TotalDomains       int
	NumChunks          int
	AvgDomainsPerChunk float64
}

func (ct *ChunkedTrie) GetMemoryUsage() ChunkedTrieMemoryStats {
	ct.mutex.RLock()
	defer ct.mutex.RUnlock()

	stats := ChunkedTrieMemoryStats{
		TotalDomains: ct.TotalDomains,
		NumChunks:    len(ct.Chunks),
	}

	if stats.NumChunks > 0 {
		stats.AvgDomainsPerChunk = float64(stats.TotalDomains) / float64(stats.NumChunks)
	}

	for _, chunk := range ct.Chunks {
		if chunk != nil {
			chunkMem := estimateTrieMemorySize(chunk, 0) // 0 means estimate based on trie structure
			stats.TotalMemory += chunkMem
			stats.PerChunkMemory = append(stats.PerChunkMemory, chunkMem)
		}
	}

	return stats
}

// shouldUseChunking determines if chunking should be used based on domain count
func shouldUseChunking(domainCount int) bool {
	const chunkThreshold = 2048
	return domainCount > chunkThreshold
}
