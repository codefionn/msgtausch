// Command memtest starts the msgtausch proxy with a domains-url blocklist and
// periodically reports memory usage. It exists to reproduce and profile the
// reported runaway memory growth (1.9-2.4 GiB) of the forward proxy when a
// large remote domain blocklist is configured.
//
// Usage:
//
//	go run ./cmd/memtest \
//	  -url https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts \
//	  -format plain \
//	  -refresh 30 \
//	  -interval 10
//
// pprof is served on http://127.0.0.1:6060/debug/pprof/ so heap profiles can
// be captured while it runs:
//
//	go tool pprof http://127.0.0.1:6060/debug/pprof/heap
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
	"github.com/codefionn/msgtausch/msgtausch-srv/proxy"
)

func main() {
	blocklistURL := flag.String("url", "",
		"blocklist URL (empty = use the built-in local synthetic list)")
	formatStr := flag.String("format", "plain",
		"blocklist format: plain|rpz|wildcard|adblock")
	listen := flag.String("listen", "127.0.0.1:18080", "proxy listen address")
	pprofAddr := flag.String("pprof", "127.0.0.1:6060", "pprof/http listen address")
	refresh := flag.Int("refresh", 60, "cache refresh interval in seconds (low = stress refresh path)")
	ttl := flag.Int("ttl", 300, "cache entry TTL in seconds")
	interval := flag.Int("interval", 10, "memory report interval in seconds")
	forceGC := flag.Bool("force-gc", true, "run runtime.GC() before each memory report (separates leak from uncollected garbage)")
	rps := flag.Int("rps", 50, "requests per second to drive through the proxy (triggers blocklist classification)")
	bigList := flag.Int("biglist", 200000, "number of synthetic domains served at the built-in /blocklist.txt")
	debugMode := flag.Bool("debug", false, "enable debug logging")
	flag.Parse()

	if *debugMode {
		logger.SetLevel(logger.DEBUG)
	}

	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{Type: config.ProxyTypeStandard, ListenAddress: *listen, Enabled: true},
		},
		TimeoutSeconds: 30,
		Classifiers: map[string]config.Classifier{
			"blocklist-url": &config.ClassifierDomainsURL{
				URL:    *blocklistURL,
				Format: config.DomainsURLFormat(*formatStr),
			},
		},
		Blocklist: &config.ClassifierRef{Id: "blocklist-url"},
		Cache: config.CacheConfig{
			Enabled:          true,
			DefaultTTL:       *ttl,
			RefreshInterval:  *refresh,
			HTTPTimeout:      60,
			MaxRetries:       3,
			RetryDelay:       5,
			ChunkedACEnabled: true,
			ChunkSize:        2048,
			ChunkThreshold:   2048,
		},
	}

	go func() {
		logger.Info("pprof listening on http://%s/debug/pprof/", *pprofAddr)
		if err := http.ListenAndServe(*pprofAddr, nil); err != nil {
			logger.Error("pprof server error: %v", err)
		}
	}()

	// Local target server: serves "ok" and, at /blocklist.txt, a large
	// synthetic domain list so the test is self-contained (no internet needed).
	mux := http.NewServeMux()
	mux.HandleFunc("/blocklist.txt", func(w http.ResponseWriter, _ *http.Request) {
		for i := 0; i < *bigList; i++ {
			fmt.Fprintf(w, "blocked-%d.example.org\n", i)
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	target := &http.Server{Addr: "127.0.0.1:18090", Handler: mux}
	go func() {
		if err := target.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("target server error: %v", err)
		}
	}()
	if *blocklistURL == "" {
		*blocklistURL = "http://127.0.0.1:18090/blocklist.txt"
		cfg.Classifiers["blocklist-url"].(*config.ClassifierDomainsURL).URL = *blocklistURL
	}

	p := proxy.NewProxy(cfg)
	go func() {
		logger.Info("starting proxy on %s with blocklist %s (format=%s)", *listen, *blocklistURL, *formatStr)
		if err := p.Start(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("proxy error: %v", err)
		}
	}()

	// Drive traffic through the proxy so the blocklist classifier actually runs.
	go func() {
		time.Sleep(2 * time.Second)
		proxyURL, _ := url.Parse("http://" + *listen)
		client := &http.Client{
			Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
			Timeout:   10 * time.Second,
		}
		tick := time.NewTicker(time.Second / time.Duration(max(*rps, 1)))
		defer tick.Stop()
		n := 0
		for range tick.C {
			n++
			// Hit the local target so the request actually completes; the
			// blocklist classifier runs on every request regardless of host.
			req, _ := http.NewRequest("GET", "http://127.0.0.1:18090/?n="+strconv.Itoa(n), nil)
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(time.Duration(*interval) * time.Second)
	defer ticker.Stop()

	start := time.Now()
	var m runtime.MemStats
	for {
		select {
		case <-sigChan:
			logger.Info("shutting down")
			_ = p.Close()
			return
		case <-ticker.C:
			if *forceGC {
				runtime.GC()
			}
			runtime.ReadMemStats(&m)
			fmt.Printf("[%6.0fs] HeapAlloc=%s HeapInuse=%s HeapSys=%s HeapObjects=%d StackInuse=%s Sys=%s NumGC=%d Goroutines=%d\n",
				time.Since(start).Seconds(),
				hsize(m.HeapAlloc), hsize(m.HeapInuse), hsize(m.HeapSys),
				m.HeapObjects, hsize(m.StackInuse), hsize(m.Sys),
				m.NumGC, runtime.NumGoroutine())
		}
	}
}

func hsize(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
