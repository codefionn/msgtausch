package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
	"github.com/codefionn/msgtausch/msgtausch-srv/proxy"
)

var version string

func main() {
	cfg, configPath := parseFlagsAndConfig()
	runProxy(cfg, configPath)
}

// parseFlagsAndConfig handles CLI flags, environment, logging, and config loading.
func parseFlagsAndConfig() (cfg *config.Config, configPath string) {
	versionFlag := flag.Bool("version", false, "Print version and exit")
	versionShortFlag := flag.Bool("v", false, "Print version and exit (shorthand)")
	configPathPtr := flag.String("config", "config.json", "Path to configuration file (supports .json and .hcl formats)")
	envfile := flag.String("envfile", "", "Path to env file to load environment variables")
	debugMode := flag.Bool("debug", false, "Enable debug logging")
	flag.Parse()

	if *versionFlag || *versionShortFlag {
		if version == "" {
			version = "dev"
		}
		fmt.Println("msgtausch version:", version)
		os.Exit(0)
	}

	if *envfile != "" {
		if err := loadEnvFile(*envfile); err != nil {
			logger.Fatal("Failed to load envfile: %v", err)
		}
		logger.Info("Loaded environment variables from %s", *envfile)
	}

	if *debugMode {
		logger.SetLevel(logger.DEBUG)
		logger.Debug("Debug logging enabled")
	}

	logger.Info("Starting msgtausch proxy server")
	logger.Debug("Using configuration file: %s", *configPathPtr)

	cfg, err := config.LoadConfig(*configPathPtr)
	if err != nil {
		logger.Warn("Could not load config file: %v. Using environment variables.", err)
		cfg, err = config.LoadConfig("")
		if err != nil {
			logger.Fatal("Failed to load configuration: %v", err)
		}
	}

	logger.Debug("Configuration loaded successfully")
	if len(cfg.Servers) > 0 {
		for i, server := range cfg.Servers {
			logger.Debug("Server %d: %s on %s", i, server.Type, server.ListenAddress)
		}
	} else {
		logger.Debug("No servers configured")
	}
	logger.Debug("Timeout: %d seconds", cfg.TimeoutSeconds)
	logger.Debug("Max connections: %d", cfg.MaxConcurrentConnections)

	return cfg, *configPathPtr
}

// runProxy starts and manages the proxy server, including signal handling and reloads.
func runProxy(cfg *config.Config, configPath string) {
	proxyInstance := proxy.NewProxy(cfg)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	proxyRunning := true
	shutdownChan := make(chan struct{})

	startProxy := func(_ *config.Config) {
		go func() {
			logger.Info("Starting proxy server...")
			if err := proxyInstance.Start(); err != nil {
				logger.Fatal("Proxy server error: %v", err)
			}
			shutdownChan <- struct{}{}
		}()
	}

	startProxy(cfg)
	currentCfg := cfg

	for {
		sig := <-sigChan
		switch sig {
		case syscall.SIGHUP:
			logger.Info("Received SIGHUP: reloading configuration...")
			newCfg, err := config.LoadConfig(configPath)
			if err != nil {
				logger.Error("Failed to reload config: %v (keeping current config)", err)
				continue
			}
			if !config.HasChanged(currentCfg, newCfg) {
				logger.Info("Config unchanged after reload; not restarting proxy.")
				continue
			}
			logger.Info("Config changed. Restarting proxy...")
			if err := proxyInstance.Stop(); err != nil {
				logger.Error("Error stopping proxy for reload: %v", err)
			}
			proxyInstance = proxy.NewProxy(newCfg)
			startProxy(newCfg)
			currentCfg = newCfg
			logger.Info("Proxy restarted with new configuration.")
		case syscall.SIGINT, syscall.SIGTERM:
			logger.Info("Received signal %v, shutting down proxy server...", sig)
			if proxyRunning {
				if err := proxyInstance.Stop(); err != nil {
					logger.Error("Error during shutdown: %v", err)
				}
			}
			logger.Info("Proxy server shutdown complete")
			return
		}
	}
}

// loadEnvFile reads a .env-style file and sets environment variables
func loadEnvFile(path string) error {
	cleanPath := filepath.Clean(path)
	if !filepath.IsAbs(cleanPath) {
		absPath, err := filepath.Abs(cleanPath)
		if err != nil {
			return fmt.Errorf("invalid file path: %w", err)
		}
		cleanPath = absPath
	}
	f, err := os.Open(cleanPath)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			logger.Error("Error closing env file: %v", closeErr)
		}
	}()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		if setErr := os.Setenv(key, val); setErr != nil {
			logger.Error("Error setting environment variable %s: %v", key, setErr)
		}
	}
	return scanner.Err()
}
