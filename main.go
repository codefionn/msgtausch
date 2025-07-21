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

type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

var version string

func main() {
	cfg, configPaths := parseFlagsAndConfig()
	runProxy(cfg, configPaths)
}

// parseFlagsAndConfig handles CLI flags, environment, logging, and config loading.
func parseFlagsAndConfig() (cfg *config.Config, configPaths []string) {
	versionFlag := flag.Bool("version", false, "Print version and exit")
	versionShortFlag := flag.Bool("v", false, "Print version and exit (shorthand)")
	configs := stringSliceFlag{}
	flag.Var(&configs, "config", "Path to configuration file (supports .json and .hcl formats). Can be specified multiple times, later configs take precedence")
	envfile := flag.String("envfile", "", "Path to env file to load environment variables")
	debugMode := flag.Bool("debug", false, "Enable debug logging")
	traceMode := flag.Bool("trace", false, "Enable trace logging")
	flag.Parse()

	if len(configs) == 0 {
		configs = append(configs, "config.json")
	}

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
	if *traceMode {
		logger.SetLevel(logger.TRACE)
		logger.Debug("Trace logging enabled")
	}

	logger.Info("Starting msgtausch proxy server")
	logger.Debug("Using configuration files: %s", strings.Join(configs, ", "))

	cfg, err := loadConfigsWithFallback(configs)
	if err != nil {
		logger.Fatal("Failed to load any configuration: %v", err)
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

	return cfg, configs
}

// runProxy starts and manages the proxy server, including signal handling and reloads.
func runProxy(cfg *config.Config, configPaths []string) {
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
			newCfg, err := loadConfigsWithFallback(configPaths)
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

// loadConfigsWithFallback tries to load configs in order, with later configs taking precedence.
// If a config fails to parse, it falls back to the previous working config.
// If no config works, it returns an error.
func loadConfigsWithFallback(configPaths []string) (*config.Config, error) {
	var finalConfig *config.Config
	successCount := 0

	for i, configPath := range configPaths {
		cfg, err := config.LoadConfig(configPath)
		if err != nil {
			logger.Warn("Failed to load config file %s: %v", configPath, err)
			if i == 0 {
				logger.Debug("Trying environment variables for first config")
				cfg, err = config.LoadConfig("")
				if err != nil {
					logger.Warn("Failed to load config from environment variables: %v", err)
					continue
				}
			} else {
				continue
			}
		}

		logger.Debug("Successfully loaded config from: %s", configPath)
		finalConfig = cfg
		successCount++
	}

	if finalConfig == nil {
		return nil, fmt.Errorf("no configuration could be loaded from any of the provided paths: %s", strings.Join(configPaths, ", "))
	}

	logger.Info("Configuration loaded, %d of %d config files successful (later configs take precedence)", successCount, len(configPaths))
	return finalConfig, nil
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
