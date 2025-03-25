package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"time"

	msgtausch_simulation "github.com/codefionn/msgtausch/msgtausch-simulation"
	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
)

func main() {
	minutes := flag.Int("minutes", 0, "Run simulation for N minutes, printing only seeds that cause errors")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	stats := flag.Bool("stats", false, "Print detailed statistics for each simulation run")
	enableForwards := flag.Bool("enable-forwards", false, "Enable proxy forwards in simulation")
	flag.Parse()

	setupLogging(*verbose)

	if *minutes > 0 {
		runTimedSimulation(*minutes, *verbose, *stats, *enableForwards)
		return
	}

	// Single-run mode (original behavior)
	runSingleSimulation(*stats, *enableForwards)
}

func setupLogging(verbose bool) {
	logger.SetLevel(logger.FATAL)
	if verbose {
		logger.SetLevel(logger.DEBUG)
	}
}

func runTimedSimulation(minutes int, verbose, stats, enableForwards bool) {
	numCPU := runtime.GOMAXPROCS(0)
	logger.Info("Running with GOMAXPROCS=%d", numCPU)

	numRunners := numCPU%8 + 1
	end := time.Now().Add(time.Duration(minutes) * time.Minute)

	var wg sync.WaitGroup
	var execute, totalSuccessful, totalErrors int
	var mu sync.Mutex
	var hasError bool

	setupInterruptHandler(&mu, &execute, &totalSuccessful, &totalErrors)

	startTime := time.Now()
	for time.Now().Before(end) {
		seed := time.Now().UnixNano()
		for range numRunners {
			wg.Add(1)
			go runSingleWorker(seed, stats, enableForwards, verbose, &wg, &mu, &hasError, &totalSuccessful, &totalErrors, &execute)
			seed++ // Ensure unique seeds for parallel runs
		}
		wg.Wait()
		mu.Lock()
		execute += numRunners
		mu.Unlock()
	}

	printSummary(time.Since(startTime), execute, totalSuccessful, totalErrors)

	if hasError {
		fmt.Fprintln(os.Stderr, "At least one simulation failed.")
		os.Exit(1)
	}
}

func setupInterruptHandler(mu *sync.Mutex, execute, totalSuccessful, totalErrors *int) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		mu.Lock()
		fmt.Fprintf(os.Stderr, "Simulation interrupted after %d runs (Successful: %d, Errors: %d)\n", *execute, *totalSuccessful, *totalErrors)
		mu.Unlock()
		os.Exit(1)
	}()
}

func runSingleWorker(currentSeed int64, stats, enableForwards, verbose bool, wg *sync.WaitGroup, mu *sync.Mutex, hasError *bool, totalSuccessful, totalErrors, execute *int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "Panic with seed %d: %v\n", currentSeed, r)
			mu.Lock()
			*hasError = true
			*totalErrors++
			mu.Unlock()
		}
		wg.Done()
	}()

	if stats {
		runWithStats(currentSeed, enableForwards, verbose, mu, hasError, totalSuccessful, totalErrors)
	} else {
		runWithoutStats(currentSeed, enableForwards, mu, hasError, totalSuccessful, totalErrors)
	}

	if verbose {
		mu.Lock()
		logger.Info("Completed simulation %d (Total: %d, Success: %d, Errors: %d)", currentSeed, *execute, *totalSuccessful, *totalErrors)
		mu.Unlock()
	}
}

func runWithStats(currentSeed int64, enableForwards, verbose bool, mu *sync.Mutex, hasError *bool, totalSuccessful, totalErrors *int) {
	simStats, err := msgtausch_simulation.RunSimulationWithStats(currentSeed, enableForwards)
	mu.Lock()
	defer mu.Unlock()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Seed %d failed: %v\n", currentSeed, err)
		*hasError = true
		*totalErrors++
	} else {
		*totalSuccessful++
		if verbose {
			printDetailedStats(simStats)
		}
	}
}

func runWithoutStats(currentSeed int64, enableForwards bool, mu *sync.Mutex, hasError *bool, totalSuccessful, totalErrors *int) {
	err := msgtausch_simulation.RunSimulation(currentSeed, enableForwards)
	mu.Lock()
	defer mu.Unlock()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Seed %d failed: %v\n", currentSeed, err)
		*hasError = true
		*totalErrors++
	} else {
		*totalSuccessful++
	}
}

func printSummary(duration time.Duration, execute, totalSuccessful, totalErrors int) {
	fmt.Printf("Simulation Summary:\n")
	fmt.Printf("  Duration: %v\n", duration)
	fmt.Printf("  Total Runs: %d\n", execute)
	fmt.Printf("  Successful: %d (%.1f%%)\n", totalSuccessful, float64(totalSuccessful)/float64(execute)*100)
	fmt.Printf("  Failed: %d (%.1f%%)\n", totalErrors, float64(totalErrors)/float64(execute)*100)
	fmt.Printf("  Rate: %.1f runs/second\n", float64(execute)/duration.Seconds())
}

func runSingleSimulation(stats, enableForwards bool) {
	seed, err := parseSeedFromArgs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid seed argument: %v\n", err)
		os.Exit(1)
	}

	if stats {
		runSingleWithStats(seed, enableForwards)
	} else {
		runSingleWithoutStats(seed, enableForwards)
	}

	fmt.Println("Simulation completed successfully.")
}

func parseSeedFromArgs() (int64, error) {
	args := flag.Args()
	if len(args) > 0 {
		return strconv.ParseInt(args[0], 10, 64)
	}
	seed := time.Now().UnixNano()
	fmt.Printf("No seed provided, using current time: %d\n", seed)
	return seed, nil
}

func runSingleWithStats(seed int64, enableForwards bool) {
	simStats, err := msgtausch_simulation.RunSimulationWithStats(seed, enableForwards)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Simulation failed: %v\n", err)
		os.Exit(1)
	}
	printDetailedStats(simStats)
}

func runSingleWithoutStats(seed int64, enableForwards bool) {
	err := msgtausch_simulation.RunSimulation(seed, enableForwards)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Simulation failed: %v\n", err)
		os.Exit(1)
	}
}

func printDetailedStats(stats *msgtausch_simulation.SimulationStats) {
	fmt.Printf("\n=== Simulation Statistics (Seed: %d) ===\n", stats.Seed)
	fmt.Printf("Total Requests: %d\n", stats.TotalRequests)
	fmt.Printf("Requests Not Forwarded: %d\n", stats.RequestsNotForwarded)
	fmt.Printf("Forwards Used: %d\n", stats.ForwardsUsed)
	fmt.Printf("Proxy Chain Length: %d\n", stats.ProxyChainLength)
	fmt.Printf("WebSocket Connections: %d (Expected: %d)\n", stats.WebSocketConnections, stats.ExpectedWebSocketConns)
	fmt.Printf("Unrecoverable Errors: %d\n", stats.UnrecoverableErrors)

	if len(stats.TargetServerStats) > 0 {
		fmt.Printf("\n--- Target Server Statistics ---\n")
		for i, target := range stats.TargetServerStats {
			fmt.Printf("Server %d (%s):\n", i+1, target.URL)
			fmt.Printf("  Requests: %d\n", target.RequestCount)
			fmt.Printf("  WebSocket Connections: %d\n", target.WebSocketConnCount)
			if len(target.ErrorCounts) > 0 {
				fmt.Printf("  Error Counts:\n")
				for errorType, count := range target.ErrorCounts {
					fmt.Printf("    %s: %d\n", errorType, count)
				}
			}
		}
	}

	if len(stats.ErrorCountsByTarget) > 0 {
		fmt.Printf("\n--- Error Summary by Target ---\n")
		for targetURL, errorCounts := range stats.ErrorCountsByTarget {
			fmt.Printf("Target: %s\n", targetURL)
			for errorType, count := range errorCounts {
				fmt.Printf("  %s: %d\n", errorType, count)
			}
		}
	}
	fmt.Printf("==========================================\n\n")
}
