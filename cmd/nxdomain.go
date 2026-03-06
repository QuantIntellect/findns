package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/SamNet-dev/findns/internal/scanner"
	"github.com/spf13/cobra"
)

var nxdomainCmd = &cobra.Command{
	Use:   "nxdomain",
	Short: "Test NXDOMAIN integrity (detect DNS hijacking)",
	RunE:  runNXDomain,
}

func init() {
	rootCmd.AddCommand(nxdomainCmd)
}

func runNXDomain(cmd *cobra.Command, args []string) error {
	ips, err := loadInput()
	if err != nil {
		return err
	}

	dur := time.Duration(timeout) * time.Second
	check := scanner.NXDomainCheck(count)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	start := time.Now()
	results := scanner.RunPoolCtx(ctx, ips, workers, dur, check, newProgress("nxdomain"))
	elapsed := time.Since(start)

	if ctx.Err() != nil {
		fmt.Fprintf(os.Stderr, "\n⚠ Interrupted — saving partial results\n")
	}

	return writeReport("nxdomain", results, elapsed, "hijack")
}
