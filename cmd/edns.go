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

var ednsCmd = &cobra.Command{
	Use:   "edns",
	Short: "Test EDNS payload size support (critical for DNS tunneling)",
	RunE:  runEDNS,
}

func init() {
	ednsCmd.Flags().String("domain", "", "tunnel domain to test payload against")
	ednsCmd.MarkFlagRequired("domain")
	rootCmd.AddCommand(ednsCmd)
}

func runEDNS(cmd *cobra.Command, args []string) error {
	domain, _ := cmd.Flags().GetString("domain")

	ips, err := loadInput()
	if err != nil {
		return err
	}

	dur := time.Duration(timeout) * time.Second
	check := scanner.EDNSCheck(domain, count)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	start := time.Now()
	results := scanner.RunPoolCtx(ctx, ips, workers, dur, check, newProgress("edns"))
	elapsed := time.Since(start)

	if ctx.Err() != nil {
		fmt.Fprintf(os.Stderr, "\n⚠ Interrupted — saving partial results\n")
	}

	return writeReport("edns", results, elapsed, "edns_max")
}
