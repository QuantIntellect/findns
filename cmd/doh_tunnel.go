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

var dohTunnelCmd = &cobra.Command{
	Use:   "tunnel",
	Short: "Test NS delegation and glue resolution via DoH resolver",
	RunE:  runDoHTunnel,
}

func init() {
	dohTunnelCmd.Flags().String("domain", "", "tunnel domain to check NS for")
	dohTunnelCmd.MarkFlagRequired("domain")
	dohResolveCmd.AddCommand(dohTunnelCmd)
}

func runDoHTunnel(cmd *cobra.Command, args []string) error {
	domain, _ := cmd.Flags().GetString("domain")

	urls, err := loadInput()
	if err != nil {
		return err
	}

	dur := time.Duration(timeout) * time.Second
	check := scanner.DoHTunnelCheck(domain, count)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	start := time.Now()
	results := scanner.RunPoolCtx(ctx, urls, workers, dur, check, newProgress("doh/resolve/tunnel"))
	elapsed := time.Since(start)

	if ctx.Err() != nil {
		fmt.Fprintf(os.Stderr, "\n⚠ Interrupted — saving partial results\n")
	}

	return writeReport("doh/resolve/tunnel", results, elapsed, "resolve_ms")
}
