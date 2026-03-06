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

var dohResolveCmd = &cobra.Command{
	Use:   "resolve",
	Short: "Test if DoH resolvers can resolve a given domain",
	RunE:  runDoHResolve,
}

func init() {
	dohResolveCmd.Flags().String("domain", "", "domain to test")
	dohResolveCmd.MarkFlagRequired("domain")
	dohCmd.AddCommand(dohResolveCmd)
}

func runDoHResolve(cmd *cobra.Command, args []string) error {
	domain, _ := cmd.Flags().GetString("domain")

	urls, err := loadInput()
	if err != nil {
		return err
	}

	dur := time.Duration(timeout) * time.Second
	check := scanner.DoHResolveCheck(domain, count)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	start := time.Now()
	results := scanner.RunPoolCtx(ctx, urls, workers, dur, check, newProgress("doh/resolve"))
	elapsed := time.Since(start)

	if ctx.Err() != nil {
		fmt.Fprintf(os.Stderr, "\n⚠ Interrupted — saving partial results\n")
	}

	return writeReport("doh/resolve", results, elapsed, "resolve_ms")
}
