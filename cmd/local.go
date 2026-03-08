package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/SamNet-dev/findns/internal/data"
	"github.com/spf13/cobra"
)

var localCmd = &cobra.Command{
	Use:   "local",
	Short: "Export bundled Iranian resolver lists or discover new resolvers",
	Long: `Export Iranian DNS resolver data bundled inside the binary.
No internet connection needed — everything is embedded.

Two modes:

  KNOWN RESOLVERS (default):
    Exports 7,800+ pre-verified Iranian DNS resolver IPs.
    These are known working resolvers — high success rate when scanned.
    Source: net2share/ir-resolvers

    Example:
      findns local -o resolvers.txt
      findns scan -i resolvers.txt -o results.json --domain t.example.com

  DISCOVER NEW RESOLVERS (--discover):
    Exports IPs from Iran's full IP space (1,919 CIDR ranges, ~10.8M IPs).
    These are NOT resolvers — they are candidates to scan.
    Most will fail — only a small percentage are DNS servers.
    Use this to find resolvers not in the known list.

    Example:
      findns local -o candidates.txt --discover
      findns scan -i candidates.txt -o results.json --domain t.example.com

    Discovery supports three sub-modes:
      --sample N   Pick N random IPs per subnet (default: 10, ~19K total)
      --batch N    Export N IPs at a time (non-overlapping, use --offset)
      --full       All ~10.8M IPs (takes days to scan)`,
	RunE: runLocal,
}

func init() {
	localCmd.Flags().StringP("output", "o", "", "output file path to write IP list")

	// Discovery mode
	localCmd.Flags().Bool("discover", false,
		"discover NEW resolvers by scanning Iran's full IP space\n"+
			"without this flag, exports known pre-verified resolvers")

	// Discovery sub-mode flags
	localCmd.Flags().Int("sample", 10,
		"[discover] random IPs to pick per subnet (0 = all)\n"+
			"higher = more coverage but slower scan")
	localCmd.Flags().Bool("full", false,
		"[discover] export ALL ~10.8M IPs (overrides --sample)\n"+
			"warning: scanning all of them will take days")
	localCmd.Flags().Int("batch", 0,
		"[discover] export exactly this many IPs (non-overlapping)\n"+
			"use with --offset for pagination — no duplicates")
	localCmd.Flags().Int("offset", 0,
		"[discover] skip this many IPs before starting the batch\n"+
			"program prints the correct --offset for next batch")

	// Info flag
	localCmd.Flags().Bool("list-ranges", false,
		"print the embedded CIDR ranges to stdout and exit\n"+
			"does not require -o flag")

	rootCmd.AddCommand(localCmd)
}

func runLocal(cmd *cobra.Command, args []string) error {
	output, _ := cmd.Flags().GetString("output")
	discover, _ := cmd.Flags().GetBool("discover")
	samplePer, _ := cmd.Flags().GetInt("sample")
	full, _ := cmd.Flags().GetBool("full")
	batchSize, _ := cmd.Flags().GetInt("batch")
	offset, _ := cmd.Flags().GetInt("offset")
	listRanges, _ := cmd.Flags().GetBool("list-ranges")

	// --list-ranges: just print CIDRs and exit
	if listRanges {
		cidrs, err := data.IRCIDRs()
		if err != nil {
			return err
		}
		for _, c := range cidrs {
			fmt.Println(c)
		}
		fmt.Fprintf(os.Stderr, "%d CIDR ranges\n", len(cidrs))
		return nil
	}

	// All other modes need -o
	if output == "" {
		return fmt.Errorf("--output / -o is required (use --list-ranges to just view ranges)")
	}

	var ips []string
	var err error

	if discover {
		ips, err = runDiscover(cmd, samplePer, full, batchSize, offset)
	} else {
		// Warn if discover-only flags are used without --discover
		if full || batchSize > 0 || cmd.Flags().Changed("sample") || cmd.Flags().Changed("offset") {
			fmt.Fprintf(os.Stderr, "warning: --sample/--batch/--full/--offset only work with --discover\n")
			fmt.Fprintf(os.Stderr, "         without --discover, known resolvers are exported\n")
			fmt.Fprintf(os.Stderr, "         did you mean: findns local -o %s --discover ...?\n\n", output)
		}
		ips, err = runKnown()
	}
	if err != nil {
		return err
	}

	// Write output
	f, err := os.Create(output)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, ip := range ips {
		fmt.Fprintln(f, ip)
	}

	fmt.Fprintf(os.Stderr, "wrote %s IPs to %s\n", formatNum(len(ips)), output)
	fmt.Fprintf(os.Stderr, "\nnext step: findns scan -i %s -o results.json --domain <your-tunnel-domain>\n", output)
	return nil
}

// runKnown exports the pre-verified resolver list
func runKnown() ([]string, error) {
	ips, err := data.IRResolvers()
	if err != nil {
		return nil, fmt.Errorf("reading embedded resolvers: %w", err)
	}
	fmt.Fprintf(os.Stderr, "loaded %s known Iranian DNS resolvers (source: ir-resolvers)\n",
		formatNum(len(ips)))
	fmt.Fprintf(os.Stderr, "these are pre-verified resolvers — high scan success rate expected\n")
	return ips, nil
}

// runDiscover generates candidate IPs from CIDR ranges
func runDiscover(cmd *cobra.Command, samplePer int, full bool, batchSize, offset int) ([]string, error) {
	cidrs, err := data.IRCIDRs()
	if err != nil {
		return nil, fmt.Errorf("reading embedded CIDRs: %w", err)
	}

	totalIPs, err := data.TotalUsableIPs(cidrs)
	if err != nil {
		return nil, err
	}

	fmt.Fprintf(os.Stderr, "loaded %d Iranian CIDR ranges (%s total IPs, source: RIPE NCC)\n",
		len(cidrs), formatNum(totalIPs))
	fmt.Fprintf(os.Stderr, "note: these are NOT known resolvers — most IPs will not be DNS servers\n")

	var ips []string

	if batchSize > 0 {
		// Batch mode
		if offset >= totalIPs {
			fmt.Fprintf(os.Stderr, "offset %s >= total %s — nothing to export\n",
				formatNum(offset), formatNum(totalIPs))
			return nil, nil
		}
		ips, _, err = data.ExpandCIDRsBatch(cidrs, offset, batchSize)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "  batch range:  IP #%s to #%s (of %s total)\n",
			formatNum(offset+1), formatNum(offset+len(ips)), formatNum(totalIPs))
		fmt.Fprintf(os.Stderr, "  IPs in batch: %s\n", formatNum(len(ips)))
		fmt.Fprintf(os.Stderr, "\n")
		nextOffset := offset + batchSize
		if nextOffset < totalIPs {
			fmt.Fprintf(os.Stderr, "  next batch command:\n")
			fmt.Fprintf(os.Stderr, "    findns local -o <next-file>.txt --discover --batch %d --offset %d\n", batchSize, nextOffset)
			fmt.Fprintf(os.Stderr, "  remaining: %s IPs\n", formatNum(totalIPs-nextOffset))
		} else {
			fmt.Fprintf(os.Stderr, "  this is the LAST batch — all IPs covered\n")
		}
		fmt.Fprintf(os.Stderr, "\n")
	} else if full {
		// Full mode
		fmt.Fprintf(os.Stderr, "expanding ALL %s IPs (this may take a moment)...\n", formatNum(totalIPs))
		ips, err = data.ExpandCIDRsSampled(cidrs, 0)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "warning: scanning %s IPs will take a very long time!\n", formatNum(len(ips)))
		fmt.Fprintf(os.Stderr, "tip: consider --discover --batch 1000000 for incremental scanning\n")
	} else {
		// Sample mode (default for discover)
		ips, err = data.ExpandCIDRsSampled(cidrs, samplePer)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "sampled %d random IPs per subnet -> %s candidate IPs\n",
			samplePer, formatNum(len(ips)))
	}

	return ips, nil
}

func formatNum(n int) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	s := fmt.Sprintf("%d", n)
	var parts []string
	for i := len(s); i > 0; i -= 3 {
		start := i - 3
		if start < 0 {
			start = 0
		}
		parts = append([]string{s[start:i]}, parts...)
	}
	return strings.Join(parts, ",")
}
