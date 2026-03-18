package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type Step struct {
	Name    string
	Timeout time.Duration
	Check   CheckFunc
	SortBy  string
	Limit   int // if > 0, only pass top N results to the next step
}

type StepResult struct {
	Name    string  `json:"name"`
	Tested  int     `json:"tested"`
	Passed  int     `json:"passed"`
	Failed  int     `json:"failed"`
	Seconds float64 `json:"duration_secs"`
}

type ChainReport struct {
	Steps  []StepResult `json:"steps"`
	Passed []IPRecord   `json:"passed"`
	Failed []IPRecord   `json:"failed"`
}

type ProgressFactory func(stepName string) ProgressFunc

func RunChain(ips []string, workers int, steps []Step, newProgress ProgressFactory) ChainReport {
	return runChain(context.Background(), ips, workers, steps, newProgress, false)
}

// RunChainQuiet runs the chain without printing step-by-step logs (for scan command which has its own summary).
func RunChainQuiet(ips []string, workers int, steps []Step, newProgress ProgressFactory) ChainReport {
	return runChain(context.Background(), ips, workers, steps, newProgress, true)
}

func RunChainCtx(ctx context.Context, ips []string, workers int, steps []Step, newProgress ProgressFactory) ChainReport {
	return runChain(ctx, ips, workers, steps, newProgress, false)
}

func RunChainQuietCtx(ctx context.Context, ips []string, workers int, steps []Step, newProgress ProgressFactory) ChainReport {
	return runChain(ctx, ips, workers, steps, newProgress, true)
}

func runChain(ctx context.Context, ips []string, workers int, steps []Step, newProgress ProgressFactory, quiet bool) ChainReport {
	if !quiet {
		fmt.Fprintf(os.Stderr, "chain: %d IPs, %d steps\n", len(ips), len(steps))
	}

	current := ips
	allFailed := make(map[string]struct{})
	accumulated := make(map[string]Metrics)
	var stepResults []StepResult

	for _, step := range steps {
		// Stop between steps if interrupted
		if ctx.Err() != nil {
			break
		}

		var progress ProgressFunc
		if newProgress != nil {
			progress = newProgress(step.Name)
		}

		start := time.Now()
		results := RunPoolCtx(ctx, current, workers, step.Timeout, step.Check, progress)
		elapsed := time.Since(start)

		var passed, failed int
		var nextIPs []string
		for _, r := range results {
			if r.OK {
				passed++
				nextIPs = append(nextIPs, r.IP)
				// Merge metrics into accumulated map
				if accumulated[r.IP] == nil {
					accumulated[r.IP] = make(Metrics)
				}
				for k, v := range r.Metrics {
					accumulated[r.IP][k] = v
				}
			} else {
				failed++
				allFailed[r.IP] = struct{}{}
			}
		}

		// Sort passed results by step's primary metric
		if step.SortBy != "" {
			SortByMetric(results, step.SortBy)
			nextIPs = nil
			for _, r := range results {
				if r.OK {
					nextIPs = append(nextIPs, r.IP)
				}
			}
		}

		sr := StepResult{
			Name:    step.Name,
			Tested:  len(results),
			Passed:  passed,
			Failed:  failed,
			Seconds: elapsed.Seconds(),
		}
		stepResults = append(stepResults, sr)

		if !quiet {
			fmt.Fprintf(os.Stderr, "  %-18s %d tested | %d pass | %d fail | %.1fs\n",
				step.Name+":", sr.Tested, sr.Passed, sr.Failed, sr.Seconds)
		}

		// Apply limit: only pass top N to next step
		if step.Limit > 0 && len(nextIPs) > step.Limit {
			nextIPs = nextIPs[:step.Limit]
		}

		current = nextIPs
	}

	// Build IPRecord slices with accumulated metrics
	passedRecords := make([]IPRecord, 0, len(current))
	for _, ip := range current {
		passedRecords = append(passedRecords, IPRecord{IP: ip, Metrics: accumulated[ip]})
	}

	failedRecords := make([]IPRecord, 0, len(allFailed))
	for ip := range allFailed {
		failedRecords = append(failedRecords, IPRecord{IP: ip})
	}

	report := ChainReport{
		Steps:  stepResults,
		Passed: passedRecords,
		Failed: failedRecords,
	}
	if report.Passed == nil {
		report.Passed = []IPRecord{}
	}

	if !quiet {
		totalDuration := 0.0
		for _, sr := range stepResults {
			totalDuration += sr.Seconds
		}
		fmt.Fprintf(os.Stderr, "\n  chain: %d passed | %d failed | %.1fs\n",
			len(report.Passed), len(report.Failed), totalDuration)
	}

	return report
}

func WriteChainReport(report ChainReport, path string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// MergeChainReports merges src into dst, accumulating step counts and results.
func MergeChainReports(dst *ChainReport, src ChainReport) {
	dst.Passed = append(dst.Passed, src.Passed...)
	dst.Failed = append(dst.Failed, src.Failed...)
	if len(dst.Steps) == 0 {
		dst.Steps = src.Steps
	} else {
		for i := range dst.Steps {
			if i < len(src.Steps) {
				dst.Steps[i].Tested += src.Steps[i].Tested
				dst.Steps[i].Passed += src.Steps[i].Passed
				dst.Steps[i].Failed += src.Steps[i].Failed
				dst.Steps[i].Seconds += src.Steps[i].Seconds
			}
		}
	}
}

// LoadChainReport reads a previously saved ChainReport from disk.
func LoadChainReport(path string) (ChainReport, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ChainReport{}, err
	}
	var report ChainReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return ChainReport{}, err
	}
	return report, nil
}
