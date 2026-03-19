package scanner

import (
	"context"
	"sync"
)

// PipelineResult is the outcome of running one IP through the full step pipeline.
type PipelineResult struct {
	IP         string
	OK         bool
	Metrics    Metrics
	FailedStep int // index of the step where it failed; -1 if passed all
}

// RunPipeline processes each IP through all steps sequentially per-IP (DFS).
// Unlike RunChain which processes all IPs through step 1, then step 2 (BFS),
// each worker takes one IP and runs it through the entire pipeline.
// Results are emitted to the returned channel as each IP completes.
// The channel is closed when all IPs are processed or the context is cancelled.
func RunPipeline(ctx context.Context, ips []string, workers int, steps []Step) <-chan PipelineResult {
	out := make(chan PipelineResult, workers)

	go func() {
		defer close(out)

		jobs := make(chan string)
		bufSize := workers * 4
		if bufSize > len(ips) {
			bufSize = len(ips)
		}
		if bufSize < 1 {
			bufSize = 1
		}
		results := make(chan PipelineResult, bufSize)

		// Launch workers — each takes one IP and runs ALL steps on it.
		// WaitGroup ensures all workers finish before we close `results`,
		// preventing goroutine leaks on context cancellation.
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for ip := range jobs {
					func() {
						defer func() {
							if r := recover(); r != nil {
								select {
								case results <- PipelineResult{IP: ip, OK: false, FailedStep: 0}:
								case <-ctx.Done():
								}
							}
						}()

						m := make(Metrics)
						for si, step := range steps {
							if ctx.Err() != nil {
								select {
								case results <- PipelineResult{IP: ip, OK: false, FailedStep: si}:
								case <-ctx.Done():
								}
								return
							}
							ok, sm := step.Check(ip, step.Timeout)
							if !ok {
								select {
								case results <- PipelineResult{IP: ip, OK: false, FailedStep: si}:
								case <-ctx.Done():
								}
								return
							}
							for k, v := range sm {
								m[k] = v
							}
						}
						select {
						case results <- PipelineResult{IP: ip, OK: true, Metrics: m, FailedStep: -1}:
						case <-ctx.Done():
						}
					}()
				}
			}()
		}

		// Feed IPs to workers
		go func() {
			defer close(jobs)
			for _, ip := range ips {
				select {
				case jobs <- ip:
				case <-ctx.Done():
					return
				}
			}
		}()

		// Close results channel once all workers are done
		go func() {
			wg.Wait()
			close(results)
		}()

		// Forward results to output channel until results is closed or context cancelled
		for r := range results {
			select {
			case out <- r:
			case <-ctx.Done():
				return
			}
		}
	}()

	return out
}
