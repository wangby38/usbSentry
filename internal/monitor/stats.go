//go:build linux

package monitor

import (
	"sync"
	"time"

	"github.com/Hara602/usbSentry/internal/sysutil"
	"go.uber.org/zap"
)

// EventStats tracks file event statistics in a thread-safe manner.
type EventStats struct {
	mu     sync.Mutex
	counts map[string]int64 // event type -> count
	procs  map[string]int64 // process name -> count
	total  int64
	start  time.Time
}

// NewEventStats creates a new statistics tracker.
func NewEventStats() *EventStats {
	return &EventStats{
		counts: make(map[string]int64),
		procs:  make(map[string]int64),
		start:  time.Now(),
	}
}

// Record increments counters for the given event type and process.
func (s *EventStats) Record(eventOp string, procName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts[eventOp]++
	s.procs[procName]++
	s.total++
}

// Snapshot returns a copy of current statistics.
func (s *EventStats) Snapshot() (counts map[string]int64, procs map[string]int64, total int64, elapsed time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	counts = make(map[string]int64, len(s.counts))
	for k, v := range s.counts {
		counts[k] = v
	}
	procs = make(map[string]int64, len(s.procs))
	for k, v := range s.procs {
		procs[k] = v
	}
	return counts, procs, s.total, time.Since(s.start)
}

// TopProcs returns the top N processes by event count.
func (s *EventStats) TopProcs(n int) []ProcCount {
	s.mu.Lock()
	defer s.mu.Unlock()

	type pair struct {
		name  string
		count int64
	}
	pairs := make([]pair, 0, len(s.procs))
	for name, count := range s.procs {
		pairs = append(pairs, pair{name, count})
	}
	for i := 0; i < len(pairs) && i < n; i++ {
		maxIdx := i
		for j := i + 1; j < len(pairs); j++ {
			if pairs[j].count > pairs[maxIdx].count {
				maxIdx = j
			}
		}
		pairs[i], pairs[maxIdx] = pairs[maxIdx], pairs[i]
	}

	result := make([]ProcCount, 0, n)
	for i := 0; i < len(pairs) && i < n; i++ {
		result = append(result, ProcCount{Name: pairs[i].name, Count: pairs[i].count})
	}
	return result
}

// ProcCount represents a process and its event count.
type ProcCount struct {
	Name  string
	Count int64
}

// StatsReporter periodically logs event statistics.
type StatsReporter struct {
	stats    *EventStats
	interval time.Duration
	stop     chan struct{}
}

// NewStatsReporter creates a reporter that logs stats every interval.
func NewStatsReporter(stats *EventStats, interval time.Duration) *StatsReporter {
	return &StatsReporter{
		stats:    stats,
		interval: interval,
		stop:     make(chan struct{}),
	}
}

// Start begins periodic reporting in a goroutine.
func (r *StatsReporter) Start() {
	go func() {
		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				r.report()
			case <-r.stop:
				return
			}
		}
	}()
}

// Stop stops the reporter goroutine.
func (r *StatsReporter) Stop() {
	close(r.stop)
}

func (r *StatsReporter) report() {
	counts, procs, total, elapsed := r.stats.Snapshot()
	top5 := r.stats.TopProcs(5)

	sysutil.Log.Info("=== File Event Statistics ===",
		zap.Int64("total_events", total),
		zap.Duration("elapsed", elapsed.Round(time.Second)),
	)
	for op, count := range counts {
		sysutil.LogSugar.Infof("  %-20s: %d", op, count)
	}
	sysutil.LogSugar.Info("Top processes by event count:")
	for _, p := range top5 {
		sysutil.LogSugar.Infof("  %-20s: %d", p.Name, p.Count)
	}
	if len(procs) == 0 {
		sysutil.LogSugar.Info("  (no events yet)")
	}
}
