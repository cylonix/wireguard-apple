// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: MIT

package main

import (
	"runtime"
	"time"
)

// The iOS network extension is jetsam-killed at ~50MB resident
// (per-process-limit). The watchdog samples Go memory and, when it
// crosses memWatchThreshold, logs the state and writes a heap profile to
// the shared debug_profiles directory so post-mortems of memory spikes
// have allocation-site evidence even when jetsam wins the race. The dump
// path runs runtime.GC() first, which also sheds droppable memory at the
// moment of danger.
const (
	memWatchInterval  = 5 * time.Second
	memWatchThreshold = 34 << 20 // Go-owned bytes; GOMEMLIMIT is 32MiB
	memWatchDumpGap   = 10 * time.Minute
)

func startMemoryWatchdog() {
	go func() {
		var lastDump time.Time
		var above bool
		for range time.Tick(memWatchInterval) {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			goMem := m.HeapInuse + m.StackInuse + m.MSpanInuse +
				m.MCacheInuse + m.GCSys + m.OtherSys
			if goMem < memWatchThreshold {
				above = false
				continue
			}
			if !above {
				// Log once per excursion above the threshold.
				clogf("memwatch: go memory high: total=%dK heapInuse=%dK heapSys=%dK stacks=%dK numGC=%d goroutines=%d",
					goMem>>10, m.HeapInuse>>10, m.HeapSys>>10,
					m.StackInuse>>10, m.NumGC, runtime.NumGoroutine())
			}
			above = true
			if time.Since(lastDump) < memWatchDumpGap {
				continue
			}
			lastDump = time.Now()
			if summary, err := dumpDebugPprof("heap"); err != nil {
				clogf("memwatch: heap profile failed: %v", err)
			} else {
				clogf("memwatch: wrote heap profile: %s", summary)
			}
		}
	}()
}
