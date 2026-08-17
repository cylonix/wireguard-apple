// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: MIT

package main

import (
	"runtime"
	"time"
)

// The iOS network extension runs under a tight resident-memory limit
// (~50MB, jetsam per-process-limit). The watchdog samples Go memory and
// warns when it crosses memWatchThreshold. It deliberately does NO disk
// I/O: an earlier version wrote heap profiles to disk on every excursion,
// which added write pressure to an extension that has hit iOS disk-write
// resource limits before. It only logs, and only on a state change
// (crossing the threshold), with a once-per-hour reminder while the
// condition persists, so a sustained high-memory state cannot flood the
// log.
const (
	memWatchInterval  = 5 * time.Second
	memWatchThreshold = 34 << 20 // Go-owned bytes; GOMEMLIMIT is 32MiB
	memWatchRepeat    = time.Hour
)

func startMemoryWatchdog() {
	go func() {
		var above bool
		var lastWarn time.Time
		for range time.Tick(memWatchInterval) {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			goMem := m.HeapInuse + m.StackInuse + m.MSpanInuse +
				m.MCacheInuse + m.GCSys + m.OtherSys

			if goMem < memWatchThreshold {
				if above {
					clogf("memwatch: go memory recovered: total=%dK", goMem>>10)
				}
				above = false
				continue
			}

			// At or above the threshold. Warn on the initial crossing, then
			// at most once per hour while it stays high.
			if above && time.Since(lastWarn) < memWatchRepeat {
				continue
			}
			lastWarn = time.Now()
			above = true
			clogf("memwatch: go memory high: total=%dK heapInuse=%dK heapSys=%dK stacks=%dK numGC=%d goroutines=%d",
				goMem>>10, m.HeapInuse>>10, m.HeapSys>>10,
				m.StackInuse>>10, m.NumGC, runtime.NumGoroutine())
		}
	}()
}
