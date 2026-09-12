// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"runtime"
	"runtime/metrics"
	"strings"
	"time"

	"tailscale.com/ipn/ipnlocal"
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

// memClasses returns a compact breakdown of Go-owned memory from
// runtime/metrics: what is live, what is idle but still resident, what has
// been returned to the OS, and where the rest went. iOS charges resident
// pages, so "free" (idle, not yet released) is the number that separates a
// heap that is big from one that merely was big. All values in KiB.
func memClasses() string {
	names := []string{
		"/gc/heap/live:bytes",
		"/memory/classes/heap/objects:bytes",
		"/memory/classes/heap/free:bytes",
		"/memory/classes/heap/released:bytes",
		"/memory/classes/heap/unused:bytes",
		"/memory/classes/heap/stacks:bytes",
		"/memory/classes/metadata/mspan/inuse:bytes",
		"/memory/classes/metadata/other:bytes",
		"/memory/classes/other:bytes",
		"/memory/classes/total:bytes",
		"/gc/heap/goal:bytes",
		"/sched/goroutines:goroutines",
	}
	labels := []string{
		"live", "objects", "free", "released", "unused", "stacks",
		"mspan", "gcmeta", "other", "total", "goal", "goroutines",
	}
	samples := make([]metrics.Sample, len(names))
	for i, n := range names {
		samples[i].Name = n
	}
	metrics.Read(samples)
	var b strings.Builder
	for i, s := range samples {
		if s.Value.Kind() != metrics.KindUint64 {
			continue
		}
		v := s.Value.Uint64()
		if labels[i] == "goroutines" {
			fmt.Fprintf(&b, " %s=%d", labels[i], v)
		} else {
			fmt.Fprintf(&b, " %s=%dK", labels[i], v>>10)
		}
	}
	return strings.TrimSpace(b.String())
}

// footprintString renders the resident footprint and its lifetime peak,
// the figures iOS compares against the extension's limit.
func footprintString() string {
	cur, peak, res, resPeak, ok := taskMemory()
	if !ok {
		return "footprint=n/a"
	}
	return fmt.Sprintf("footprint=%dM peak=%dM resident=%dM residentPeak=%dM", cur>>20, peak>>20, res>>20, resPeak>>20)
}

func startMemoryWatchdog() {
	// Let the user's other devices read the footprint over the peer API
	// (tailscale/ipn/ipnlocal/peerdebug.go).
	ipnlocal.PeerDebugFootprint = taskFootprint
	ipnlocal.PeerDebugTaskMemory = taskMemory
	go func() {
		var above bool
		var lastWarn, lastFootprint time.Time
		var ticks int
		for range time.Tick(memWatchInterval) {
			ticks++
			if ticks == 12 {
				// One baseline a minute after start, so a later "high"
				// line has something to be compared against.
				clogf("memwatch: baseline %s %s", footprintString(), memClasses())
			}
			if time.Since(lastFootprint) >= memWatchRepeat {
				// Once an hour regardless of state: the peak is what a
				// jetsam post-mortem needs and nothing else records it.
				lastFootprint = time.Now()
				clogf("memwatch: %s", footprintString())
			}
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			goMem := m.HeapInuse + m.StackInuse + m.MSpanInuse +
				m.MCacheInuse + m.GCSys + m.OtherSys

			if goMem < memWatchThreshold {
				if above {
					clogf("memwatch: go memory recovered: total=%dK %s %s", goMem>>10, footprintString(), memClasses())
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
			clogf("memwatch: go memory high: total=%dK heapInuse=%dK heapSys=%dK stacks=%dK numGC=%d goroutines=%d | %s %s",
				goMem>>10, m.HeapInuse>>10, m.HeapSys>>10,
				m.StackInuse>>10, m.NumGC, runtime.NumGoroutine(), footprintString(), memClasses())
		}
	}()
}
