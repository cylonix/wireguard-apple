// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/feature/taildrop" // __CYLONIX_MOD__ moved from tailscale.com/taildrop in v1.96
	"tailscale.com/ipn"
	// __BEGIN_CYLONIX_ADD__
	"tailscale.com/ipn/ipnlocal"
	// __END_CYLONIX_ADD__
)

func (app *App) WatchNotifications(mask int, cb NotificationCallback) NotificationManager {
	app.ready.Wait()

	ctx, cancel := context.WithCancel(context.Background())
	go app.backend.WatchNotifications(ctx, ipn.NotifyWatchOpt(mask), func() {}, func(notify *ipn.Notify) bool {
		defer func() {
			if p := recover(); p != nil {
				log.Printf("panic in WatchNotifications %s: %s", p, debug.Stack())
				panic(p)
			}
		}()

		b, err := json.Marshal(notify)
		if err != nil {
			log.Printf("error: WatchNotifications: marshal notify: %s", err)
			return true
		}
		err = cb.OnNotify(b)
		if err != nil {
			log.Printf("error: WatchNotifications: OnNotify: %s", err)
			return true
		}
		return true
	})
	return &notificationManager{name: "WatchNotifications", cancel: cancel}
}

type notificationManager struct {
	name string
	cancel func()
}

func (nm *notificationManager) Stop() {
	log.Printf("%v: stop", nm.name)
	nm.cancel()
}

func (app *App) WatchNotificationsRaw(mask int, cb func(*ipn.Notify)) NotificationManager {
	app.ready.Wait()

	ctx, cancel := context.WithCancel(context.Background())
	go app.backend.WatchNotifications(ctx, ipn.NotifyWatchOpt(mask), func() {}, func(notify *ipn.Notify) bool {
		defer func() {
			if p := recover(); p != nil {
				log.Printf("panic in WatchNotificationsRaw %s: %s", p, debug.Stack())
				panic(p)
			}
		}()
		cb(notify)
		return true
	})
	return &notificationManager{name: "WatchNotificationsRaw", cancel: cancel}
}

func (app *App) WatchAwaitingFiles(cb func(dir string, files []apitype.WaitingFile)) NotificationManager {
	app.ready.Wait()

	log.Printf("WatchAwaitingFiles: start")
	ctx, cancel := context.WithCancel(context.Background())
	nm := &notificationManager{name: "WatchAwaitingFiles", cancel: cancel}
	//logf := logger.RateLimitedFn(log.Printf, 1*time.Minute, 2, 10)
	lastUpdate := ""
	maxSleep := 30 // seconds
	backOff := 0

	go func() {
		defer func() {
			if p := recover(); p != nil {
				log.Printf("panic in WatchNotificationsRaw %s: %s", p, debug.Stack())
				panic(p)
			} else {
				log.Printf("WatchAwaitingFiles: done")
			}
		}()
		// __BEGIN_CYLONIX_MOD__
		// v1.96: AwaitWaitingFiles / WaitingFilesDir moved off LocalBackend
		// into the feature/taildrop Extension. Resolve the extension once
		// and call it directly. The "waiting files dir" concept doesn't have
		// a public accessor anymore, so we report directFileRoot (which on
		// iOS/macOS is always where received files land).
		ext, _ := ipnlocal.GetExt[*taildrop.Extension](app.backend)
		// __END_CYLONIX_MOD__
		for {
			ctx2, cancel2 := context.WithCancel(context.Background())
			select {
			case <-ctx.Done():
				log.Printf("WatchAwaitingFiles: canncel")
				cancel2()
				return
			default:
				// __BEGIN_CYLONIX_MOD__
				if ext == nil {
					log.Printf("WatchAwaitingFiles: taildrop extension not registered")
					time.Sleep(time.Second)
					continue
				}
				files, err := ext.AwaitWaitingFiles(ctx2)
				// __END_CYLONIX_MOD__
				if err != nil {
					if !errors.Is(err, taildrop.ErrNoTaildrop) {
						log.Printf("WatchAwaitingFiles: error=%v", err)
					}
					time.Sleep(time.Second)
					continue
				}
				if len(files) != 0 {
					//log.Printf("WatchAwaitingFiles: count=%d", len(files))
					// __BEGIN_CYLONIX_MOD__
					// v1.96 removed LocalBackend.WaitingFilesDir(). When
					// directFileRoot is set, taildrop writes there directly;
					// otherwise it stages files under
					// <TailscaleVarRoot>/files/<login>-uid-<uid> (see
					// feature/taildrop/ext.go fileRoot()). The host app needs
					// the actual on-disk location to read incoming peer-message
					// attachments and to let the user pick a destination via
					// the share sheet, so reproduce the staging-mode path
					// computation here using public LocalBackend accessors.
					dir := app.directFileRoot
					if dir == "" {
						dir = stagingFilesDir(app.backend)
					}
					// __END_CYLONIX_MOD__
					cb(dir, files)
					v, _ := json.Marshal(files)
					sleep := 1
					if string(v) == lastUpdate {
						backOff++
						sleep = 1 << backOff
						if sleep > maxSleep {
							sleep = maxSleep
							backOff = 0
							lastUpdate = ""
						}
					} else {
						backOff = 0
						lastUpdate = string(v)
					}
					time.Sleep(time.Second * time.Duration(sleep))
					continue
				}
				//logf("WatchAwaitingFiles: no file is waiting")
				time.Sleep(time.Second)
			}
		}
	}()
	return nm
}

// __BEGIN_CYLONIX_ADD__
// stagingFilesDir reproduces the staging-mode path that
// feature/taildrop/ext.go fileRoot() builds when SetDirectFileRoot has
// not been called: <TailscaleVarRoot>/files/<login>-uid-<uid>.
//
// The original libtailscale called LocalBackend.WaitingFilesDir() to get
// this path, but v1.96 removed that accessor. Since taildrop's fileRoot
// helper is unexported and the same inputs (varRoot, login, uid) are all
// reachable via public LocalBackend methods, reproduce the path here so
// the host app gets a real source dir for both peer-message attachment
// auto-save and share-sheet user-picked destinations.
//
// Returns "" if any required input is unavailable, in which case the
// caller falls back to the empty path (same as previous broken state).
func stagingFilesDir(b *ipnlocal.LocalBackend) string {
	if b == nil {
		return ""
	}
	varRoot := b.TailscaleVarRoot()
	if varRoot == "" {
		return ""
	}
	profile := b.CurrentProfile()
	if !profile.Valid() {
		return ""
	}
	up := profile.UserProfile()
	if up.LoginName == "" {
		return ""
	}
	baseDir := fmt.Sprintf("%s-uid-%d",
		strings.ReplaceAll(up.LoginName, "@", "-"),
		up.ID)
	return filepath.Join(varRoot, "files", baseDir)
}

// __END_CYLONIX_ADD__
