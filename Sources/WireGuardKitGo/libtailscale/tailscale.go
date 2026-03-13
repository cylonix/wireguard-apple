// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime/debug"
	"time"

	"tailscale.com/health"
	"tailscale.com/logpolicy"
	"tailscale.com/logtail"
	"tailscale.com/logtail/filch"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/syspolicy"
)

const defaultMTU = 1280 // minimalMTU from wgengine/userspace.go

const (
	logPrefKey               = "privatelogid"
	loginMethodPrefKey       = "loginmethod"
	customLoginServerPrefKey = "customloginserver"
)

func newApp(dataDir, directFileRoot string, appCtx AppContext) Application {
	a := &App{
		directFileRoot: directFileRoot,
		dataDir:        dataDir,
		appCtx:         appCtx,
	}
	a.ready.Add(2)

	a.store = newStateStore(a.appCtx)
	a.policyStore = &syspolicyHandler{a: a}
	netmon.RegisterInterfaceGetter(a.getInterfaces)
	syspolicy.RegisterHandler(a.policyStore)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				log.Printf("panic in runBackend %s: %s", p, debug.Stack())
				panic(p)
			}
		}()

		ctx := context.Background()
		if err := a.runBackend(ctx); err != nil {
			a.fatalErr(err)
		}
	}()

	return a
}

func (a *App) fatalErr(err error) {
	// TODO: expose in UI.
	a.appCtx.OnFatalError(err)
	log.Printf("fatal error: %v", err)
}

// osVersion returns android.os.Build.VERSION.RELEASE. " [nogoogle]" is appended
// if Google Play services are not compiled in.
func (a *App) osVersion() string {
	version, err := a.appCtx.GetOSVersion()
	if err != nil {
		panic(err)
	}
	return version
}

// modelName return the MANUFACTURER + MODEL from
// android.os.Build.
func (a *App) modelName() string {
	model, err := a.appCtx.GetModelName()
	if err != nil {
		panic(err)
	}
	return model
}

func (a *App) isChromeOS() bool {
	isChromeOS, err := a.appCtx.IsChromeOS()
	if err != nil {
		panic(err)
	}
	return isChromeOS
}

// SetupLogs sets up remote logging.
func (b *backend) setupLogs(logDir string, logID logid.PrivateID, logf logger.Logf, health *health.Tracker) {
	if b.netMon == nil {
		panic("netMon must be created prior to SetupLogs")
	}

	logURL := logpolicy.LogURL()
	log.Printf("goSetupLogs: logID=%v, logDir=%q, logURL=%v", logID.Public(), logDir, logURL)
	u, _ := url.Parse(logURL)
	logHost := u.Host
	logClient := &http.Client{Transport: logpolicy.TransportOptions{
		Host:   logHost,
		NetMon: b.netMon,
		Health: health,
		Logf:   logf,
	}.New()}

	logcfg := logtail.Config{
		BaseURL:             logURL,
		Collection:          logtail.CollectionNode,
		PrivateID:           logID,
		Stderr:              log.Writer(),
		StderrLevel:         1, // __CYLONIX_MOD__
		MetricsDelta:        clientmetric.EncodeLogTailMetricsDelta,
		IncludeProcID:       true,
		IncludeProcSequence: true,
		HTTPC:               logClient,
		CompressLogs:        true,
	}
	logcfg.FlushDelayFn = func() time.Duration { return 2 * time.Minute }

	filchOpts := filch.Options{
		ReplaceStderr: replaceStderrWithFilch,
	}

	var filchErr error
	if logDir != "" {
		logPath := filepath.Join(logDir, "ipn.log.")
		logcfg.Buffer, filchErr = filch.New(logPath, filchOpts)
	}

	b.logger = logtail.NewLogger(logcfg, logf)

	log.SetFlags(0)
	log.SetOutput(b.logger)

	log.Printf("goSetupLogs: logID=%v, logURL=%v, logHost=%v, logDir=%q", logID.Public(), logURL, logHost, logDir)
	log.Printf("goSetupLogs: success")

	if logDir == "" {
		log.Printf("SetupLogs: no logDir, storing logs in memory")
	}
	if filchErr != nil {
		log.Printf("SetupLogs: filch setup failed: %v", filchErr)
	}

	go func() {
		for {
			select {
			case logstr := <-onLog:
				b.logger.Logf(logstr)
			}
		}
	}()
}
