// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"sync"
	"sync/atomic"

	"tailscale.com/drive/driveimpl"
	_ "tailscale.com/feature/condregister"

	// __BEGIN_CYLONIX_ADD__
	"tailscale.com/feature/taildrop"
	"tailscale.com/ipn/ipnauth"

	// __END_CYLONIX_ADD__
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/localapi"
	"tailscale.com/logtail"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/paths"
	"tailscale.com/tsd"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/netstack"
	"tailscale.com/wgengine/router"
)

type App struct {
	dataDir string

	// enables direct file mode for the taildrop manager
	directFileRoot string

	// appCtx is a global reference to the com.tailscale.ipn.App instance.
	appCtx AppContext

	store             *stateStore
	policyStore       *syspolicyHandler
	logIDPublicAtomic atomic.Pointer[logid.PublicID]

	localAPIHandler http.Handler
	backend         *ipnlocal.LocalBackend
	ready           sync.WaitGroup
}

func start(dataDir, directFileRoot string, appCtx AppContext) Application {
	defer func() {
		if p := recover(); p != nil {
			log.Printf("panic in Start %s: %s", p, debug.Stack())
			panic(p)
		}
	}()

	initLogging(appCtx, dataDir)
	// Set XDG_CACHE_HOME to make os.UserCacheDir work.
	if _, exists := os.LookupEnv("XDG_CACHE_HOME"); !exists {
		cachePath := filepath.Join(dataDir, "cache")
		os.Setenv("XDG_CACHE_HOME", cachePath)
	}
	// Set XDG_CONFIG_HOME to make os.UserConfigDir work.
	if _, exists := os.LookupEnv("XDG_CONFIG_HOME"); !exists {
		cfgPath := filepath.Join(dataDir, "config")
		os.Setenv("XDG_CONFIG_HOME", cfgPath)
	}
	// Set HOME to make os.UserHomeDir work.
	if _, exists := os.LookupEnv("HOME"); !exists {
		os.Setenv("HOME", dataDir)
	}

	return newApp(dataDir, directFileRoot, appCtx)
}

type backend struct {
	engine     wgengine.Engine
	backend    *ipnlocal.LocalBackend
	sys        *tsd.System
	devices    *multiTUN
	settings   settingsFunc
	lastCfg    *router.Config
	lastDNSCfg *dns.OSConfig
	netMon     *netmon.Monitor

	logIDPublic logid.PublicID
	logger      *logtail.Logger

	// avoidEmptyDNS controls whether to use fallback nameservers
	// when no nameservers are provided by Tailscale.
	avoidEmptyDNS bool

	appCtx AppContext
}

type settingsFunc func(*router.Config, *dns.OSConfig) error

func (a *App) runBackend(ctx context.Context) error {
	paths.AppSharedDir.Store(a.dataDir)
	hostinfo.SetOSVersion(a.osVersion())
	hostinfo.SetPackage(a.appCtx.GetInstallSource())
	deviceModel := a.modelName()
	if a.isChromeOS() {
		deviceModel = "ChromeOS: " + deviceModel
	}
	hostinfo.SetDeviceModel(deviceModel)
	defer func() {
		if r := recover(); r != nil {
			// Log directly to appCtx since normal logging might not be set up
			stack := string(debug.Stack())
			a.appCtx.Log("BACKEND", fmt.Sprintf("PANIC in runBackend: %v\n%s", r, stack))
		}
	}()

	type configPair struct {
		rcfg *router.Config
		dcfg *dns.OSConfig
	}
	configs := make(chan configPair)
	configErrs := make(chan error)
	b, err := a.newBackend(a.dataDir, a.directFileRoot, a.appCtx, a.store, func(rcfg *router.Config, dcfg *dns.OSConfig) error {
		if rcfg == nil {
			return nil
		}
		configs <- configPair{rcfg, dcfg}
		return <-configErrs
	})
	if err != nil {
		return err
	}
	a.logIDPublicAtomic.Store(&b.logIDPublic)
	a.backend = b.backend
	defer b.CloseTUNs()

	// __BEGIN_CYLONIX_MOD__
	// v1.96: localapi.NewHandler now takes a HandlerConfig struct
	// (Actor, Backend, Logf, LogID, EventBus). The EventBus is sourced
	// from the tsd.System on the LocalBackend.
	h := localapi.NewHandler(localapi.HandlerConfig{
		Actor:    ipnauth.Self,
		Backend:  b.backend,
		Logf:     log.Printf,
		LogID:    *a.logIDPublicAtomic.Load(),
		EventBus: b.backend.Sys().Bus.Get(),
	})
	h.PermitRead = true
	h.PermitWrite = true
	a.localAPIHandler = h
	// __END_CYLONIX_MOD__

	a.ready.Done()

	// Contrary to the documentation for VpnService.Builder.addDnsServer,
	// ChromeOS doesn't fall back to the underlying network nameservers if
	// we don't provide any.
	b.avoidEmptyDNS = a.isChromeOS()

	var (
		cfg        configPair
		state      ipn.State
		networkMap *netmap.NetworkMap
	)

	stateCh := make(chan ipn.State)
	netmapCh := make(chan *netmap.NetworkMap)
	go b.backend.WatchNotifications(ctx, ipn.NotifyInitialNetMap|ipn.NotifyInitialPrefs|ipn.NotifyInitialState, func() {}, func(notify *ipn.Notify) bool {
		if notify.State != nil {
			stateCh <- *notify.State
		}
		if notify.NetMap != nil {
			netmapCh <- notify.NetMap
		}
		return true
	})
	log.Println("rundBackend 1")
	for {
		select {
		case s := <-stateCh:
			log.Println("rundBackend 2")
			state = s
			if state >= ipn.Starting && vpnService.service != nil && b.isConfigNonNilAndDifferent(cfg.rcfg, cfg.dcfg) {
				log.Printf("rundBackend 2.1 state >= ipn.Starting=%v vpnService.service != nil=%v b.isConfigNonNilAndDifferent=%v",
					state, vpnService.service != nil, b.isConfigNonNilAndDifferent(cfg.rcfg, cfg.dcfg))
				// On state change, check if there are router or config changes requiring an update to VPNBuilder
				if err := b.updateTUN(cfg.rcfg, cfg.dcfg); err != nil {
					log.Println("rundBackend 2.2")
					if errors.Is(err, errMultipleUsers) {
						log.Printf("rundBackend 2.3: multiple users %v", err)
						// TODO: surface error to user
					}
					a.closeVpnService(err, b)
					log.Printf("rundBackend 2.4, closing vpn serivice due to error %v", err)
				}
				log.Println("rundBackend 2.5")
			}
			log.Println("rundBackend 3")
		case n := <-netmapCh:
			networkMap = n
		case c := <-configs:
			log.Println("rundBackend 4")
			cfg = c
			if vpnService.service == nil || !b.isConfigNonNilAndDifferent(cfg.rcfg, cfg.dcfg) {
				log.Println("rundBackend 5")
				configErrs <- nil
				log.Println("rundBackend 6")
				break
			}
			log.Println("rundBackend 7")
			configErrs <- b.updateTUN(cfg.rcfg, cfg.dcfg)
		case s := <-onVPNRequested:
			log.Printf("localbackend onVPNRequested serviceID=%s existingServiceNil=%v state=%v cfgNil=%v", s.ID(), vpnService.service == nil, state, cfg.rcfg == nil) // __CYLONIX_ADD__
			if vpnService.service != nil && vpnService.service.ID() == s.ID() {
				log.Println("rundBackend 8")
				log.Printf("localbackend onVPNRequested ignored same serviceID=%s", s.ID()) // __CYLONIX_ADD__
				// Still the same VPN instance, do nothing
				break
			}
			log.Println("rundBackend 9")
			setProtectFunc(func(fd int) error { // __CYLONIX_MOD__
				if !s.Protect(int32(fd)) {
					// TODO(bradfitz): return an error back up to netns if this fails, once
					// we've had some experience with this and analyzed the logs over a wide
					// range of Android phones. For now we're being paranoid and conservative
					// and do the JNI call to protect best effort, only logging if it fails.
					// The risk of returning an error is that it breaks users on some Android
					// versions even when they're not using exit nodes. I'd rather the
					// relatively few number of exit node users file bug reports if Tailscale
					// doesn't work and then we can look for this log print.
					log.Printf("[unexpected] VpnService.protect(%d) returned false", fd)
				}
				return nil // even on error. see big TODO above.
			})
			log.Println("rundBackend 10")
			log.Printf("onVPNRequested: rebind required")
			// TODO(catzkorn): When we start the android application
			// we bind sockets before we have access to the VpnService.protect()
			// function which is needed to avoid routing loops. When we activate
			// the service we get access to the protect, but do not retrospectively
			// protect the sockets already opened, which breaks connectivity.
			// As a temporary fix, we rebind and protect the magicsock.Conn on connect
			// which restores connectivity.
			// See https://github.com/tailscale/corp/issues/13814
			b.backend.DebugRebind()

			vpnService.service = s
			log.Printf("localbackend vpnService set serviceID=%s state=%v cfgNil=%v", s.ID(), state, cfg.rcfg == nil) // __CYLONIX_ADD__

			if networkMap != nil {
				// TODO
			}
			if state >= ipn.Starting && b.isConfigNonNilAndDifferent(cfg.rcfg, cfg.dcfg) {
				if err := b.updateTUN(cfg.rcfg, cfg.dcfg); err != nil {
					a.closeVpnService(err, b)
				}
			}
			log.Println("rundBackend 11")
		case s := <-onDisconnect:
			log.Printf("localbackend onDisconnect serviceID=%s existingServiceNil=%v existingServiceID=%s", s.ID(), vpnService.service == nil, currentVPNServiceID()) // __CYLONIX_ADD__
			log.Println("rundBackend 12")
			b.CloseTUNs()
			if vpnService.service != nil && vpnService.service.ID() == s.ID() {
				setProtectFunc(nil) // __CYLONIX_MOD__
				log.Println("rundBackend 13")
				vpnService.service = nil
				log.Printf("localbackend vpnService cleared serviceID=%s", s.ID()) // __CYLONIX_ADD__
			}
			log.Println("rundBackend 14")
		case i := <-onDNSConfigChanged:
			log.Println("rundBackend 15")
			go b.NetworkChanged(i)
			log.Println("rundBackend 16")
		// __BEGIN_CYLONIX_MOD__
		case <-onTunnelUpdated:
			log.Println("rundBackend 17")
			go b.tunnelUpdatedHandler()
			log.Println("rundBackend 18")
			// __END_CYLONIX_MOD__
		}
	}
}

func (a *App) newBackend(dataDir, directFileRoot string, appCtx AppContext, store *stateStore,
	settings settingsFunc) (*backend, error) {

	// __BEGIN_CYLONIX_MOD__
	// v1.96: tsd.System now requires a non-nil eventbus.Bus before use;
	// tsd.NewSystem allocates the bus and a default health tracker.
	sys := tsd.NewSystem()
	sys.Set(store)
	// __END_CYLONIX_MOD__

	logf := logger.RusagePrefixLog(log.Printf)
	b := &backend{
		devices:  newTUNDevices(),
		settings: settings,
		appCtx:   appCtx,
	}
	var logID logid.PrivateID
	logID.UnmarshalText([]byte("dead0000dead0000dead0000dead0000dead0000dead0000dead0000dead0000"))
	storedLogID, err := store.read(logPrefKey)
	if err == nil && storedLogID != nil {
		err = logID.UnmarshalText([]byte(storedLogID))
		if err != nil {
			log.Printf("Failed to unmarshal logID read from store: %v", err)
		} else {
			logf("Successfully unmarshaled logID from store: %s", logID.Public())
		}
	}

	// In all failure cases we ignore any errors and continue with the dead value above.
	if err != nil || storedLogID == nil {
		// Read failed or there was no previous log id.
		newLogID, err := logid.NewPrivateID()
		if err == nil {
			logID = newLogID
			enc, err := newLogID.MarshalText()
			if err == nil {
				store.write(logPrefKey, enc)
			}
		}
		log.Printf("Generated new logID: %s (%s), err: %v", logID.Public(), newLogID.Public(), err)
	}

	// __BEGIN_CYLONIX_MOD__
	// v1.96: netmon.New requires the eventbus from the tsd.System;
	// HealthTracker is now a SubSystem field, accessed via .Get().
	netMon, err := netmon.New(sys.Bus.Get(), logf)
	if err != nil {
		log.Printf("netmon.New: %v", err)
	}
	b.netMon = netMon
	b.setupLogs(dataDir, logID, logf, sys.HealthTracker.Get())
	// __END_CYLONIX_MOD__
	dialer := new(tsdial.Dialer)
	dialer.Logf = logf
	b.devices.SetDialer(dialer) // __CYLONIX_ADD__
	vf := &VPNFacade{
		SetBoth:           b.setCfg,
		GetBaseConfigFunc: b.getDNSBaseConfig,
	}
	engine, err := wgengine.NewUserspaceEngine(logf, wgengine.Config{
		Tun:            b.devices,
		Router:         vf,
		DNS:            vf,
		ReconfigureVPN: vf.ReconfigureVPN,
		Dialer:         dialer,
		SetSubsystem:   sys.Set,
		NetMon:         b.netMon,
		HealthTracker:  sys.HealthTracker.Get(), // __CYLONIX_MOD__ v1.96: SubSystem.Get()
		Metrics:        sys.UserMetricsRegistry(),
		ControlKnobs:   sys.ControlKnobs(), // __CYLONIX_ADD__
		DriveForLocal:  driveimpl.NewFileSystemForLocal(logf),
		// __BEGIN_CYLONIX_ADD__
		// v1.96 wgengine.Config gained an EventBus field. tstun.Wrap (called
		// by NewUserspaceEngine) does bus.Client("net.tstun") on it
		// unconditionally, so omitting it panics with a nil-pointer
		// dereference at tstun/wrap.go:343 during cold start. The bus must
		// be the same one tsd.System owns so all subsystems publish to a
		// single broker.
		EventBus: sys.Bus.Get(),
		// __END_CYLONIX_ADD__
	})
	if err != nil {
		return nil, fmt.Errorf("runBackend: NewUserspaceEngine: %v", err)
	}
	sys.Set(engine)
	b.devices.SetEngine(engine) // __CYLONIX_ADD__
	b.logIDPublic = logID.Public()
	ns, err := netstack.Create(logf, sys.Tun.Get(), engine, sys.MagicSock.Get(), dialer, sys.DNSManager.Get(), sys.ProxyMapper())
	if err != nil {
		return nil, fmt.Errorf("netstack.Create: %w", err)
	}
	sys.Set(ns)
	ns.ProcessLocalIPs = false // let Android kernel handle it; VpnBuilder sets this up
	ns.ProcessSubnets = true   // for Android-being-an-exit-node support
	sys.NetstackRouter.Set(true)
	if w, ok := sys.Tun.GetOK(); ok {
		w.Start()
	}
	lb, err := ipnlocal.NewLocalBackend(logf, logID.Public(), sys, 0)
	if err != nil {
		engine.Close()
		return nil, fmt.Errorf("runBackend: NewLocalBackend: %v", err)
	}
	// __BEGIN_CYLONIX_MOD__
	// v1.96: SetDirectFileRoot moved from LocalBackend to the
	// feature/taildrop Extension. Look up the registered extension
	// (auto-registered by feature/condregister) and call it there.
	if ext, ok := ipnlocal.GetExt[*taildrop.Extension](lb); ok {
		ext.SetDirectFileRoot(directFileRoot)
	} else if directFileRoot != "" {
		log.Printf("taildrop extension not registered; ignoring directFileRoot=%q", directFileRoot)
	}
	// __END_CYLONIX_MOD__

	if err := ns.Start(lb); err != nil {
		return nil, fmt.Errorf("startNetstack: %w", err)
	}
	if b.logger != nil {
		lb.SetLogFlusher(b.logger.StartFlush)
	}
	b.engine = engine
	b.backend = lb
	b.sys = sys
	go func() {
		err := lb.Start(ipn.Options{})
		if err != nil {
			log.Printf("Failed to start LocalBackend, panicking: %s", err)
			panic(err)
		}
		a.ready.Done()
	}()
	return b, nil
}

func (b *backend) isConfigNonNilAndDifferent(rcfg *router.Config, dcfg *dns.OSConfig) bool {
	if reflect.DeepEqual(rcfg, b.lastCfg) && reflect.DeepEqual(dcfg, b.lastDNSCfg) {
		b.logger.Logf("isConfigNonNilAndDifferent: no change to Routes or DNS, ignore")
		return false
	}
	return rcfg != nil
}

func (a *App) closeVpnService(err error, b *backend) {
	log.Printf("VPN update failed: %v", err)
	log.Printf("localbackend closeVpnService err=%v existingServiceNil=%v existingServiceID=%s", err, vpnService.service == nil, currentVPNServiceID()) // __CYLONIX_ADD__

	mp := new(ipn.MaskedPrefs)
	mp.WantRunning = false
	mp.WantRunningSet = true

	if _, localApiErr := a.EditPrefs(*mp); localApiErr != nil {
		log.Printf("localapi edit prefs error %v", localApiErr)
	}

	b.lastCfg = nil
	b.CloseTUNs()

	vpnService.service.DisconnectVPN()
	vpnService.service = nil
	log.Printf("localbackend closeVpnService cleared vpnService") // __CYLONIX_ADD__
}

func currentVPNServiceID() string { // __CYLONIX_ADD__
	if vpnService.service == nil { // __CYLONIX_ADD__
		return "<nil>" // __CYLONIX_ADD__
	} // __CYLONIX_ADD__
	return vpnService.service.ID() // __CYLONIX_ADD__
} // __CYLONIX_ADD__

// __BEGIN_CYLONIX_ADD__
// GetTailDropFilePath returns the absolute on-disk path for a received Taildrop
// file with the given basename.
//
// In v1.96 the LocalBackend.GetFilePath helper moved out of ipnlocal and into
// feature/taildrop, but only as an unexported method on the (also unexported)
// taildrop.manager type — so we can't call it from outside the package. On
// iOS/macOS we always run with directFileRoot set (the Network Extension
// writes received files straight into that directory), so we can reconstruct
// the same answer by joining the configured directFileRoot with the basename.
// If a safer/public Extension.GetFilePath wrapper is added upstream later,
// this should switch to use it.
func (a *App) GetTailDropFilePath(filename string) (string, error) {
	if a.backend == nil {
		return "", fmt.Errorf("backend not initialized")
	}
	if a.directFileRoot == "" {
		return "", fmt.Errorf("GetTailDropFilePath: directFileRoot not set; v1.96 taildrop does not expose a public path lookup")
	}
	if filename == "" {
		return "", fmt.Errorf("GetTailDropFilePath: empty filename")
	}
	return filepath.Join(a.directFileRoot, filename), nil
}

// __END_CYLONIX_ADD__
