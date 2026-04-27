// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"encoding/json"
	"errors"
	"sync"

	"tailscale.com/util/set"
	"tailscale.com/util/syspolicy"
	// __BEGIN_CYLONIX_ADD__
	// v1.96: the old syspolicy.Handler interface was removed in favor of
	// source.Store, which keys settings on pkey.Key (a string alias) and uses
	// setting.ErrNotConfigured to signal "no value".
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/setting"
	// __END_CYLONIX_ADD__
)

// syspolicyHandler is a syspolicy handler for the Android version of the Tailscale client,
// which lets the main networking code read values set via the Android RestrictionsManager.
type syspolicyHandler struct {
	a   *App
	mu  sync.RWMutex
	cbs set.HandleSet[func()]
}

// __BEGIN_CYLONIX_MOD__
// v1.96: source.Store keys are pkey.Key (a string alias) and the "missing"
// sentinel is setting.ErrNotConfigured rather than syspolicy.ErrNoSuchKey.
func (h *syspolicyHandler) ReadString(key pkey.Key) (string, error) {
	if key == "" {
		return "", setting.ErrNotConfigured
	}
	retVal, err := h.a.appCtx.GetSyspolicyStringValue(string(key))
	return retVal, translateHandlerError(err)
}

func (h *syspolicyHandler) ReadBoolean(key pkey.Key) (bool, error) {
	if key == "" {
		return false, setting.ErrNotConfigured
	}
	retVal, err := h.a.appCtx.GetSyspolicyBooleanValue(string(key))
	return retVal, translateHandlerError(err)
}

func (h *syspolicyHandler) ReadUInt64(key pkey.Key) (uint64, error) {
	if key == "" {
		return 0, setting.ErrNotConfigured
	}
	// We don't have any UInt64 policy settings as of 2024-08-06.
	return 0, errors.New("ReadUInt64 is not implemented on Android")
}

func (h *syspolicyHandler) ReadStringArray(key pkey.Key) ([]string, error) {
	if key == "" {
		return nil, setting.ErrNotConfigured
	}
	retVal, err := h.a.appCtx.GetSyspolicyStringArrayJSONValue(string(key))
	if err := translateHandlerError(err); err != nil {
		return nil, err
	}
	if retVal == "" {
		return nil, setting.ErrNotConfigured
	}
	var arr []string
	jsonErr := json.Unmarshal([]byte(retVal), &arr)
	if jsonErr != nil {
		return nil, jsonErr
	}
	return arr, err
}
// __END_CYLONIX_MOD__

func (h *syspolicyHandler) RegisterChangeCallback(cb func()) (unregister func(), err error) {
	h.mu.Lock()
	handle := h.cbs.Add(cb)
	h.mu.Unlock()
	return func() {
		h.mu.Lock()
		delete(h.cbs, handle)
		h.mu.Unlock()
	}, nil
}

func (h *syspolicyHandler) notifyChanged() {
	h.mu.RLock()
	for _, cb := range h.cbs {
		go cb()
	}
	h.mu.RUnlock()
}

func translateHandlerError(err error) error {
	// __BEGIN_CYLONIX_MOD__
	// v1.96: report missing values as setting.ErrNotConfigured (the
	// source.Store contract). Preserve compatibility with callers that
	// still hand back an err whose string matches the legacy
	// syspolicy.ErrNoSuchKey value.
	if err == nil {
		return nil
	}
	if errors.Is(err, setting.ErrNotConfigured) {
		return setting.ErrNotConfigured
	}
	if errors.Is(err, syspolicy.ErrNoSuchKey) || err.Error() == syspolicy.ErrNoSuchKey.Error() {
		return setting.ErrNotConfigured
	}
	return err
	// __END_CYLONIX_MOD__
}
