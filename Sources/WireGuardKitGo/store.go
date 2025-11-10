package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"

	"tailscale.com/ipn"
)

// stateStore is the Go interface for a persistent storage
// backend by ios keychain
type stateStore struct{}

func newStateStore() *stateStore {
	s := &stateStore{}
	return s
}

func prefKeyFor(id ipn.StateKey) string {
	return "statestore-" + string(id)
}

func (s *stateStore) ReadString(key string, def string) (string, error) {
	data, err := s.read(key)
	if err != nil {
		return def, err
	}
	if data == nil {
		return def, nil
	}
	return string(data), nil
}

func (s *stateStore) WriteString(key string, val string) error {
	return s.write(key, []byte(val))
}

func (s *stateStore) ReadBool(key string, def bool) (bool, error) {
	data, err := s.read(key)
	if err != nil {
		return def, err
	}
	if data == nil {
		return def, nil
	}
	return string(data) == "true", nil
}

func (s *stateStore) WriteBool(key string, val bool) error {
	data := []byte("false")
	if val {
		data = []byte("true")
	}
	return s.write(key, data)
}

func (s *stateStore) ReadState(id ipn.StateKey) ([]byte, error) {
	state, err := s.read(prefKeyFor(id))
	if err != nil {
		return nil, err
	}
	if state == nil {
		return nil, ipn.ErrStateNotExist
	}
	return state, nil
}

func (s *stateStore) WriteState(id ipn.StateKey, bs []byte) error {
	prefKey := prefKeyFor(id)
	return s.write(prefKey, bs)
}

func (s *stateStore) read(key string) ([]byte, error) {
	var data []byte
	b64, err := getKeychainItem(key)
	if err != nil {
		if errors.Is(err, errKeychainItemNotFound) {
			return nil, nil
		}
		clogf("Failed to read state @%q: %v", key, err)
		return nil, fmt.Errorf("failed to read state: %w", err)
	}
	data, err = base64.RawStdEncoding.DecodeString(string(b64))
	if err != nil {
		clogf("Failed to decode state for key @%q value=%q: %v", key, shortString(string(b64)), err)
		return nil, fmt.Errorf("failed to decode state: %w", err)
	}
	clogf("Store read: %q=%q", key, shortString(string(data)))
	return data, err
}

func (s *stateStore) write(key string, value []byte) error {
	bs64 := base64.RawStdEncoding.EncodeToString(value)
	if err := setKeychainItem(key, bs64); err != nil {
		clogf("Failed to write state for key @%q value=%q: %v", key, shortString(string(value)), err)
		return fmt.Errorf("failed to write state: %w", err)
	}
	if _, err := getKeychainItem(key); err != nil {
		// Could be due to set/get race condition. Ignore the error for now.
		clogf("Ignored error: failed to get the key @%q just set: %v", key, err)
	}
	clogf("Store written: %q=%q", key, shortString(string(value)))
	return nil
}

func (s *stateStore) GetBoolState(key ipn.StateKey) (bool, error) {
	v, err := s.ReadState(key)
	if err == nil {
		if len(v) <= 0 {
			return false, nil
		}
		return strconv.ParseBool(string(v))
	}
	if errors.Is(err, ipn.ErrStateNotExist) {
		return false, nil
	}
	return false, err
}

func (s *stateStore) SetBoolState(key ipn.StateKey, state bool) error {
	if state {
		return s.WriteState(key, []byte("true"))
	} else {
		return s.WriteState(key, []byte("false"))
	}
}
