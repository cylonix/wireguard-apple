package libtailscale

// Converted from tailscale-android/android/src/main/java/com/tailscale/ipn/ui/localapi/Client.kt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"sync/atomic"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
)

const (
	endpointDebug             = "debug"
	endpointDebugLog          = "debug-log"
	endpointBugReport         = "bugreport"
	endpointPrefs             = "prefs"
	endpointFileTargets       = "file-targets"
	endpointUploadMetrics     = "upload-client-metrics"
	endpointStart             = "start"
	endpointLoginInteractive  = "login-interactive"
	endpointResetAuth         = "reset-auth"
	endpointLogout            = "logout"
	endpointProfiles          = "profiles/"
	endpointProfilesCurrent   = "profiles/current"
	endpointStatus            = "status"
	endpointTKAStatus         = "tka/status"
	endpointTKASign           = "tka/sign"
	endpointTKAVerifyDeepLink = "tka/verify-deeplink"
	endpointPing              = "ping"
	endpointFiles             = "files/"
	endpointFilePut           = "file-put/"
	endpointTailfsServerAddr  = "tailfs/fileserver-address"
	endpointEnableExitNode    = "set-use-exit-node-enabled"
)

type Client struct {
	app Application
}

func NewClient(app Application) *Client {
	return &Client{app: app}
}

func (c *Client) Start(optionsJsonString string) error {
	return c.post(endpointStart, 0, []byte(optionsJsonString), nil)
}

func (c *Client) StartLoginInteractive() error {
	err := c.post(endpointLoginInteractive, 0, nil, nil)
	log.Printf("start login interface result: %v", err)
	return err
}

func (c *Client) EditPrefs(prefsJsonString string, result interface{}) error {
	return c.patch(endpointPrefs, []byte(prefsJsonString), result)
}

func (c *Client) Profiles(result interface{}) error {
	return c.get(endpointProfiles, result)
}

func (c *Client) CurrentProfile(result interface{}) error {
	return c.get(endpointProfilesCurrent, result)
}

func (c *Client) AddProfile() error {
	return c.put(endpointProfiles, nil, nil)
}

func (c *Client) SwitchProfile(profile ipn.ProfileID) error {
	return c.post(endpointProfiles+url.PathEscape(string(profile)), 0, nil, nil)
}

func (c *Client) Ping(ip string) (string, error) {
	result := &ipnstate.PingResult{}
	if err := c.post(endpointPing+"?ip="+url.QueryEscape(ip)+"&type=disco", 2000, nil, result); err != nil {
		result.Err = err.Error()
	}
	v, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("marshaling ping result: %w", err)
	}
	return string(v), nil
}

func (c *Client) DebugRebind() error {
	return c.post(endpointDebug+"?action=rebind", 0, nil, nil)
}

func (c *Client) DebugReStun() error {
	return c.post(endpointDebug+"?action=restun", 0, nil, nil)
}

func (c *Client) DebugBreakDERPConns() error {
	return c.post(endpointDebug+"?action=break-derp-conns", 0, nil, nil)
}

func (c *Client) Status() (string, error) {
	result := &ipnstate.Status{}
	if err := c.get(endpointStatus, result); err != nil {
		return "", err
	}
	v, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("marshaling status: %w", err)
	}
	return string(v), nil
}

func (c *Client) Logout() error {
	return c.post(endpointLogout, 0, nil, nil)
}

func (c *Client) WaitingFiles(result interface{}) error {
	return c.get(endpointFiles, result)
}

func (c *Client) DeleteFile(filename string) error {
	return c.delete(endpointFiles+filename, nil, nil)
}

type countingByteStreamAdapter struct {
	r *bytes.Reader
	n atomic.Int64
}

func (b *countingByteStreamAdapter) Read() ([]byte, error) {
	buf := make([]byte, 32*1024)
	n, err := b.r.Read(buf)
	if n > 0 {
		b.n.Add(int64(n))
	}
	return buf[:n], err
}

func (b *countingByteStreamAdapter) Close() error {
	return nil
}

func (b *countingByteStreamAdapter) BytesRead() int64 {
	return b.n.Load()
}

type fileStreamAdapter struct {
	f      *os.File
	n      atomic.Int64
	buffer []byte
}

func newFileStreamAdapter(f *os.File) *fileStreamAdapter {
	return &fileStreamAdapter{
		f:      f,
		buffer: make([]byte, 32*1024), // 32KB buffer
	}
}

func (fs *fileStreamAdapter) Read() ([]byte, error) {
	n, err := fs.f.Read(fs.buffer)
	if n > 0 {
		fs.n.Add(int64(n))
	}
	return fs.buffer[:n], err
}

func (fs *fileStreamAdapter) Close() error {
	return fs.f.Close()
}

func (fs *fileStreamAdapter) BytesRead() int64 {
	return fs.n.Load()
}

type OutgoingFile struct {
	ipn.OutgoingFile
	Path string
}

type MultipartFiles struct {
	parts []*FilePart
}

func (m *MultipartFiles) Len() int32 {
	return int32(len(m.parts))
}

func (m *MultipartFiles) Get(i int32) *FilePart {
	return m.parts[i]
}

func (c *Client) PutTaildropFiles(peerID string, files []OutgoingFile, result interface{}) error {
	// Create manifest file part
	manifest, err := json.Marshal(files)
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	manifestCounter := &countingByteStreamAdapter{r: bytes.NewReader(manifest)}
	manifestPart := &FilePart{
		Filename:      "manifest.json",
		ContentType:   "application/json",
		ContentLength: int64(len(manifest)),
		Body:          manifestCounter,
	}

	parts := make([]*FilePart, 0, len(files)+1)
	parts = append(parts, manifestPart)

	// Track progress for all files
	streamers := make([]*fileStreamAdapter, len(files))

	// Add each file as a part
	for i, file := range files {
		f, err := os.Open(file.Path)
		if err != nil {
			return fmt.Errorf("open file %s: %w", file.Name, err)
		}
		defer f.Close()

		info, err := f.Stat()
		if err != nil {
			return fmt.Errorf("stat file %s: %w", file.Name, err)
		}

		// Create counting reader for this file
		streamer := newFileStreamAdapter(f)
		streamers[i] = streamer

		part := &FilePart{
			Filename:      file.Name,
			ContentLength: info.Size(),
			Body:          streamer,
		}
		parts = append(parts, part)
	}

	return c.postMultipart(fmt.Sprintf(endpointFilePut+peerID), &MultipartFiles{parts}, result)
}

func (c *Client) get(path string, result interface{}) error {
	resp, err := c.app.CallLocalAPI(defaultTimeout(), "GET", "/localapi/v0/"+path, nil)
	if err != nil {
		return fmt.Errorf("calling local API: %w", err)
	}
	return handleResponse(resp, result)
}

func (c *Client) delete(path string, body []byte, result interface{}) error {
	var input *inputStreamAdapter
	if body != nil {
		input = &inputStreamAdapter{data: body}
	}
	resp, err := c.app.CallLocalAPI(defaultTimeout(), "DELETE", "/localapi/v0/"+path, input)
	if err != nil {
		return fmt.Errorf("calling local API: %w", err)
	}
	return handleResponse(resp, result)
}

func (c *Client) put(path string, body []byte, result interface{}) error {
	var input *inputStreamAdapter
	if body != nil {
		input = &inputStreamAdapter{data: body}
	}

	resp, err := c.app.CallLocalAPI(defaultTimeout(), "PUT", "/localapi/v0/"+path, input)
	if err != nil {
		return fmt.Errorf("calling local API: %w", err)
	}
	return handleResponse(resp, result)
}

type inputStreamAdapter struct {
	read bool
	data []byte
}

func (a *inputStreamAdapter) Read() ([]byte, error) {
	if a == nil {
		return nil, nil
	}
	if a.read {
		return nil, nil
	}
	a.read = true
	if len(a.data) == 0 {
		return nil, nil
	}
	return a.data, nil
}

func (a *inputStreamAdapter) Close() error {
	a.read = true
	a.data = nil
	return nil
}

func (c *Client) post(path string, timeout int, body []byte, result interface{}) error {
	var input *inputStreamAdapter
	if body != nil {
		input = &inputStreamAdapter{data: body}
	}
	if timeout <= 0 {
		timeout = defaultTimeout()
	}

	resp, err := c.app.CallLocalAPI(timeout, "POST", "/localapi/v0/"+path, input)
	if err != nil {
		return fmt.Errorf("calling local API: %w", err)
	}
	err = handleResponse(resp, result)
	log.Printf("POST: %v err=%v", path, err)
	return err
}

func (c *Client) patch(path string, body []byte, result interface{}) error {
	var input *inputStreamAdapter
	if body != nil {
		input = &inputStreamAdapter{data: body}
	}
	resp, err := c.app.CallLocalAPI(defaultTimeout(), "PATCH", "/localapi/v0/"+path, input)
	if err != nil {
		return fmt.Errorf("calling local API: %w", err)
	}
	return handleResponse(resp, result)
}

func handleResponse(resp LocalAPIResponse, result interface{}) error {
	if resp.StatusCode() >= 400 {
		body, err := resp.BodyBytes()
		return fmt.Errorf("request failed with status %d: %s %w", resp.StatusCode(), string(body), err)
	}

	v, err := resp.BodyBytes()
	if err != nil {
		return fmt.Errorf("error reading response: %w", err)
	}

	if result != nil && len(v) > 0 {
		// Handle string result type specially
		if s, ok := result.(*string); ok {
			*s = string(v)
			return nil
		}
		if err := json.Unmarshal(v, result); err != nil {
			s := string(v)
			if len(s) > 200 {
				s = s[:200] + "..."
			}
			return fmt.Errorf("unmarshaling response '%q': %w", s, err)
		}
	}

	return nil
}

func (c *Client) postMultipart(path string, parts FileParts, result interface{}) error {
	resp, err := c.app.CallLocalAPIMultipart(
		24*60*60*1000, // 24 hour timeout
		"POST",
		fmt.Sprintf("/localapi/v0/%s", path),
		parts,
	)
	if err != nil {
		return fmt.Errorf("calling multipart API: %w", err)
	}
	return handleResponse(resp, result)
}

func defaultTimeout() int {
	return 30000 // 30 seconds in milliseconds
}
