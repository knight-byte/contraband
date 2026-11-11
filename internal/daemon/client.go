package daemon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

var ErrNotRunning = errors.New("contraband daemon is not running")

type Client struct {
	http *http.Client
}

func NewClient(socket string) *Client {
	dialer := &net.Dialer{}
	return &Client{http: &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socket)
		},
	}}}
}

func (client *Client) StartSession(ctx context.Context, request StartRequest) (StartResponse, error) {
	var response StartResponse
	return response, client.call(ctx, http.MethodPost, "/v1/sessions", request, &response)
}

func (client *Client) EndSession(ctx context.Context, id string, request EndRequest) (EndResponse, error) {
	var response EndResponse
	return response, client.call(ctx, http.MethodPost, "/v1/sessions/"+url.PathEscape(id)+"/end", request, &response)
}

func (client *Client) Diff(ctx context.Context, before, after string) (DiffResponse, error) {
	var response DiffResponse
	query := url.Values{"a": {before}, "b": {after}}
	return response, client.call(ctx, http.MethodGet, "/v1/diff?"+query.Encode(), nil, &response)
}

func (client *Client) Show(ctx context.Context, id string) (ShowResponse, error) {
	var response ShowResponse
	return response, client.call(ctx, http.MethodGet, "/v1/sessions/"+url.PathEscape(id), nil, &response)
}

func (client *Client) ApprovedPolicy(ctx context.Context, cwd string) (PolicyResponse, error) {
	var response PolicyResponse
	return response, client.call(ctx, http.MethodGet, "/v1/policy?"+url.Values{"cwd": {cwd}}.Encode(), nil, &response)
}

func (client *Client) Approve(ctx context.Context, request ApproveRequest) error {
	var response PolicyResponse
	return client.call(ctx, http.MethodPost, "/v1/policy/approve", request, &response)
}

// Stream calls visit for each message until ctx ends or the daemon closes the stream.
func (client *Client) Stream(ctx context.Context, session string, visit func(Message)) error {
	body, err := client.open(ctx, http.MethodGet, "/v1/stream?"+url.Values{"session": {session}}.Encode(), nil)
	if err != nil {
		return err
	}
	defer body.Close() //nolint:errcheck // read-only stream
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		var msg Message
		if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
			return fmt.Errorf("stream: %w", err)
		}
		visit(msg)
	}
	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		return fmt.Errorf("stream: %w", err)
	}
	return nil
}

func (client *Client) Export(ctx context.Context, out io.Writer) error {
	body, err := client.open(ctx, http.MethodGet, "/v1/export", nil)
	if err != nil {
		return err
	}
	defer body.Close() //nolint:errcheck // read-only stream
	if _, err := io.Copy(out, body); err != nil {
		return fmt.Errorf("export: %w", err)
	}
	return nil
}

func (client *Client) call(ctx context.Context, method, path string, request, response any) error {
	body, err := client.open(ctx, method, path, request)
	if err != nil {
		return err
	}
	defer body.Close() //nolint:errcheck // fully read below
	if err := json.NewDecoder(body).Decode(response); err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	return nil
}

func (client *Client) open(ctx context.Context, method, path string, request any) (io.ReadCloser, error) {
	var payload io.Reader
	if request != nil {
		encoded, err := json.Marshal(request)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", method, path, err)
		}
		payload = bytes.NewReader(encoded)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, method, "http://contraband"+path, payload)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	httpResponse, err := client.http.Do(httpRequest)
	if err != nil {
		var opErr *net.OpError
		if errors.As(err, &opErr) && opErr.Op == "dial" {
			return nil, ErrNotRunning
		}
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	if httpResponse.StatusCode != http.StatusOK {
		defer httpResponse.Body.Close() //nolint:errcheck // error body read below
		detail, _ := io.ReadAll(io.LimitReader(httpResponse.Body, 4096))
		return nil, fmt.Errorf("%s %s: %s: %s", method, path, httpResponse.Status, strings.TrimSpace(string(detail)))
	}
	return httpResponse.Body, nil
}
