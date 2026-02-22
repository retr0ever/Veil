// Package memory provides a thin HTTP client for the mem0 hosted REST API,
// enabling agents to store and retrieve memories for long-term context.
package memory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	defaultBaseURL = "https://api.mem0.ai"
	httpTimeout    = 10 * time.Second
	maxResponseLen = 1 << 20 // 1 MiB
)

// Client is an HTTP client for the mem0 memory API.
type Client struct {
	apiKey  string
	baseURL string
	http    *http.Client
}

// Memory represents a single memory entry returned by the mem0 API.
type Memory struct {
	ID        string                 `json:"id"`
	Memory    string                 `json:"memory"`
	AgentID   string                 `json:"agent_id,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	Score     float64                `json:"score,omitempty"`
	CreatedAt string                 `json:"created_at,omitempty"`
	UpdatedAt string                 `json:"updated_at,omitempty"`
}

// Message represents a chat message sent to the mem0 Add endpoint.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// AddRequest is the payload for adding memories via POST /v1/memories/.
type AddRequest struct {
	Messages []Message              `json:"messages"`
	AgentID  string                 `json:"agent_id,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
	Infer    bool                   `json:"infer"`
}

// SearchRequest is the payload for searching memories via POST /v2/memories/search/.
type SearchRequest struct {
	Query   string                 `json:"query"`
	AgentID string                 `json:"agent_id,omitempty"`
	Filters map[string]any `json:"filters,omitempty"`
	TopK    int                    `json:"top_k,omitempty"`
}

// searchResponse wraps the v2 search response format.
type searchResponse struct {
	Results []Memory `json:"results"`
}

// NewClient creates a new mem0 API client. It reads the MEM0_API_KEY
// environment variable (required) and the optional MEM0_API_URL variable
// (defaults to https://api.mem0.ai). Returns nil if MEM0_API_KEY is not set.
func NewClient() *Client {
	key := os.Getenv("MEM0_API_KEY")
	if key == "" {
		return nil
	}

	base := os.Getenv("MEM0_API_URL")
	if base == "" {
		base = defaultBaseURL
	}

	return &Client{
		apiKey:  key,
		baseURL: base,
		http: &http.Client{
			Timeout: httpTimeout,
		},
	}
}

// Add stores one or more messages as memories in mem0.
func (c *Client) Add(ctx context.Context, req *AddRequest) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("memory: marshal add request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/v1/memories/", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("memory: create add request: %w", err)
	}
	c.setHeaders(httpReq)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("memory: add request failed: %w", err)
	}
	defer resp.Body.Close()
	// Drain body to allow connection reuse.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseLen))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("memory: add returned status %d", resp.StatusCode)
	}
	return nil
}

// Search queries mem0 for memories matching the given request and returns
// the results ordered by relevance score.
func (c *Client) Search(ctx context.Context, req *SearchRequest) ([]Memory, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("memory: marshal search request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/v2/memories/search/", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("memory: create search request: %w", err)
	}
	c.setHeaders(httpReq)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("memory: search request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseLen))
	if err != nil {
		return nil, fmt.Errorf("memory: read search response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("memory: search returned status %d: %s",
			resp.StatusCode, string(data))
	}

	// Try v2 format: {"results": [...]}
	var wrapped searchResponse
	if err := json.Unmarshal(data, &wrapped); err == nil && wrapped.Results != nil {
		return wrapped.Results, nil
	}

	// Fall back to v1 format: bare [...]
	var memories []Memory
	if err := json.Unmarshal(data, &memories); err != nil {
		return nil, fmt.Errorf("memory: decode search response: %w", err)
	}
	return memories, nil
}

// setHeaders adds the required authorization and content-type headers.
func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Token "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
}
