package classify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

var crusoeClient = &http.Client{Timeout: 15 * time.Second}

// CrusoeClassify calls the Crusoe Inference API (OpenAI-compatible) for classification.
func CrusoeClassify(ctx context.Context, raw, systemPrompt string) *Result {
	apiURL := os.Getenv("CRUSOE_API_URL")
	if apiURL == "" {
		apiURL = "https://inference.crusoe.ai/v1"
	}
	apiKey := os.Getenv("CRUSOE_API_KEY")
	model := os.Getenv("CRUSOE_MODEL")
	if model == "" {
		model = "meta-llama/Meta-Llama-3.1-8B-Instruct"
	}

	if apiKey == "" || apiKey == "placeholder" {
		return &Result{
			Classification: "SUSPICIOUS",
			Confidence:     0.5,
			Reason:         "Crusoe API key not configured",
			Classifier:     "crusoe",
		}
	}

	start := time.Now()

	body, _ := json.Marshal(map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": raw},
		},
		"temperature": 0.0,
		"max_tokens":  200,
	})

	req, _ := http.NewRequestWithContext(ctx, "POST", apiURL+"/chat/completions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := crusoeClient.Do(req)
	elapsed := float64(time.Since(start).Milliseconds())
	if err != nil {
		return &Result{
			Classification: "SUSPICIOUS",
			Confidence:     0.5,
			Reason:         fmt.Sprintf("Crusoe connection error: %v", err),
			Classifier:     "crusoe",
			ResponseTimeMs: elapsed,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &Result{
			Classification: "SUSPICIOUS",
			Confidence:     0.5,
			Reason:         fmt.Sprintf("Crusoe API error: %d", resp.StatusCode),
			Classifier:     "crusoe",
			ResponseTimeMs: elapsed,
		}
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return &Result{
			Classification: "SUSPICIOUS",
			Confidence:     0.5,
			Reason:         "Failed to read Crusoe response",
			Classifier:     "crusoe",
			ResponseTimeMs: elapsed,
		}
	}

	var chatResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(data, &chatResp); err != nil || len(chatResp.Choices) == 0 {
		return &Result{
			Classification: "SUSPICIOUS",
			Confidence:     0.5,
			Reason:         "Failed to parse Crusoe response",
			Classifier:     "crusoe",
			ResponseTimeMs: elapsed,
		}
	}

	content := strings.TrimSpace(chatResp.Choices[0].Message.Content)
	result := parseJSONResult(content)
	result.Classifier = "crusoe"
	result.ResponseTimeMs = elapsed
	return result
}

// parseJSONResult extracts a Result from a JSON string, handling LLM output
// that may contain extra text around the JSON.
func parseJSONResult(content string) *Result {
	var r Result
	if err := json.Unmarshal([]byte(content), &r); err == nil {
		return &r
	}
	// Try extracting JSON from surrounding text
	start := strings.Index(content, "{")
	end := strings.LastIndex(content, "}")
	if start >= 0 && end > start {
		if err := json.Unmarshal([]byte(content[start:end+1]), &r); err == nil {
			return &r
		}
	}
	return &Result{
		Classification: "SUSPICIOUS",
		Confidence:     0.5,
		Reason:         "Failed to parse classifier response",
	}
}
