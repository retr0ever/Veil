package classify

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/bedrock"
)

// ClaudeClassify calls Claude via AWS Bedrock for deep request analysis.
func ClaudeClassify(ctx context.Context, raw, systemPrompt string) *Result {
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "eu-west-1"
	}
	model := os.Getenv("BEDROCK_MODEL")
	if model == "" {
		model = "global.anthropic.claude-sonnet-4-5-20250929-v1:0"
	}

	// Check if AWS credentials are available
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" && os.Getenv("AWS_PROFILE") == "" {
		return &Result{
			Classification: "SUSPICIOUS",
			Confidence:     0.5,
			AttackType:     "none",
			Reason:         "AWS credentials not configured",
			Classifier:     "claude",
		}
	}

	start := time.Now()

	client := anthropic.NewClient(
		bedrock.WithLoadDefaultConfig(ctx),
	)

	message, err := client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: 300,
		System: []anthropic.TextBlockParam{
			{Text: systemPrompt},
		},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(raw)),
		},
	})

	elapsed := float64(time.Since(start).Milliseconds())

	if err != nil {
		return &Result{
			Classification: "SUSPICIOUS",
			Confidence:     0.5,
			AttackType:     "none",
			Reason:         fmt.Sprintf("Claude API error: %v", err),
			Classifier:     "claude",
			ResponseTimeMs: elapsed,
		}
	}

	if len(message.Content) == 0 {
		return &Result{
			Classification: "SUSPICIOUS",
			Confidence:     0.5,
			AttackType:     "none",
			Reason:         "Empty Claude response",
			Classifier:     "claude",
			ResponseTimeMs: elapsed,
		}
	}

	content := strings.TrimSpace(message.Content[0].Text)
	result := parseJSONResult(content)
	result.Classifier = "claude"
	result.ResponseTimeMs = elapsed
	return result
}
