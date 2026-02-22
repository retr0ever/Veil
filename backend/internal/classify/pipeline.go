package classify

import (
	"context"
	"log/slog"

	"github.com/veil-waf/veil-go/internal/db"
)

// Pipeline orchestrates the multi-stage classification cascade:
// regex → Crusoe LLM → Claude deep analysis.
type Pipeline struct {
	db     *db.DB
	logger *slog.Logger
}

// NewPipeline creates a new classification pipeline.
func NewPipeline(database *db.DB, logger *slog.Logger) *Pipeline {
	return &Pipeline{db: database, logger: logger}
}

// Classify runs the full classification pipeline on a raw HTTP request string.
// It fetches rules for the given siteID to pass as system prompts to LLMs.
func (p *Pipeline) Classify(ctx context.Context, siteID int, rawRequest string) *Result {
	rules, err := p.db.GetCurrentRules(ctx, siteID)
	if err != nil {
		p.logger.Debug("no rules found for site, using defaults", "site_id", siteID)
	}

	return p.ClassifyWithRules(ctx, rawRequest, rules)
}

// ClassifyWithRules runs classification with explicit rules (can be nil for defaults).
func (p *Pipeline) ClassifyWithRules(ctx context.Context, rawRequest string, rules *db.Rules) *Result {
	if rules == nil {
		rules = &db.Rules{
			Version:      1,
			CrusoePrompt: defaultCrusoePrompt,
			ClaudePrompt: defaultClaudePrompt,
		}
	}

	// Stage 0: Regex classifier (always runs, instant)
	regexResult := RegexClassify(rawRequest)
	classification := regexResult.Classification
	confidence := regexResult.Confidence
	finalResult := regexResult

	// Stage 1: Crusoe fast check
	crusoeResult := CrusoeClassify(ctx, rawRequest, rules.CrusoePrompt)
	if crusoeResult.Classification == "MALICIOUS" ||
		(crusoeResult.Classification == "SUSPICIOUS" && classification != "MALICIOUS") {
		classification = crusoeResult.Classification
		finalResult = crusoeResult
		confidence = crusoeResult.Confidence
	}

	// Stage 2: Claude deep analysis (only if suspicious or malicious)
	if classification == "SUSPICIOUS" || classification == "MALICIOUS" {
		claudeResult := ClaudeClassify(ctx, rawRequest, rules.ClaudePrompt)
		if claudeResult.Classification == "MALICIOUS" {
			classification = claudeResult.Classification
			finalResult = claudeResult
			confidence = claudeResult.Confidence
		} else if claudeResult.Classification == "SAFE" && regexResult.Classification != "MALICIOUS" {
			classification = "SAFE"
			finalResult = claudeResult
			confidence = claudeResult.Confidence
		}
	}

	blocked := classification == "MALICIOUS" && confidence > 0.6

	return &Result{
		Classification: classification,
		Confidence:     confidence,
		Blocked:        blocked,
		AttackType:     finalResult.AttackType,
		Classifier:     finalResult.Classifier,
		Reason:         finalResult.Reason,
		ResponseTimeMs: finalResult.ResponseTimeMs,
		RulesVersion:   rules.Version,
	}
}

const defaultCrusoePrompt = `You are a web application firewall. Analyze the HTTP request and respond with a JSON object:
{"classification": "SAFE" | "SUSPICIOUS" | "MALICIOUS", "confidence": 0.0-1.0, "attack_type": "sqli" | "xss" | "path_traversal" | "command_injection" | "ssrf" | "xxe" | "none", "reason": "brief explanation"}

Only respond with the JSON object, no other text.`

const defaultClaudePrompt = `You are an advanced web application firewall performing deep analysis. The request has been flagged as potentially malicious. Analyze it carefully and respond with a JSON object:
{"classification": "SAFE" | "SUSPICIOUS" | "MALICIOUS", "confidence": 0.0-1.0, "attack_type": "sqli" | "xss" | "path_traversal" | "command_injection" | "ssrf" | "xxe" | "auth_bypass" | "none", "reason": "detailed explanation of why this is or is not an attack"}

Consider context, encoding evasion, and advanced techniques. Only respond with the JSON object.`

// DefaultCrusoePrompt returns the default Crusoe system prompt.
func DefaultCrusoePrompt() string { return defaultCrusoePrompt }

// DefaultClaudePrompt returns the default Claude system prompt.
func DefaultClaudePrompt() string { return defaultClaudePrompt }
