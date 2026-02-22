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
// Pipeline follows the spec cascade:
//
//	Stage 0: Regex (instant)  → SAFE=done, MALICIOUS=block, SUSPICIOUS=continue
//	Stage 1: Crusoe fast LLM  → only if regex was SUSPICIOUS
//	Stage 2: Claude deep LLM  → only if Stage 1 says SUSPICIOUS/MALICIOUS
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
	regexResult.RulesVersion = rules.Version

	// Fast path: regex says SAFE with confidence → done, no LLM needed.
	// This is the common case for normal traffic (static assets, standard pages).
	if regexResult.Classification == "SAFE" {
		return regexResult
	}

	// Fast path: regex says MALICIOUS with high confidence → block immediately.
	if regexResult.Classification == "MALICIOUS" && regexResult.Confidence >= 0.85 {
		regexResult.Blocked = true
		return regexResult
	}

	// Stage 1: Crusoe fast check (only if regex found something suspicious or
	// low-confidence malicious)
	finalResult := regexResult
	classification := regexResult.Classification
	confidence := regexResult.Confidence

	crusoeResult := CrusoeClassify(ctx, rawRequest, rules.CrusoePrompt)

	// Only accept Crusoe's verdict if it actually succeeded (not a fallback).
	// Crusoe fallback on API errors returns Confidence == 0.5 exactly — ignore those.
	crusoeSucceeded := crusoeResult.Confidence != 0.5 || crusoeResult.Classification == "SAFE"
	if crusoeSucceeded {
		if crusoeResult.Classification == "MALICIOUS" {
			classification = crusoeResult.Classification
			finalResult = crusoeResult
			confidence = crusoeResult.Confidence
		} else if crusoeResult.Classification == "SAFE" && regexResult.Classification != "MALICIOUS" {
			// Crusoe says SAFE and regex didn't find definitive malice → trust Crusoe
			classification = "SAFE"
			finalResult = crusoeResult
			confidence = crusoeResult.Confidence
		} else if crusoeResult.Classification == "SUSPICIOUS" && regexResult.Classification != "MALICIOUS" {
			classification = crusoeResult.Classification
			finalResult = crusoeResult
			confidence = crusoeResult.Confidence
		}
	}
	// If Crusoe failed (API error), keep the regex result as-is.

	// Stage 2: Claude deep analysis (only if still suspicious or malicious)
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
