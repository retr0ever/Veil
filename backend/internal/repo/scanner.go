package repo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/bedrock"
	"github.com/google/go-github/v69/github"
	"golang.org/x/oauth2"

	"github.com/veil-waf/veil-go/internal/auth"
	"github.com/veil-waf/veil-go/internal/db"
)

// Scanner provides GitHub repository listing, code fetching, and vulnerability analysis.
type Scanner struct {
	db        *db.DB
	encryptor *auth.TokenEncryptor
	logger    *slog.Logger
}

func NewScanner(database *db.DB, enc *auth.TokenEncryptor, logger *slog.Logger) *Scanner {
	return &Scanner{db: database, encryptor: enc, logger: logger}
}

// getClient creates an authenticated GitHub client for a user.
func (s *Scanner) getClient(ctx context.Context, userID int) (*github.Client, error) {
	encToken, err := s.db.GetGitHubToken(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get github token: %w", err)
	}
	token, err := s.encryptor.Decrypt(encToken)
	if err != nil {
		return nil, fmt.Errorf("decrypt token: %w", err)
	}
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	return github.NewClient(oauth2.NewClient(ctx, ts)), nil
}

// ListRepos returns repos the user has access to.
func (s *Scanner) ListRepos(ctx context.Context, userID int) ([]*github.Repository, error) {
	client, err := s.getClient(ctx, userID)
	if err != nil {
		return nil, err
	}
	repos, _, err := client.Repositories.List(ctx, "", &github.RepositoryListOptions{
		Sort:        "updated",
		ListOptions: github.ListOptions{PerPage: 30},
	})
	return repos, err
}

// ---------------------------------------------------------------------------
// File fetching
// ---------------------------------------------------------------------------

// sourceExtensions lists file extensions we consider source code.
var sourceExtensions = map[string]bool{
	".js": true, ".ts": true, ".jsx": true, ".tsx": true,
	".py": true, ".go": true, ".rb": true, ".php": true,
	".java": true, ".rs": true, ".html": true, ".sql": true,
	".ejs": true, ".hbs": true, ".vue": true, ".svelte": true,
}

// skipDirs lists directories to ignore when scanning.
var skipDirs = []string{
	"node_modules/", "vendor/", ".git/", "dist/", "build/",
	"__pycache__/", ".next/", ".nuxt/", "coverage/", ".venv/",
	"target/", "pkg/", "bin/",
}

// FetchRepoTree returns all source file paths in the repo.
func (s *Scanner) FetchRepoTree(ctx context.Context, userID int, owner, repo, branch string) ([]string, error) {
	client, err := s.getClient(ctx, userID)
	if err != nil {
		return nil, err
	}

	tree, _, err := client.Git.GetTree(ctx, owner, repo, branch, true)
	if err != nil {
		return nil, fmt.Errorf("get tree: %w", err)
	}

	var paths []string
	for _, entry := range tree.Entries {
		if entry.GetType() != "blob" {
			continue
		}
		path := entry.GetPath()
		if !isSourceFile(path) {
			continue
		}
		if isSkippedDir(path) {
			continue
		}
		paths = append(paths, path)
	}
	return paths, nil
}

// FetchFileContent returns the decoded content of a single file (max 500KB).
func (s *Scanner) FetchFileContent(ctx context.Context, userID int, owner, repo, branch, path string) (string, error) {
	client, err := s.getClient(ctx, userID)
	if err != nil {
		return "", err
	}

	fc, _, _, err := client.Repositories.GetContents(ctx, owner, repo, path,
		&github.RepositoryContentGetOptions{Ref: branch})
	if err != nil {
		return "", fmt.Errorf("get contents %s: %w", path, err)
	}

	if fc.GetSize() > 500*1024 {
		return "", fmt.Errorf("file too large: %d bytes", fc.GetSize())
	}

	if fc.Content != nil {
		decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(*fc.Content, "\n", ""))
		if err != nil {
			return "", fmt.Errorf("decode base64: %w", err)
		}
		return string(decoded), nil
	}

	// Fallback: use GetContents which sometimes returns decoded content
	content, err := fc.GetContent()
	if err != nil {
		return "", fmt.Errorf("get content: %w", err)
	}
	return content, nil
}

// relevanceKeywords maps attack types to code patterns that indicate relevant files.
var relevanceKeywords = map[string][]string{
	"sqli":              {"query", "sql", "db.", "database", "SELECT", "INSERT", "exec(", "prepare", "knex", "sequelize", "prisma", "pg.", "mysql"},
	"xss":               {"innerHTML", "dangerouslySetInnerHTML", "document.write", "render", "template", "v-html", "ng-bind-html", "res.send", "res.write"},
	"path_traversal":    {"readFile", "open(", "fs.", "os.", "path.join", "path.resolve", "sendFile", "createReadStream", "readdir"},
	"command_injection": {"exec(", "system(", "spawn(", "popen", "subprocess", "child_process", "os.system", "shell_exec", "Runtime.exec"},
	"ssrf":              {"fetch(", "http.get", "request(", "urllib", "curl", "axios", "got(", "node-fetch", "httpx"},
	"xxe":               {"xml", "parse", "SAXParser", "XMLReader", "etree", "lxml", "DOMParser"},
	"header_injection":  {"setHeader", "writeHead", "res.header", "response.header", "Content-Type", "Location"},
	"auth_bypass":       {"login", "auth", "password", "token", "session", "jwt", "verify", "authenticate", "bcrypt"},
	"encoding_evasion":  {"decode", "encode", "unescape", "decodeURI", "atob", "Buffer.from", "base64"},
}

// FetchRelevantFiles picks the most relevant files for an attack type, fetches their content.
// Returns map[path]content, limited to 10 files and 100KB total.
func (s *Scanner) FetchRelevantFiles(ctx context.Context, userID int, owner, repo, branch, attackType string) (map[string]string, error) {
	allPaths, err := s.FetchRepoTree(ctx, userID, owner, repo, branch)
	if err != nil {
		return nil, err
	}

	keywords := relevanceKeywords[attackType]
	if len(keywords) == 0 {
		// Generic: look at route handlers and main files
		keywords = []string{"route", "handler", "controller", "app.", "server", "api"}
	}

	// Score files by how likely they contain the vulnerability
	type scored struct {
		path  string
		score int
	}
	var candidates []scored
	for _, p := range allPaths {
		score := 0
		lower := strings.ToLower(p)
		for _, kw := range keywords {
			if strings.Contains(lower, strings.ToLower(kw)) {
				score += 2
			}
		}
		// Boost route/handler/controller files
		for _, hint := range []string{"route", "handler", "controller", "middleware", "api", "server"} {
			if strings.Contains(lower, hint) {
				score++
			}
		}
		if score > 0 {
			candidates = append(candidates, scored{p, score})
		}
	}

	// If no keyword matches, take the first 10 source files
	if len(candidates) == 0 {
		for i, p := range allPaths {
			if i >= 10 {
				break
			}
			candidates = append(candidates, scored{p, 1})
		}
	}

	// Sort by score descending, take top 10
	for i := 0; i < len(candidates); i++ {
		for j := i + 1; j < len(candidates); j++ {
			if candidates[j].score > candidates[i].score {
				candidates[i], candidates[j] = candidates[j], candidates[i]
			}
		}
	}
	if len(candidates) > 10 {
		candidates = candidates[:10]
	}

	// Fetch contents, cap total at 100KB
	files := make(map[string]string)
	totalSize := 0
	for _, c := range candidates {
		content, err := s.FetchFileContent(ctx, userID, owner, repo, branch, c.path)
		if err != nil {
			s.logger.Warn("fetch file failed", "path", c.path, "err", err)
			continue
		}
		if totalSize+len(content) > 100*1024 {
			break
		}
		files[c.path] = content
		totalSize += len(content)
	}

	return files, nil
}

// ---------------------------------------------------------------------------
// Claude code analysis
// ---------------------------------------------------------------------------

// AnalysisFinding is what Claude returns for each vulnerability found.
type AnalysisFinding struct {
	FilePath     string  `json:"file_path"`
	LineStart    int     `json:"line_start"`
	LineEnd      int     `json:"line_end"`
	Snippet      string  `json:"snippet"`
	FindingType  string  `json:"finding_type"`
	Confidence   float64 `json:"confidence"`
	Description  string  `json:"description"`
	SuggestedFix string  `json:"suggested_fix"`
}

// AnalyzeCode sends source files + attack context to Claude and returns structured findings.
func (s *Scanner) AnalyzeCode(ctx context.Context, attackType, payload, reason string, files map[string]string) ([]AnalysisFinding, error) {
	if len(files) == 0 {
		return nil, nil
	}

	var fileBlock strings.Builder
	for path, content := range files {
		fmt.Fprintf(&fileBlock, "--- %s ---\n%s\n\n", path, content)
	}

	prompt := fmt.Sprintf(`You are a security code reviewer. A web application firewall detected the following attack:

Attack type: %s
Payload: %s
Reason: %s

Below are source files from the application. Find the code that is vulnerable to this attack type.

%s
For each vulnerability found, respond with a JSON array:
[
  {
    "file_path": "exact/path/to/file.js",
    "line_start": 42,
    "line_end": 45,
    "snippet": "the vulnerable code lines",
    "finding_type": "%s",
    "confidence": 0.95,
    "description": "Explain what the vulnerability is and why it's dangerous",
    "suggested_fix": "Show the fixed code that resolves the vulnerability"
  }
]

Only report real vulnerabilities that match the detected attack type. If no vulnerable code is found, return an empty array [].
Respond ONLY with the JSON array, no other text.`, attackType, payload, reason, fileBlock.String(), attackType)

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "eu-west-1"
	}
	model := os.Getenv("BEDROCK_MODEL")
	if model == "" {
		model = "global.anthropic.claude-sonnet-4-5-20250929-v1:0"
	}

	client := anthropic.NewClient(bedrock.WithLoadDefaultConfig(ctx))

	message, err := client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: 4096,
		System: []anthropic.TextBlockParam{
			{Text: "You are an expert security code auditor. Analyze code for vulnerabilities and respond only with JSON."},
		},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(prompt)),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("claude analyze: %w", err)
	}

	if len(message.Content) == 0 {
		return nil, fmt.Errorf("empty claude response")
	}

	raw := strings.TrimSpace(message.Content[0].Text)

	var findings []AnalysisFinding
	if err := json.Unmarshal([]byte(raw), &findings); err != nil {
		// Try extracting JSON array from surrounding text
		start := strings.Index(raw, "[")
		end := strings.LastIndex(raw, "]")
		if start >= 0 && end > start {
			if err := json.Unmarshal([]byte(raw[start:end+1]), &findings); err != nil {
				s.logger.Warn("failed to parse claude findings", "raw", raw[:min(len(raw), 500)])
				return nil, fmt.Errorf("parse findings: %w", err)
			}
		}
	}

	// Validate findings
	var valid []AnalysisFinding
	for _, f := range findings {
		if f.FilePath == "" || f.Description == "" {
			continue
		}
		if f.Confidence <= 0 || f.Confidence > 1 {
			f.Confidence = 0.7
		}
		if f.FindingType == "" {
			f.FindingType = attackType
		}
		valid = append(valid, f)
	}

	return valid, nil
}

// ---------------------------------------------------------------------------
// High-level orchestration
// ---------------------------------------------------------------------------

// ScanAndAnalyze runs the full flow: fetch repo → pick files → analyze with Claude → insert findings.
func (s *Scanner) ScanAndAnalyze(ctx context.Context, siteID, userID int, attackType, payload, reason string, threatID *int64) ([]db.CodeFinding, error) {
	repo, err := s.db.GetSiteRepo(ctx, siteID)
	if err != nil || repo == nil {
		return nil, nil // no repo connected
	}

	s.logger.Info("scanning repo for vulnerabilities",
		"site", siteID, "repo", repo.RepoOwner+"/"+repo.RepoName, "attack", attackType)

	start := time.Now()

	files, err := s.FetchRelevantFiles(ctx, userID, repo.RepoOwner, repo.RepoName, repo.DefaultBranch, attackType)
	if err != nil {
		return nil, fmt.Errorf("fetch files: %w", err)
	}

	if len(files) == 0 {
		s.logger.Info("no relevant files found", "site", siteID, "attack", attackType)
		return nil, nil
	}

	s.logger.Info("fetched files for analysis", "count", len(files), "attack", attackType)

	analysisFindings, err := s.AnalyzeCode(ctx, attackType, payload, reason, files)
	if err != nil {
		return nil, fmt.Errorf("analyze code: %w", err)
	}

	// Deduplicate against existing findings
	existing, _ := s.db.GetCodeFindings(ctx, siteID)
	existingSet := make(map[string]bool)
	for _, e := range existing {
		key := fmt.Sprintf("%s:%d:%s", e.FilePath, ptrVal(e.LineStart), e.FindingType)
		existingSet[key] = true
	}

	var inserted []db.CodeFinding
	for _, af := range analysisFindings {
		key := fmt.Sprintf("%s:%d:%s", af.FilePath, af.LineStart, af.FindingType)
		if existingSet[key] {
			continue
		}

		lineStart := af.LineStart
		lineEnd := af.LineEnd
		finding := &db.CodeFinding{
			SiteID:       siteID,
			ThreatID:     threatID,
			FilePath:     af.FilePath,
			LineStart:    &lineStart,
			LineEnd:      &lineEnd,
			Snippet:      af.Snippet,
			FindingType:  af.FindingType,
			Confidence:   float32(af.Confidence),
			Description:  af.Description,
			SuggestedFix: af.SuggestedFix,
			Status:       "open",
		}
		if err := s.db.InsertCodeFinding(ctx, finding); err != nil {
			s.logger.Warn("insert finding failed", "err", err, "path", af.FilePath)
			continue
		}
		inserted = append(inserted, *finding)
	}

	s.logger.Info("code scan complete",
		"site", siteID, "findings", len(inserted), "elapsed", time.Since(start))

	return inserted, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func isSourceFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return sourceExtensions[ext]
}

func isSkippedDir(path string) bool {
	for _, dir := range skipDirs {
		if strings.Contains(path, dir) {
			return true
		}
	}
	return false
}

func ptrVal(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}
