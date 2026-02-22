package repo

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/go-github/v69/github"
	"golang.org/x/oauth2"

	"github.com/veil-waf/veil-go/internal/auth"
	"github.com/veil-waf/veil-go/internal/db"
)

// Scanner provides GitHub repository listing and code search capabilities.
type Scanner struct {
	db        *db.DB
	encryptor *auth.TokenEncryptor
	logger    *slog.Logger
}

// NewScanner creates a new Scanner instance.
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

// ScanForVulnerability searches the connected repo for code related to a threat.
func (s *Scanner) ScanForVulnerability(ctx context.Context, site db.Site, threat db.Threat) error {
	repo, err := s.db.GetSiteRepo(ctx, site.ID)
	if err != nil || repo == nil {
		return nil // no repo connected, skip
	}

	client, err := s.getClient(ctx, site.UserID)
	if err != nil {
		return err
	}

	query := fmt.Sprintf("repo:%s/%s %s", repo.RepoOwner, repo.RepoName, threat.Category)
	results, _, err := client.Search.Code(ctx, query, &github.SearchOptions{
		ListOptions: github.ListOptions{PerPage: 10},
	})
	if err != nil {
		return fmt.Errorf("search code: %w", err)
	}

	for _, result := range results.CodeResults {
		finding := &db.CodeFinding{
			SiteID:      site.ID,
			ThreatID:    &threat.ID,
			FilePath:    result.GetPath(),
			FindingType: threat.Category,
			Confidence:  0.5,
			Description: fmt.Sprintf("Potential %s vulnerability pattern found in %s", threat.Category, result.GetPath()),
			Status:      "open",
		}
		if err := s.db.InsertCodeFinding(ctx, finding); err != nil {
			s.logger.Warn("insert code finding failed", "err", err, "path", result.GetPath())
		}
	}
	return nil
}
