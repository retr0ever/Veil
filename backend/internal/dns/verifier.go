package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/veil-waf/veil-go/internal/db"
)

type DNSRecords struct {
	Domain string   `json:"domain"`
	A      []string `json:"a,omitempty"`
	AAAA   []string `json:"aaaa,omitempty"`
	CNAME  string   `json:"cname,omitempty"`
}

type Verifier struct {
	db         *db.DB
	logger     *slog.Logger
	proxyCNAME string
}

func NewVerifier(database *db.DB, logger *slog.Logger) *Verifier {
	return &Verifier{
		db:         database,
		logger:     logger,
		proxyCNAME: envOr("VEIL_PROXY_CNAME", "router.reveil.tech"),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ResolveDomain fetches current DNS records for a domain
func ResolveDomain(domain string) (*DNSRecords, error) {
	result := &DNSRecords{Domain: domain}

	cname, err := net.LookupCNAME(domain)
	if err == nil && cname != domain+"." {
		result.CNAME = strings.TrimSuffix(cname, ".")
	}

	ips, err := net.LookupHost(domain)
	if err != nil {
		return result, nil // domain may not resolve yet, not an error
	}
	for _, ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil {
			if parsed.To4() != nil {
				result.A = append(result.A, ip)
			} else {
				result.AAAA = append(result.AAAA, ip)
			}
		}
	}
	return result, nil
}

// VerificationLoop polls unverified sites every 60 seconds
func (v *Verifier) VerificationLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sites, err := v.db.GetUnverifiedSites(ctx)
			if err != nil {
				v.logger.Error("dns: query unverified sites failed", "err", err)
				continue
			}
			for _, site := range sites {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if err := v.verifySite(ctx, site); err != nil {
					v.logger.Warn("dns: verification failed",
						"domain", site.Domain, "err", err)
				}
			}
		}
	}
}

func (v *Verifier) verifySite(ctx context.Context, site db.Site) error {
	cname, err := net.LookupCNAME(site.Domain)
	if err != nil {
		return fmt.Errorf("lookup CNAME: %w", err)
	}
	resolved := strings.TrimSuffix(cname, ".")
	if resolved == v.proxyCNAME {
		v.logger.Info("dns: site verified", "domain", site.Domain)
		return v.db.UpdateSiteStatus(ctx, site.ID, "active")
	}
	return nil
}

// VerifySiteNow is the manual "Check Now" trigger
func (v *Verifier) VerifySiteNow(ctx context.Context, siteID int) error {
	site, err := v.db.GetSiteByID(ctx, siteID)
	if err != nil || site == nil {
		return fmt.Errorf("site not found")
	}
	return v.verifySite(ctx, *site)
}

// ProxyCNAME returns the configured CNAME target
func (v *Verifier) ProxyCNAME() string {
	return v.proxyCNAME
}
