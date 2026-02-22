package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/caddyserver/certmagic"
	"github.com/veil-waf/veil-go/internal/db"
)

// CertManager manages automatic TLS certificates via certmagic with on-demand provisioning.
type CertManager struct {
	db     *db.DB
	logger *slog.Logger
	cfg    *certmagic.Config
}

// NewCertManager creates a CertManager that provisions TLS certificates on demand
// for domains registered in the database.
func NewCertManager(database *db.DB, logger *slog.Logger) *CertManager {
	certmagic.DefaultACME.Email = os.Getenv("ACME_EMAIL")
	certmagic.DefaultACME.Agreed = true

	if os.Getenv("VEIL_ENV") != "production" {
		certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
	}

	cfg := certmagic.NewDefault()
	cm := &CertManager{db: database, logger: logger, cfg: cfg}

	cfg.OnDemand = &certmagic.OnDemandConfig{
		DecisionFunc: cm.allowCert,
	}

	return cm
}

// allowCert is the on-demand decision function that checks whether a certificate
// should be provisioned for the given domain name.
func (cm *CertManager) allowCert(ctx context.Context, name string) error {
	site, err := cm.db.GetSiteByDomain(ctx, name)
	if err != nil || site == nil {
		return fmt.Errorf("unknown domain: %s", name)
	}
	if site.Status != "active" && site.Status != "ssl_provisioning" && site.Status != "live" {
		return fmt.Errorf("site not verified: %s (status=%s)", name, site.Status)
	}
	return nil
}

// ListenAndServe starts an HTTPS server using certmagic's TLS configuration.
// It pre-manages known domains, then serves the handler over TLS on port 443.
func (cm *CertManager) ListenAndServe(handler http.Handler) error {
	proxyCNAME := os.Getenv("VEIL_PROXY_CNAME")
	dashDomain := os.Getenv("VEIL_DASHBOARD_DOMAIN")

	var domains []string
	if proxyCNAME != "" {
		domains = append(domains, proxyCNAME)
	}
	if dashDomain != "" {
		domains = append(domains, dashDomain)
	}

	cm.logger.Info("starting TLS server", "domains", domains)

	// Pre-manage known domains so their certs are ready immediately
	if len(domains) > 0 {
		if err := cm.cfg.ManageSync(context.Background(), domains); err != nil {
			return fmt.Errorf("manage known domains: %w", err)
		}
	}

	// Create TLS listener using certmagic's TLS config
	tlsCfg := cm.cfg.TLSConfig()
	ln, err := tls.Listen("tcp", fmt.Sprintf(":%d", certmagic.HTTPSPort), tlsCfg)
	if err != nil {
		return fmt.Errorf("tls listen: %w", err)
	}

	cm.logger.Info("serving HTTPS", "port", certmagic.HTTPSPort)
	return http.Serve(ln, handler)
}

// TLSConfig returns the certmagic config for use with custom listeners.
func (cm *CertManager) TLSConfig() *certmagic.Config {
	return cm.cfg
}
