package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/veil-waf/veil-go/internal/agents"
	"github.com/veil-waf/veil-go/internal/auth"
	"github.com/veil-waf/veil-go/internal/classify"
	"github.com/veil-waf/veil-go/internal/db"
	veildns "github.com/veil-waf/veil-go/internal/dns"
	"github.com/veil-waf/veil-go/internal/handlers"
	"github.com/veil-waf/veil-go/internal/proxy"
	"github.com/veil-waf/veil-go/internal/ratelimit"
	"github.com/veil-waf/veil-go/internal/repo"
	"github.com/veil-waf/veil-go/internal/server"
	"github.com/veil-waf/veil-go/internal/sse"
	"github.com/veil-waf/veil-go/internal/ws"
)

func main() {
	logger := server.SetupLogger(os.Getenv("LOG_LEVEL"))
	slog.SetDefault(logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Connect to PostgreSQL
	database, err := db.Connect(ctx, logger)
	if err != nil {
		logger.Error("failed to connect to database", "err", err)
		os.Exit(1)
	}
	defer database.Close()

	// Init components
	production := os.Getenv("VEIL_ENV") == "production"
	sm := auth.NewSessionManager(database, logger, production)

	// Token encryption (optional — nil if env var not set)
	var tokenEnc *auth.TokenEncryptor
	if enc, err := auth.NewTokenEncryptor(); err == nil {
		tokenEnc = enc
	} else {
		logger.Warn("token encryption not configured", "err", err)
	}

	oauthCfg := auth.OAuthConfig{
		ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		BaseURL:      os.Getenv("VEIL_BASE_URL"),
	}
	oauth := auth.NewOAuthHandler(oauthCfg, sm, database, logger, tokenEnc)

	dnsVerifier := veildns.NewVerifier(database, logger)
	sseHub := sse.NewHub(logger)
	pgListener := sse.NewPGListener(database.Pool, sseHub, logger)
	limiter := ratelimit.New()

	// Classification pipeline
	pipeline := classify.NewPipeline(database, logger)

	// WebSocket manager
	wsManager := ws.NewManager(database, logger)

	// Agent loop
	agentLoop := agents.NewLoop(database, pipeline, wsManager, logger)

	// Proxy handler
	proxyHandler := proxy.NewHandler(database, pipeline, sseHub, limiter, logger)

	// HTTP handlers
	siteHandler := handlers.NewSiteHandler(database, dnsVerifier, logger)
	streamHandler := handlers.NewStreamHandler(sseHub, database)
	dashHandler := handlers.NewDashboardHandler(database, logger)
	compatHandler := handlers.NewCompatHandler(database, pipeline, proxyHandler, agentLoop, limiter, logger)

	// Repo scanner and handler (only if token encryption is configured)
	var repoHandler *handlers.RepoHandler
	if tokenEnc != nil {
		scanner := repo.NewScanner(database, tokenEnc, logger)
		repoHandler = handlers.NewRepoHandler(database, scanner, logger)
	}

	// Build router
	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(corsMiddleware)

	// Health check
	r.Get("/ping", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("pong"))
	})

	// Public config
	r.Get("/api/config", compatHandler.GetConfig)

	// Auth routes (no auth middleware)
	r.Get("/auth/github", oauth.BeginLogin)
	r.Get("/auth/github/login", oauth.BeginLogin)
	r.Get("/auth/github/callback", oauth.Callback)
	r.Get("/auth/me", oauth.Me)
	r.Post("/auth/logout", oauth.Logout)
	r.Get("/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		// Python backend uses GET for logout — support both
		oauth.Logout(w, r)
	})

	// Classification endpoint (rate limited, no auth)
	r.Post("/v1/classify", compatHandler.Classify)

	// Proxy routes (no auth — public proxy endpoints)
	r.Get("/p/{siteID}", compatHandler.ProxyInfoPage)
	r.HandleFunc("/p/{siteID}/*", compatHandler.ProxyForward)

	// WebSocket (no auth — matches Python backend)
	r.Get("/ws", wsManager.HandleWS)

	// API routes (require auth)
	r.Route("/api", func(api chi.Router) {
		api.Use(auth.RequireAuth(sm))

		// Global endpoints (Python backend compatibility)
		api.Get("/stats", compatHandler.GetGlobalStats)
		api.Get("/threats", compatHandler.GetGlobalThreats)
		api.Get("/agents", compatHandler.GetGlobalAgentLogs)
		api.Get("/requests", compatHandler.GetGlobalRequests)
		api.Get("/rules", compatHandler.GetGlobalRules)

		// Agent triggers
		api.Post("/agents/peek/run", compatHandler.TriggerPeek)
		api.Post("/agents/poke/run", compatHandler.TriggerPoke)
		api.Post("/agents/cycle", compatHandler.TriggerCycle)

		// Sites
		api.Post("/sites", siteHandler.CreateSite)
		api.Get("/sites", siteHandler.ListSites)
		api.Get("/sites/{id}", siteHandler.GetSite)
		api.Get("/sites/{id}/status", siteHandler.GetSiteStatus)
		api.Post("/sites/{id}/verify", siteHandler.VerifySiteNow)
		api.Delete("/sites/{id}", siteHandler.DeleteSite)

		// Site-scoped dashboard data
		api.Get("/sites/{id}/stats", dashHandler.GetStats)
		api.Get("/sites/{id}/threats", dashHandler.GetThreats)
		api.Get("/sites/{id}/agents", dashHandler.GetAgentLogs)
		api.Get("/sites/{id}/requests", dashHandler.GetRequests)
		api.Get("/sites/{id}/rules", dashHandler.GetRules)
		api.Get("/sites/{id}/pipeline", dashHandler.GetPipeline)

		// Analytics
		api.Get("/analytics/threat-distribution", dashHandler.GetThreatDistribution)
		api.Get("/compliance/report", dashHandler.GetComplianceReport)

		// Repo connect (incremental OAuth)
		api.Get("/auth/github/repo-connect", oauth.BeginRepoConnect)

		// Repo linking and code findings (only if token encryption is configured)
		if repoHandler != nil {
			api.Get("/sites/{id}/repos", repoHandler.ListRepos)
			api.Post("/sites/{id}/repos", repoHandler.LinkRepo)
			api.Delete("/sites/{id}/repos", repoHandler.UnlinkRepo)
			api.Get("/sites/{id}/findings", repoHandler.GetFindings)
			api.Patch("/sites/{id}/findings/{fid}", repoHandler.UpdateFinding)
		}

		// SSE stream
		api.Get("/stream/events", streamHandler.HandleSSE)
	})

	// Start background goroutines
	go server.RunWithRecovery(ctx, logger, "dns-verifier", dnsVerifier.VerificationLoop)
	go server.RunWithRecovery(ctx, logger, "session-cleanup", sm.CleanupLoop)
	go server.RunWithRecovery(ctx, logger, "pg-listener", pgListener.Listen)
	go server.RunWithRecovery(ctx, logger, "agent-loop", func(ctx context.Context) {
		agentLoop.Run(ctx)
	})
	go oauth.StateCleanupLoop(ctx)

	// Start HTTP server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 0, // SSE + WebSocket need unlimited write time
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		logger.Info("shutdown signal received")
		cancel() // stop background goroutines

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("server shutdown failed", "err", err)
		}
	}()

	logger.Info("server starting", "port", port)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server failed", "err", err)
		os.Exit(1)
	}
	logger.Info("server stopped")
}

// corsMiddleware adds CORS headers matching the Python backend configuration.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
