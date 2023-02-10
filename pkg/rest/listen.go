package rest

import (
	"context"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/NYTimes/gziphandler"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/twitchtv/twirp"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
	dbc "github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils"
	rpcScanner "github.com/aquasecurity/trivy/rpc/scanner"
)

const updateInterval = 1 * time.Hour

// RestServer represents Trivy Rest server
type RestServer struct {
	appVersion   string
	addr         string
	cacheDir     string
	token        string
	tokenHeader  string
	dbRepository string
}

// NewRestServer returns an instance of RestServer
func NewRestServer(appVersion, addr, cacheDir, token, tokenHeader, dbRepository string) RestServer {
	return RestServer{
		appVersion:   appVersion,
		addr:         addr,
		cacheDir:     cacheDir,
		token:        token,
		tokenHeader:  tokenHeader,
		dbRepository: dbRepository,
	}
}

// ListenAndServe starts Trivy server
func (s RestServer) ListenAndServe(insecure bool) error {
	requestWg := &sync.WaitGroup{}
	dbUpdateWg := &sync.WaitGroup{}

	go func() {
		worker := newDBWorker(dbc.NewClient(s.cacheDir, true, insecure, dbc.WithDBRepository(s.dbRepository)))
		ctx := context.Background()
		for {
			time.Sleep(updateInterval)
			if err := worker.update(ctx, s.appVersion, s.cacheDir, dbUpdateWg, requestWg); err != nil {
				log.Logger.Errorf("%+v\n", err)
			}
		}
	}()

	handler := newHandler(dbUpdateWg, requestWg, s.token, s.tokenHeader)
	log.Logger.Infof("Listening %s...", s.addr)

	return http.ListenAndServe(s.addr, handler)
}

func newHandler(dbUpdateWg, requestWg *sync.WaitGroup, token, tokenHeader string) http.Handler {
	withWaitGroup := func(base http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Stop processing requests during DB update
			dbUpdateWg.Wait()

			// Wait for all requests to be processed before DB update
			requestWg.Add(1)
			defer requestWg.Done()

			base.ServeHTTP(w, r)

		})
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(NewStructuredLogger())
	r.Use(middleware.Recoverer)
	r.Use(middleware.URLFormat)
	r.Use(render.SetContentType(render.ContentTypeJSON))

	scanServer := newScannerServer()
	scanHandler := withToken(withWaitGroup(scanServer), token, tokenHeader)

	r.Post("/rest/orgs/{org_id}/packages/{purl}/issues", gziphandler.GzipHandler(scanHandler).ServeHTTP)

	r.Get("/healthz", func(rw http.ResponseWriter, r *http.Request) {
		if _, err := rw.Write([]byte("ok")); err != nil {
			log.Logger.Errorf("health check error: %s", err)
		}
	})

	return r
}

func withToken(base http.Handler, token, tokenHeader string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token != "" && token != r.Header.Get(tokenHeader) {
			rpcScanner.WriteError(w, twirp.NewError(twirp.Unauthenticated, "invalid token"))
			return
		}
		base.ServeHTTP(w, r)
	})
}

type dbWorker struct {
	dbClient dbc.Operation
}

func newDBWorker(dbClient dbc.Operation) dbWorker {
	return dbWorker{dbClient: dbClient}
}

func (w dbWorker) update(ctx context.Context, appVersion, cacheDir string,
	dbUpdateWg, requestWg *sync.WaitGroup) error {
	log.Logger.Debug("Check for DB update...")
	needsUpdate, err := w.dbClient.NeedsUpdate(appVersion, false)
	if err != nil {
		return xerrors.Errorf("failed to check if db needs an update")
	} else if !needsUpdate {
		return nil
	}

	log.Logger.Info("Updating DB...")
	if err = w.hotUpdate(ctx, cacheDir, dbUpdateWg, requestWg); err != nil {
		return xerrors.Errorf("failed DB hot update: %w", err)
	}
	return nil
}

func (w dbWorker) hotUpdate(ctx context.Context, cacheDir string, dbUpdateWg, requestWg *sync.WaitGroup) error {
	tmpDir, err := os.MkdirTemp("", "db")
	if err != nil {
		return xerrors.Errorf("failed to create a temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err = w.dbClient.Download(ctx, tmpDir); err != nil {
		return xerrors.Errorf("failed to download vulnerability DB: %w", err)
	}

	log.Logger.Info("Suspending all requests during DB update")
	dbUpdateWg.Add(1)
	defer dbUpdateWg.Done()

	log.Logger.Info("Waiting for all requests to be processed before DB update...")
	requestWg.Wait()

	if err = db.Close(); err != nil {
		return xerrors.Errorf("failed to close DB: %w", err)
	}

	// Copy trivy.db
	if _, err = utils.CopyFile(db.Path(tmpDir), db.Path(cacheDir)); err != nil {
		return xerrors.Errorf("failed to copy the database file: %w", err)
	}

	// Copy metadata.json
	if _, err = utils.CopyFile(metadata.Path(tmpDir), metadata.Path(cacheDir)); err != nil {
		return xerrors.Errorf("failed to copy the metadata file: %w", err)
	}

	log.Logger.Info("Reopening DB...")
	if err = db.Init(cacheDir); err != nil {
		return xerrors.Errorf("failed to open DB: %w", err)
	}

	return nil
}
