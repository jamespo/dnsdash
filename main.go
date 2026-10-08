// Command dnsdash is a web-based DNS lookup tool modelled on MxToolbox's SuperTool.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"
)

//go:embed web
var webFS embed.FS

type server struct {
	defaultResolver string
	allowCustom     bool
	timeout         time.Duration
}

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	resolver := flag.String("resolver", "", "default DNS resolver (ip or ip:port); defaults to /etc/resolv.conf")
	allowCustom := flag.Bool("allow-custom-resolver", true, "let users pick their own resolver")
	timeout := flag.Duration("timeout", 5*time.Second, "per-query timeout")
	flag.Parse()

	def := *resolver
	if def == "" {
		def = systemResolver("1.1.1.1:53")
	}
	def, err := normalizeServer(def)
	if err != nil {
		log.Fatal(err)
	}
	s := &server{defaultResolver: def, allowCustom: *allowCustom, timeout: *timeout}

	static, _ := fs.Sub(webFS, "web")
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(static))
	mux.HandleFunc("GET /api/lookup", s.handleLookup)
	mux.HandleFunc("GET /api/commands", s.handleCommands)

	log.Printf("dnsdash listening on %s (default resolver %s)", *addr, def)
	srv := &http.Server{Addr: *addr, Handler: logRequests(mux), ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

func (s *server) handleLookup(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" || len(q) > 300 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing or too long q parameter"})
		return
	}
	server := s.defaultResolver
	if custom := r.URL.Query().Get("server"); custom != "" && custom != "default" {
		if !s.allowCustom {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "custom resolvers are disabled"})
			return
		}
		var err error
		if server, err = normalizeServer(custom); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	res := &Resolver{Server: server, Timeout: s.timeout}
	writeJSON(w, http.StatusOK, Run(ctx, res, q))
}

func (s *server) handleCommands(w http.ResponseWriter, _ *http.Request) {
	type cmd struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Example     string `json:"example"`
	}
	var list []cmd
	for _, c := range commands {
		list = append(list, cmd{c.Name, c.Description, c.Example})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"commands":        list,
		"defaultResolver": s.defaultResolver,
		"allowCustom":     s.allowCustom,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h.ServeHTTP(w, r)
		log.Printf("%s %q %s", r.Method, r.URL.RequestURI(), time.Since(start).Round(time.Millisecond)) // #nosec G706 -- URI is %q-quoted, so control chars are escaped
	})
}
