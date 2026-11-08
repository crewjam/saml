package server

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Request logs and metrics. Every request is logged with slog, and
// counted in Prometheus metrics, which MetricsHandler serves. On Fly.io
// they are scraped from a port of their own (fly.toml's [metrics]), so
// they are not public.

type metrics struct {
	reg         *prometheus.Registry
	requests    *prometheus.CounterVec
	duration    *prometheus.HistogramVec
	inFlight    prometheus.Gauge
	rateLimited prometheus.Counter
}

func (s *Server) newMetrics() *metrics {
	reg := prometheus.NewRegistry()
	m := &metrics{
		reg: reg,
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gosaml_http_requests_total",
			Help: "HTTP requests, by method, route pattern and status code.",
		}, []string{"method", "route", "code"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "gosaml_http_request_duration_seconds",
			Help:    "How long HTTP requests took, by method and route pattern.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30},
		}, []string{"method", "route"}),
		inFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "gosaml_http_requests_in_flight",
			Help: "HTTP requests being served, including followed live logs.",
		}),
		rateLimited: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "gosaml_http_rate_limited_total",
			Help: "HTTP requests refused with 429 by the per-client rate limit.",
		}),
	}
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.requests, m.duration, m.inFlight, m.rateLimited,
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "gosaml_instances",
			Help: "Test IdPs and SPs that exist.",
		}, func() float64 {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			n, err := s.Store.CountInstances(ctx)
			if err != nil {
				return -1
			}
			return float64(n)
		}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "gosaml_live_log_subscribers",
			Help: "Management pages following their instance's log.",
		}, func() float64 {
			s.hub.mu.Lock()
			defer s.hub.mu.Unlock()
			return float64(s.hub.total)
		}),
	)
	return m
}

// MetricsHandler serves the server's metrics in the Prometheus format.
// Serve it on its own address, not with the application.
func (s *Server) MetricsHandler() http.Handler {
	return promhttp.HandlerFor(s.metrics.reg, promhttp.HandlerOpts{})
}

// statusWriter notes a response's status and size.
type statusWriter struct {
	http.ResponseWriter
	status int
	size   int64
}

func (w *statusWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.size += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// route is the pattern r matches, such as "GET /idp/{id}/sso": a metric
// label of bounded cardinality, which never holds a management secret.
func (s *Server) route(r *http.Request) string {
	_, pattern := s.mux.Handler(r)
	if pattern == "" {
		return "unmatched"
	}
	return pattern
}

// observe serves r with next, then logs and counts it.
func (s *Server) observe(w http.ResponseWriter, r *http.Request, next func(http.ResponseWriter, *http.Request)) {
	start := time.Now()
	route := s.route(r)
	ip := s.clientIP(r)

	s.metrics.inFlight.Inc()
	sw := &statusWriter{ResponseWriter: w}
	defer func() {
		s.metrics.inFlight.Dec()
		elapsed := time.Since(start)
		status := sw.status
		if status == 0 {
			status = http.StatusOK
		}
		if status == http.StatusTooManyRequests {
			s.metrics.rateLimited.Inc()
		}
		method := r.Method
		if !knownMethod(method) {
			method = "other"
		}
		s.metrics.requests.WithLabelValues(method, route, strconv.Itoa(status)).Inc()
		s.metrics.duration.WithLabelValues(method, route).Observe(elapsed.Seconds())

		level := slog.LevelInfo
		switch {
		case r.URL.Path == "/healthz":
			level = slog.LevelDebug
		case status >= 500:
			level = slog.LevelError
		}
		s.Logger.LogAttrs(r.Context(), level, "request",
			slog.String("method", r.Method),
			slog.String("path", logPath(r, route)),
			slog.String("route", route),
			slog.Int("status", status),
			slog.Int64("bytes", sw.size),
			slog.Duration("duration", elapsed),
			slog.String("ip", ip.String()),
			slog.String("user_agent", r.UserAgent()),
		)
	}()

	if s.rateLimited(sw, r, ip) {
		return
	}
	next(sw, r)
}

// logPath is the path to log for r. A management URL's path is its only
// credential, so for those (/manage/... and /api/manage/...) the route
// pattern is logged instead.
func logPath(r *http.Request, route string) string {
	if strings.Contains(route, "{secret}") || strings.Contains(r.URL.Path, "/manage/") {
		return route
	}
	return r.URL.Path
}

func knownMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions:
		return true
	}
	return false
}
