package routes

import (
	"fmt"
	"golang.org/x/exp/slog"
	"log"
	"net/http"
	m "ocsp-controller/internal/mutate"
	"os"

	"ocsp-controller/internal/ocsp"
)

func NewRouter() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/ocsp-check", handleOcsp)
	mux.HandleFunc("/mutate", handleMutation)

	return mux
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	_, _ = fmt.Println("ocsp-controller root handler")
	w.Header().Set("Content-Type", "application/json-patch+json")
	w.WriteHeader(http.StatusOK)
}

func handleOcsp(w http.ResponseWriter, r *http.Request) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	logger.Info("Started OCSP check")
	errors := ocsp.NewOcspController().HandleOcspJob()
	if len(errors) == 0 {
		logger.Error("ocsp check failed", "error", errors)
	} else {
		logger.Info("ocsp check finished successfully")
	}
}

func handleMutation(w http.ResponseWriter, r *http.Request) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	logger.Debug("routes.go: Called MUTATE webhook")

	mutated, err := m.Mutate(r)
	if err != nil {
		log.Printf("Something went wrong %v", err)
		sendError(err, w)
		return
	}

	w.Header().Set("Content-Type", "application/json-patch+json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(mutated)
	if err != nil {
		logger.Error(`Something went wrong`, "error", err)
		return
	}
	logger.Info("Secret mutated successfully")
}

func sendError(err error, w http.ResponseWriter) {
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = fmt.Fprintf(w, "%s", err)
}
