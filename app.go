package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/robfig/cron/v3"
	"golang.org/x/exp/slog"
	"net/http"
	"ocsp-controller/internal/ocsp"
	"ocsp-controller/internal/routes"
	"os"
	"time"
)

const (
	address      = ":8443"
	readTimeout  = 10 * time.Second
	writeTimeout = 10 * time.Second
	caPath       = "/etc/ocsp-manager/ca.crt"
	certPath     = "/etc/ocsp-manager/tls.crt"
	keyPath      = "/etc/ocsp-manager/tls.key"
)

type AppConfig struct {
	CaPath   string `json:"caPath"`
	CertPath string `json:"certPath"`
	KeyPath  string `json:"keyPath"`
}

func loadConfigFromEnv() *AppConfig {
	return &AppConfig{
		CaPath:   getEnv("CA_PATH", caPath),
		CertPath: getEnv("CERT_PATH", certPath),
		KeyPath:  getEnv("KEY_PATH", keyPath),
	}
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func handleOcspJob() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	logger.Info("Started OCSP check")
	err := ocsp.NewOcspController().HandleOcspJob()
	if len(err) == 0 {
		logger.Error("ocsp check failed", "error", err)
	} else {
		logger.Info("ocsp check finished successfully")
	}
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	displayBanner(logger)
	mux := routes.NewRouter()
	config := loadConfigFromEnv()

	c := cron.New()
	_, err2 := c.AddFunc(CRON_EXPRESSION, handleOcspJob)
	if err2 != nil {
		logger.Error("Error configuring cron Job")
	}
	c.Start()

	tlsConfig, err := createTLSConfig(config.CaPath, config.CertPath, config.KeyPath)
	if err != nil {
		logger.Error("Error loading TLS config", "error", err)
	}
	logger.Info("TLS config loaded successfully")

	httpsServer := &http.Server{
		Addr:           address,
		Handler:        mux,
		ReadTimeout:    readTimeout,
		WriteTimeout:   writeTimeout,
		MaxHeaderBytes: 1 << 20, // 1048576
		TLSConfig:      tlsConfig,
	}

	if err := httpsServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("Error starting HTTPS server", "error", err)
		c.Stop()
	}
}

func createTLSConfig(caCertPath, tlsCertPath, tlsKeyPath string) (*tls.Config, error) {
	// Read the CA certificate, TLS certificate, and private key files
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("error reading CA certificate file: %v", err)
	}

	tlsCert, err := os.ReadFile(tlsCertPath)
	if err != nil {
		return nil, fmt.Errorf("error reading TLS certificate file: %v", err)
	}

	tlsKey, err := os.ReadFile(tlsKeyPath)
	if err != nil {
		return nil, fmt.Errorf("error reading TLS private key file: %v", err)
	}

	// Create a TLS configuration with the loaded certificates and key
	tlsConfig := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		InsecureSkipVerify: false, // Set to true if you want to skip certificate verification
	}

	// Append the CA certificate to the TLS configuration
	if ok := tlsConfig.RootCAs.AppendCertsFromPEM(caCert); !ok {
		return nil, fmt.Errorf("error appending CA certificate to the TLS configuration")
	}

	// Create a certificate and private key pair
	cert, err := tls.X509KeyPair(tlsCert, tlsKey)
	if err != nil {
		return nil, fmt.Errorf("error creating X509 key pair: %v", err)
	}

	// Add the certificate and private key to the TLS configuration
	tlsConfig.Certificates = []tls.Certificate{cert}

	return tlsConfig, nil
}

const (
	CRON_EXPRESSION = "*/5 * * * *"
)
