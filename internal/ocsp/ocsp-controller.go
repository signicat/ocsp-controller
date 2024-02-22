package ocsp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ocsp"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func setupClient() *kubernetes.Clientset {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	_, outsideCluster := os.LookupEnv("OUTSIDE_CLUSTER")

	var config *rest.Config

	if outsideCluster {
		logger.Info("Running outside of cluster.")
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("Can't get current user home directory, %v", err)
		}
		kubeConfig := filepath.Join(home, ".kube", "config")
		config, err = clientcmd.BuildConfigFromFlags("", kubeConfig)
		if err != nil {
			log.Fatalf("Can't build kubeConfig %v", err)
		}
	} else {
		logger.Info("Running in cluster.")
		var err error
		config, err = rest.InClusterConfig()
		if err != nil {
			log.Fatal(err)
		}
	}

	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal(err)
	}

	return clientSet
}

func getSecrets(client *kubernetes.Clientset, namespace string) *v1.SecretList {
	listOptions := metav1.ListOptions{FieldSelector: "type=kubernetes.io/tls"}
	secrets, err := client.CoreV1().Secrets(namespace).List(context.Background(), listOptions)
	if err != nil {
		log.Fatal(err)
	}
	return secrets
}

func updateSecret(client *kubernetes.Clientset, namespace string, s *v1.Secret, ocspResponse *[]byte) (*v1.Secret, error) {
	s.Data[OCSP_STAPLE_KEY] = *ocspResponse
	return client.CoreV1().Secrets(namespace).Update(context.Background(), s, metav1.UpdateOptions{})
}

func convertPEMsToDERs(pems []byte) []*pem.Block {
	var ders []*pem.Block
	block, rest := pem.Decode(pems)

	for block != nil {
		ders = append(ders, block)
		block, rest = pem.Decode(rest)
	}

	return ders
}

func getCertificates(pem []byte) ([]*x509.Certificate, []error) {
	ders := convertPEMsToDERs(pem)

	var certs = make([]*x509.Certificate, len(ders))
	var errs = make([]error, len(ders))

	for i, d := range ders {
		cert, err := x509.ParseCertificate(d.Bytes)
		certs[i] = cert
		errs[i] = err
	}

	return certs, errs
}

func getOCSPResponse(c *x509.Certificate, i *x509.Certificate) (bool, *ocsp.Response) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	logger.Info(fmt.Sprintf(`Handling OCSP Response for certificate %v`, c.SerialNumber))
	if len(c.OCSPServer) < 1 {
		logger.Info(fmt.Sprintf("Certificate with Serial Number: %s is missing OCSP Server", c.SerialNumber))
		return false, nil
	}
	ocspServer := c.OCSPServer[0] // TODO: on failure retry on other URLs

	payload, err := ocsp.CreateRequest(c, i, &ocsp.RequestOptions{Hash: crypto.SHA1})
	if err != nil {
		logger.Error("failed to create ocsp request", "error", err.Error())
		return false, nil
	}

	httpRequest, _ := http.NewRequest(http.MethodPost, ocspServer, bytes.NewBuffer(payload))

	ocspUrl, err := url.Parse(ocspServer)
	if err != nil {
		logger.Error("failed parsing ocsp url", "error", err.Error())
		return false, nil
	}

	httpRequest.Header.Add(contentType, ocspRequestType)
	httpRequest.Header.Add(accept, ocspResponseType)
	httpRequest.Header.Add(host, ocspUrl.Host)
	httpClient := &http.Client{}
	httpResponse, err := httpClient.Do(httpRequest) // TODO: on failure retry with different hash algorithm and header combo
	if err != nil {
		message := fmt.Sprintf("failed to get ocsp request from %s", ocspServer)
		logger.Error(message, "error", err.Error())
		return false, nil
	}
	defer httpResponse.Body.Close()

	output, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		logger.Error(err.Error())
		return false, nil
	}

	ocspResponse, err := ocsp.ParseResponse(output, i)
	if err != nil {
		logger.Info(`OCSP Response Parsing Error`)
		logger.Error(err.Error())
		return false, nil
	}

	logger.Info(fmt.Sprintf(`OCSP response status %v`, ocspResponse.Status))

	return true, ocspResponse
}

func logErrors(err []error, logger *slog.Logger) {
	for _, e := range err {
		if e != nil {
			logger.Error(e.Error())
		}
	}
}

type OcspController struct {
	logger *slog.Logger
}

func NewOcspController() *OcspController {
	return &OcspController{
		logger: slog.New(slog.NewJSONHandler(os.Stdout, nil)),
	}
}

func (c *OcspController) HandleOcspJob() []error {
	client := setupClient()
	secrets := getSecrets(client, ISTIO_NAMESPACE)
	var errors []error
	for _, s := range secrets.Items {
		ocspResponse := c.HandleSecretMutation(s)
		if ocspResponse == nil {
			c.logger.Error(fmt.Sprintf(`ocsp response for secret %v not available`, s.Name))
			errors = append(errors, fmt.Errorf(`ocsp response for secret %v not available`, s.Name))
			continue
		}
		secret, err := updateSecret(client, ISTIO_NAMESPACE, &s, &ocspResponse)
		if err != nil {
			c.logger.Error(fmt.Sprintf(`secret %v mutation failed`, s.Name))
			errors = append(errors, fmt.Errorf(`secret %v mutated unsuccessfully %v`, s.Name, err))
			continue
		}
		c.logger.Info(fmt.Sprintf(`Secret %v mutated successfully`, secret.Name))
	}
	return errors
}

func allNil(arr []error) bool {
	for _, element := range arr {
		if element != nil {
			return false // Found a non-nil value
		}
	}
	return true // All elements are nil
}

func (c *OcspController) HandleSecretMutation(s v1.Secret) []byte {
	secretName := s.Namespace + "/" + s.Name
	c.logger.Info(fmt.Sprintf(`Handling mutation for certificate: %v`, secretName))

	certs, err := c.handleCertificateTlsFromSecret(&s)
	if err != nil {
		c.logger.Error(`Error while getting certs`, "error", err)
		return nil
	}

	cert := certs[0]
	now := time.Now()
	if cert != nil {
		c.logger.Info(fmt.Sprintf(`Certificate %v with serial number: %v`, secretName, cert.SerialNumber))
	}

	chain, err := c.handleChain(&s, certs)
	if err != nil {
		c.logger.Error(`Error while getting chain`, "error", err)
		return nil
	}

	if c.validateStaple(&s, chain[0], now) {
		return nil
	}

	if ok, ocspResponse := getOCSPResponse(certs[0], chain[0]); ok {
		c.logger.Info(fmt.Sprintf("Cert in secred %s has OCSP.Status=%d. Next update: %s.\n", s.Name, ocspResponse.Status, ocspResponse.NextUpdate))
		return ocspResponse.Raw
	} else {
		c.logger.Info(fmt.Sprintf("Failed to verify secret %s. OCSP response not fetched", s.Name))
		return nil
	}
}

func (c *OcspController) handleChain(s *v1.Secret, certs []*x509.Certificate) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	if ca, ok := s.Data[CERT_CA]; ok {
		chain, err := getCertificates(ca)
		c.logger.Info(`Certificate chain: %v`, len(chain))
		if err == nil {
			c.logger.Info(fmt.Sprintf("ca.crt has %d certs, tls.crt has %d certs", len(certs), len(chain)))
		} else {
			c.logger.Error("Error while fetching ca.crt from secret.", "secret", s.Name)
			logErrors(err, c.logger)
			return nil, fmt.Errorf("error while fetching ca.crt from secret %s.\n", s.Name)
		}
	} else {
		chain = certs[1:]
		c.logger.Info(fmt.Sprintf("ca.crt has %d certs, tls.crt has %d certs", len(certs), len(chain)))
	}
	return chain, nil
}

func (c *OcspController) validateStaple(s *v1.Secret, issuer *x509.Certificate, now time.Time) bool {
	if staple, ok := s.Data[OCSP_STAPLE_KEY]; ok {
		stapleRes, stapleError := ocsp.ParseResponse(staple, issuer)
		if stapleError != nil {
			c.logger.Error(`Staple reading error: %v`, stapleError)
			return false
		} else {
			c.logger.Info(fmt.Sprintf(`OCSP response with serialNumber %s`, stapleRes.SerialNumber))
			if now.Before(stapleRes.ThisUpdate.Add(time.Hour * 24 * 4)) {
				c.logger.Info(`OCSP Staple considered FRESH`)
				return true
			} else {
				c.logger.Info(`OCSP Staple considered STALE`)
				return false
			}
		}
	} else {
		c.logger.Info(`Secret does not contain staple key`, "secret", s.Name)
		return false
	}
}

func (c *OcspController) handleCertificateTlsFromSecret(s *v1.Secret) ([]*x509.Certificate, error) {
	if tls, ok := s.Data[CERT_TLS]; ok {
		certs, err := getCertificates(tls)
		if !allNil(err) {
			logErrors(err, c.logger)
			return nil, fmt.Errorf("error while fetching %s from secret %s.\n", CERT_TLS, s.Name)
		}
		return certs, nil
	} else {
		return nil, fmt.Errorf("secret %s is missing tls.crt file.\n", s.Name)
	}
}

const (
	ISTIO_NAMESPACE  = "istio-system"
	CERT_TLS         = "tls.crt"
	CERT_CA          = "ca.crt"
	DRY_RUN          = "DRY_RUN"
	OCSP_STAPLE_KEY  = "tls.oscp-staple"
	contentType      = "Content-Type"
	ocspRequestType  = "application/ocsp-request"
	ocspResponseType = "application/ocsp-response"
	accept           = "Accept"
	host             = "host"
)
