package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func setupClient() (clienset *kubernetes.Clientset) {
	_, outsideCluster := os.LookupEnv("OUTSIDE_CLUSTER")

	var config *rest.Config

	if outsideCluster {
		log.Println("Running outside of cluster.")
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatal("Can't get current user home directory", err)
		}
		kubeconfig := filepath.Join(home, ".kube", "config")
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			log.Fatal("Can't build kubeconfig", err)
		}
	} else {
		log.Println("Running in cluster.")
		var err error
		config, err = rest.InClusterConfig()
		if err != nil {
			log.Fatal(err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal(err)
	}

	return clientset
}

func getSecrets(client *kubernetes.Clientset, namespace string) *v1.SecretList {
	secrets, err := client.CoreV1().Secrets(namespace).List(context.Background(), metav1.ListOptions{FieldSelector: "type=kubernetes.io/tls"})
	if err != nil {
		log.Fatal(err)
	}
	return secrets
}

func updateSecret(client *kubernetes.Clientset, namespace string, s *v1.Secret, ocspResponse *[]byte) (*v1.Secret, error) {
	s.Data["ocsp-response.der"] = *ocspResponse
	return client.CoreV1().Secrets(namespace).Update(context.Background(), s, metav1.UpdateOptions{})
}

func getCertificateAndChain(s *v1.Secret) (*x509.Certificate, []*x509.Certificate) {
	var cert *x509.Certificate
	var chain []*x509.Certificate
	var certDERs, caDERs []*pem.Block

	if certPEM, ok := s.Data["tls.crt"]; ok {
		certDERs = convertPEMsToDERs(certPEM)

		if len(certDERs) < 1 {
			log.Printf("Secret %s has empty tls.crt", s.Name)
		} else {
			var certs []*x509.Certificate = make([]*x509.Certificate, len(certDERs))
			var err error
			for i := range certDERs {
				certType := certDERs[i].Type
				if certType == "CERTIFICATE" {
					certs[i], err = x509.ParseCertificate(certDERs[i].Bytes)
					if err != nil {
						log.Println(err)
					}
				} else {
					log.Printf("Secret %s tls.crt[%d] expected CERTIFICATE actual type: %s\n", s.Name, i, certType)
				}
			}
			cert = certs[0]
			chain = certs[1:]
		}
	} else {
		log.Printf("Can't find tls.crt in secret %s\n", s.Name)
	}

	if caPEM, ok := s.Data["ca.crt"]; ok {
		caDERs = convertPEMsToDERs(caPEM)

		var certs []*x509.Certificate = make([]*x509.Certificate, len(caDERs))
		var err error

		for i := range caDERs {
			caType := caDERs[i].Type
			if caType == "CERTIFICATE" {
				certs[i], err = x509.ParseCertificate(caDERs[i].Bytes)
				if err != nil {
					log.Println(err)
				}
			} else {
				log.Printf("Secret %s ca.crt[%d] expected CERTIFICATE actual type: %s\n", s.Name, i, caType)
			}
		}
	} else {
		log.Printf("Can't find ca.crt in secret %s\n", s.Name)
	}

	return cert, chain
}

func getSecretDataKeys(s *v1.Secret) *[]string {
	keys := make([]string, len(s.Data))

	i := 0
	for k := range s.Data {
		keys[i] = k
		i++
	}

	return &keys
}

func convertPEMsToDERs(pems []byte) []*pem.Block {
	ders := []*pem.Block{}
	block, rest := pem.Decode(pems)

	for block != nil {
		ders = append(ders, block)
		block, rest = pem.Decode(rest)
	}

	return ders
}

func viewCertificate(s *v1.Secret) {
	keys := getSecretDataKeys(s)
	certName := (*keys)[0]
	cert := s.Data[certName]
	ders := convertPEMsToDERs(cert)
	certificates, err := x509.ParseCertificates(ders[0].Bytes)
	if err != nil {
		log.Printf("Failed to parse certificate. $s\n", err)

	}
	for _, c := range certificates {
		printCertificate(c)
	}
}

func printCertificate(c *x509.Certificate) {
	log.Printf("AuthorityKeyId: %s\n", string(c.AuthorityKeyId))
	log.Printf("Issuer: %s\n", c.Issuer)
	log.Printf("NotAfter: %s\n", c.NotAfter)
	log.Printf("NotBefore: %s\n", c.NotBefore)
	log.Printf("PublicKeyAlgorithm: %s\n", c.PublicKeyAlgorithm)
	log.Printf("SerialNumber: %s\n", c.SerialNumber)
	log.Printf("Signature: %s\n", c.Signature)
	log.Printf("SignatureAlgorithm: %s\n", c.SignatureAlgorithm)
	log.Printf("Subject: %s\n", c.Subject)
	log.Printf("SubjectKeyId: %s\n", c.SubjectKeyId)
	log.Printf("CRLDistributionPoints: %s\n", c.CRLDistributionPoints)
	log.Printf("DNSNames: %s\n", c.DNSNames)
	log.Printf("EmailAddresses: %s\n", c.EmailAddresses)
	log.Printf("ExcludedDNSDomains: %s\n", c.ExcludedDNSDomains)
	log.Printf("ExcludedEmailAddresses: %s\n", c.ExcludedEmailAddresses)
	log.Printf("ExcludedIPRanges: %s\n", c.ExcludedIPRanges)
	log.Printf("ExcludedURIDomains: %s\n", c.ExcludedURIDomains)
	log.Printf("IPAddresses: %s\n", c.IPAddresses)
	log.Printf("Issuer.CommonName: %s\n", c.Issuer.CommonName)
	log.Printf("Issuer.SerialNumber: %s\n", c.Issuer.SerialNumber)
	log.Printf("IssuingCertificateURL: %s\n", c.IssuingCertificateURL)
	log.Printf("OCSPServer: %s\n", c.OCSPServer)
	log.Printf("PermittedDNSDomains: %s\n", c.PermittedDNSDomains)
	log.Printf("PermittedEmailAddresses: %s\n", c.PermittedEmailAddresses)
	log.Printf("PermittedIPRanges: %s\n", c.PermittedIPRanges)
	log.Printf("PermittedURIDomains: %s\n", c.PermittedURIDomains)
	log.Printf("PolicyIdentifiers: %s\n", c.PolicyIdentifiers)
	log.Printf("Subject.SerialNumber: %s\n", c.Subject.SerialNumber)
	log.Printf("URIs: %s\n", c.URIs)
	log.Printf("UnhandledCriticalExtensions: %s\n", c.UnhandledCriticalExtensions)
	log.Printf("UnknownExtKeyUsage: %s\n", c.UnknownExtKeyUsage)
	log.Printf("BasicConstraintsValid: %t\n", c.BasicConstraintsValid)
	log.Printf("IsCA: %t\n", c.IsCA)
	log.Printf("Version: %d\n", c.Version)
}

func getCertificates(pem []byte) ([]*x509.Certificate, []error) {
	ders := convertPEMsToDERs(pem)

	var certs []*x509.Certificate = make([]*x509.Certificate, len(ders))
	var errs []error = make([]error, len(ders))

	for i, d := range ders {
		cert, err := x509.ParseCertificate(d.Bytes)
		certs[i] = cert
		errs[i] = err
	}

	return certs, errs
}

func getOCSPResponse(c *x509.Certificate, i *x509.Certificate) (bool, *ocsp.Response) {
	if len(c.OCSPServer) < 1 {
		log.Printf("Certificate with Serial Number: %s is missing OCSP Server", c.SerialNumber)
		return false, nil
	}
	ocspServer := c.OCSPServer[0] // TODO: on failure retry on other URLs

	payload, err := ocsp.CreateRequest(c, i, &ocsp.RequestOptions{Hash: crypto.SHA1})
	if err != nil {
		log.Println(err)
		return false, nil
	}

	httpRequest, _ := http.NewRequest(http.MethodPost, ocspServer, bytes.NewBuffer(payload))
	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpRequest.Header.Add("host", ocspServer)
	httpClient := &http.Client{}
	httpResponse, err := httpClient.Do(httpRequest) // TODO: on failure retry with different hash algorithm and header combo
	if err != nil {
		log.Println(err)
		return false, nil
	}
	defer httpResponse.Body.Close()

	output, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		log.Println(err)
		return false, nil
	}

	ocspResponse, err := ocsp.ParseResponse(output, i)
	if err != nil {
		log.Println(err)
		return false, nil
	}

	return true, ocspResponse
}

func logErrors(err []error) {
	for _, e := range err {
		log.Println(e)
	}
}

func main() {
	client := setupClient()
	secrets := getSecrets(client, "istio-system")

	for _, s := range secrets.Items {
		log.Printf("---- %s ----", s.Name)

		var certs []*x509.Certificate
		var chain []*x509.Certificate
		var err []error

		if tls, ok := s.Data["tls.crt"]; ok {
			certs, err = getCertificates(tls)
			if err != nil {
				log.Printf("Error while fetching tls.crt from secret %s.\n", s.Name)
				logErrors(err)
			}
		} else {
			log.Printf("Secret %s is missing tls.crt file.\n", s.Name)
			continue
		}

		// Helper OCSP RFCs prohibit submiting queries for certificates
		// - expired or not valid yet
		// - issued by untrusted CA
		cert := certs[0]
		now := time.Now()
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			log.Printf("Certificate %s expired or not valid yet. Verified on %s.\n.", s.Name, now.String())
			continue
		}

		if ca, ok := s.Data["ca.crt"]; ok {
			chain, err = getCertificates(ca)
			if err == nil {
				log.Printf("ca.crt has %d certs, tls.crt has %d certs", len(certs), len(chain))
			} else {
				log.Printf("Error while fetching ca.crt from secret %s.\n", s.Name)
				logErrors(err)
			}
		} else {
			chain = certs[1:]
		}
		
		ok, ocspResponse := getOCSPResponse(certs[0], chain[0])
		if ok {
			log.Printf("Cert in %s has OCSP.Status=%d. Next update: %s.\n", s.Name, ocspResponse.Status, ocspResponse.NextUpdate)
		} else {
			log.Printf("Failed to verify secret %s.\n", s.Name)
			continue
		}

		_, dryRun := os.LookupEnv("DRY_RUN")
		if !dryRun {
			log.Printf("Updating secret %s with ocsp-response.der.\n", s.Name)
			updateSecret(client, "istio-system", &s, &ocspResponse.Raw)
		}
	}
}
