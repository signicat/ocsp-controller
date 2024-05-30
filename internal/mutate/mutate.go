package mutate

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"golang.org/x/exp/slog"
	"io"
	"net/http"
	"ocsp-controller/internal/ocsp"
	"os"

	admissionv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/json"
)

func Mutate(r *http.Request) ([]byte, error) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if r.Method != http.MethodPost {
		return nil, fmt.Errorf("invalid request method")
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading request body %v", err)
	}

	admissionReview, err := parseAdmissionReview(body)
	if err != nil {
		return nil, fmt.Errorf("error parsing admission review %v", err)
	}

	if admissionReview.Request.Kind.Kind != "Secret" {
		logger.Info("Request for an object that is not a Secret. Handling Empty Admission Response.")
		return generateEmptyResponse(admissionReview)
	}
	return handleSecretMutation(admissionReview)
}

func handleSecretMutation(admissionReview *admissionv1.AdmissionReview) ([]byte, error) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	var secret v1.Secret
	err := json.Unmarshal(admissionReview.Request.Object.Raw, &secret)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling secret %v", err)
	}
	secretName := secret.Namespace + "/" + secret.Name

	inspectUpdateReason(admissionReview, secretName)

	isCertManagerSecret := false
	for label := range secret.Labels {
		if label == "controller.cert-manager.io/fao" {
			isCertManagerSecret = true
			break
		}
	}

	if !isCertManagerSecret {
		logger.Info(`Returning empty Admission Response. Secret is not associated with certificate managed by cert-manager.`, "secret", secretName)
		return generateEmptyResponse(admissionReview)
	}

	oldSecret, secErr := getOldSecret(admissionReview)
	if secErr != nil {
		logger.Info("error unmarshalling old secret object")

	}

	forceStaple := true
	if oldSecret != nil {
		forceStaple = shouldForceStaple(secret, *oldSecret)
	}
	if forceStaple {
		logger.Info("OCSP response should be force fetched")
	}

	ocspController := ocsp.NewOcspController()
	ocspResponse := ocspController.HandleSecretMutation(secret, forceStaple)
	if ocspResponse == nil {
		logger.Info(`Empty OCSP Response. Handling Empty Admission Response`, "secret", secretName)
		return generateEmptyResponse(admissionReview)
	}

	patchJSON, err := buildStapleUpdateRequest(&ocspResponse)
	if err != nil {
		return nil, fmt.Errorf("error building request to update secret %v", err)
	}
	logger.Info(`PATCH value for secret`, secretName, string(patchJSON))
	admissionReview.Response = generatedAdmissionResponse(admissionReview, patchJSON)

	responseBytes, err := json.Marshal(admissionReview)
	if err != nil {
		return nil, fmt.Errorf("error marshalling Secret %v", err)
	}
	return responseBytes, nil
}

func inspectUpdateReason(review *admissionv1.AdmissionReview, secretName string) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	request := review.Request

	switch request.Operation {
	case "CREATE":
		logger.Info(fmt.Sprintf("Webhook triggered by a CREATE operation for secret %s", secretName))
	case "UPDATE":
		logger.Info(fmt.Sprintf("Webhook triggered by a UPDATE operation %s", secretName))
	default:
		logger.Info(fmt.Sprintf("Webhook triggered by an unknown operation for secret %s", secretName))
	}
}

func getOldSecret(admissionReview *admissionv1.AdmissionReview) (*v1.Secret, error) {
	raw := admissionReview.Request.OldObject.Raw
	secret := &v1.Secret{}

	if err := json.Unmarshal(raw, secret); err != nil {
		return nil, err
	}

	return secret, nil
}

func shouldForceStaple(secret v1.Secret, oldSecret v1.Secret) bool {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	secretName := secret.Namespace + "/" + secret.Name
	logger.Info("Verifying if TLS or CA changed for a secret", "secret", secretName)

	tls := secret.Data[CERT_TLS]
	ca := secret.Data[CERT_CA]

	oldTls := oldSecret.Data[CERT_TLS]
	oldCa := oldSecret.Data[CERT_CA]

	certChanged := false
	if bytes.Equal(tls, oldTls) {
		logger.Info("Certificate TLS did not change", "secret", secretName)
	} else {
		logger.Info("Certificate TLS changed", "secret", secretName)
		certChanged = true
	}

	caChanged := false
	if bytes.Equal(ca, oldCa) {
		logger.Info("Certificate CA did not change", "secret", secretName)
	} else {
		logger.Info("Certificate CA changed", "secret", secretName)
		caChanged = true
	}

	return certChanged || caChanged
}

func parseAdmissionReview(body []byte) (*admissionv1.AdmissionReview, error) {
	var admissionReview admissionv1.AdmissionReview
	err := json.Unmarshal(body, &admissionReview)
	if err != nil {
		return nil, err
	}
	return &admissionReview, nil
}

type Staple struct {
	VALUE string `json:"value"`
}

type Operation struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value string `json:"value"`
}

func buildStapleUpdateRequest(ocspResponse *[]byte) ([]byte, error) {
	op := []Operation{
		{
			Op:    "add",
			Path:  "/data/tls.ocsp-staple",
			Value: base64.StdEncoding.EncodeToString(*ocspResponse),
		},
	}
	return json.Marshal(op)
}

func generateEmptyResponse(admissionReview *admissionv1.AdmissionReview) ([]byte, error) {
	response := &admissionv1.AdmissionResponse{
		UID:     admissionReview.Request.UID,
		Allowed: true,
	}
	admissionReview.Response = response
	responseBytes, err := json.Marshal(admissionReview)
	if err != nil {
		return nil, fmt.Errorf("error marshalling Secret %v", err)
	}
	return responseBytes, nil
}

func generatedAdmissionResponse(admissionReview *admissionv1.AdmissionReview, patchJSON []byte) *admissionv1.AdmissionResponse {
	patchType := admissionv1.PatchTypeJSONPatch
	return &admissionv1.AdmissionResponse{
		UID:       admissionReview.Request.UID,
		Allowed:   true,
		Patch:     patchJSON,
		PatchType: &patchType,
	}
}

const (
	CERT_TLS = "tls.crt"
	CERT_CA  = "ca.crt"
)
