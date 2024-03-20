package mutate

import (
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

	ocspController := ocsp.NewOcspController()
	ocspResponse := ocspController.HandleSecretMutation(secret)
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
