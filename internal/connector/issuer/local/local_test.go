package local_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"os"
	"testing"

	"github.com/shankar0123/certctl/internal/connector/issuer"
	"github.com/shankar0123/certctl/internal/connector/issuer/local"
)

func TestLocalConnector(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	// Test 1: Create connector and validate config
	t.Run("ValidateConfig", func(t *testing.T) {
		config := &local.Config{
			CACommonName: "Test CA",
			ValidityDays: 30,
		}
		connector := local.New(config, logger)

		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}
	})

	// Test 2: Issue a certificate
	t.Run("IssueCertificate", func(t *testing.T) {
		config := &local.Config{
			CACommonName: "Test CA",
			ValidityDays: 30,
		}
		connector := local.New(config, logger)

		csr, csrPEM, err := generateTestCSR("test.example.com")
		if err != nil {
			t.Fatalf("Failed to generate CSR: %v", err)
		}

		req := issuer.IssuanceRequest{
			CommonName: csr.Subject.CommonName,
			SANs:       []string{"www.test.example.com"},
			CSRPEM:     csrPEM,
		}

		result, err := connector.IssueCertificate(ctx, req)
		if err != nil {
			t.Fatalf("IssueCertificate failed: %v", err)
		}

		if result.Serial == "" {
			t.Error("Serial is empty")
		}
		if result.CertPEM == "" {
			t.Error("CertPEM is empty")
		}
		if result.ChainPEM == "" {
			t.Error("ChainPEM is empty")
		}
		if result.OrderID == "" {
			t.Error("OrderID is empty")
		}
		if result.NotAfter.IsZero() {
			t.Error("NotAfter is zero")
		}

		t.Logf("Certificate issued: serial=%s, orderID=%s", result.Serial, result.OrderID)
	})

	// Test 3: Renew a certificate
	t.Run("RenewCertificate", func(t *testing.T) {
		config := &local.Config{
			CACommonName: "Test CA",
			ValidityDays: 30,
		}
		connector := local.New(config, logger)

		csr, csrPEM, err := generateTestCSR("test.example.com")
		if err != nil {
			t.Fatalf("Failed to generate CSR: %v", err)
		}

		renewReq := issuer.RenewalRequest{
			CommonName: csr.Subject.CommonName,
			SANs:       []string{"www.test.example.com"},
			CSRPEM:     csrPEM,
		}

		result, err := connector.RenewCertificate(ctx, renewReq)
		if err != nil {
			t.Fatalf("RenewCertificate failed: %v", err)
		}

		if result.Serial == "" {
			t.Error("Serial is empty")
		}

		t.Logf("Certificate renewed: serial=%s", result.Serial)
	})

	// Test 4: Get order status
	t.Run("GetOrderStatus", func(t *testing.T) {
		config := &local.Config{
			CACommonName: "Test CA",
			ValidityDays: 30,
		}
		connector := local.New(config, logger)

		status, err := connector.GetOrderStatus(ctx, "local-12345")
		if err != nil {
			t.Fatalf("GetOrderStatus failed: %v", err)
		}

		if status.Status != "completed" {
			t.Errorf("Expected status 'completed', got '%s'", status.Status)
		}

		t.Logf("Order status: %s", status.Status)
	})

	// Test 5: Revoke a certificate
	t.Run("RevokeCertificate", func(t *testing.T) {
		config := &local.Config{
			CACommonName: "Test CA",
			ValidityDays: 30,
		}
		connector := local.New(config, logger)

		revokeReq := issuer.RevocationRequest{
			Serial: "test-serial-12345",
		}

		err := connector.RevokeCertificate(ctx, revokeReq)
		if err != nil {
			t.Fatalf("RevokeCertificate failed: %v", err)
		}

		t.Logf("Certificate revoked: serial=%s", revokeReq.Serial)
	})

	// Test 6: Invalid CSR
	t.Run("InvalidCSR", func(t *testing.T) {
		config := &local.Config{
			CACommonName: "Test CA",
			ValidityDays: 30,
		}
		connector := local.New(config, logger)

		req := issuer.IssuanceRequest{
			CommonName: "test.example.com",
			CSRPEM:     "invalid pem",
		}

		_, err := connector.IssueCertificate(ctx, req)
		if err == nil {
			t.Fatal("Expected error for invalid CSR")
		}

		t.Logf("Correctly rejected invalid CSR: %v", err)
	})
}

func generateTestCSR(commonName string) (*x509.CertificateRequest, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", err
	}

	subj := pkix.Name{
		CommonName: commonName,
	}

	csrTemplate := x509.CertificateRequest{
		Subject:            subj,
		DNSNames:           []string{commonName},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, key)
	if err != nil {
		return nil, "", err
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, "", err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	return csr, string(csrPEM), nil
}
