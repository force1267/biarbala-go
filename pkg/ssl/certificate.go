package ssl

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

// CertificateManager manages SSL certificates for domains
type CertificateManager struct {
	logger *logrus.Logger
	provider CertificateProvider
}

// CertificateProvider interface for different SSL certificate providers
type CertificateProvider interface {
	RequestCertificate(ctx context.Context, domain string) (*Certificate, error)
	RenewCertificate(ctx context.Context, domain string) (*Certificate, error)
	GetCertificate(ctx context.Context, domain string) (*Certificate, error)
	RevokeCertificate(ctx context.Context, domain string) error
}

// Certificate represents an SSL certificate
type Certificate struct {
	Domain      string    `json:"domain"`
	Certificate []byte    `json:"certificate"`
	PrivateKey  []byte    `json:"private_key"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Provider    string    `json:"provider"`
	Status      string    `json:"status"` // active, expired, revoked, pending
}

// NewCertificateManager creates a new certificate manager
func NewCertificateManager(logger *logrus.Logger, provider CertificateProvider) *CertificateManager {
	return &CertificateManager{
		logger:   logger,
		provider: provider,
	}
}

// RequestCertificate requests a new SSL certificate for a domain
func (cm *CertificateManager) RequestCertificate(ctx context.Context, domain string) (*Certificate, error) {
	cm.logger.WithField("domain", domain).Info("Requesting SSL certificate")

	cert, err := cm.provider.RequestCertificate(ctx, domain)
	if err != nil {
		cm.logger.WithError(err).WithField("domain", domain).Error("Failed to request SSL certificate")
		return nil, fmt.Errorf("failed to request SSL certificate: %w", err)
	}

	cm.logger.WithFields(logrus.Fields{
		"domain":     domain,
		"expires_at": cert.ExpiresAt,
		"provider":   cert.Provider,
	}).Info("SSL certificate requested successfully")

	return cert, nil
}

// RenewCertificate renews an existing SSL certificate
func (cm *CertificateManager) RenewCertificate(ctx context.Context, domain string) (*Certificate, error) {
	cm.logger.WithField("domain", domain).Info("Renewing SSL certificate")

	cert, err := cm.provider.RenewCertificate(ctx, domain)
	if err != nil {
		cm.logger.WithError(err).WithField("domain", domain).Error("Failed to renew SSL certificate")
		return nil, fmt.Errorf("failed to renew SSL certificate: %w", err)
	}

	cm.logger.WithFields(logrus.Fields{
		"domain":     domain,
		"expires_at": cert.ExpiresAt,
		"provider":   cert.Provider,
	}).Info("SSL certificate renewed successfully")

	return cert, nil
}

// GetCertificate retrieves an existing SSL certificate
func (cm *CertificateManager) GetCertificate(ctx context.Context, domain string) (*Certificate, error) {
	cert, err := cm.provider.GetCertificate(ctx, domain)
	if err != nil {
		cm.logger.WithError(err).WithField("domain", domain).Error("Failed to get SSL certificate")
		return nil, fmt.Errorf("failed to get SSL certificate: %w", err)
	}

	return cert, nil
}

// RevokeCertificate revokes an SSL certificate
func (cm *CertificateManager) RevokeCertificate(ctx context.Context, domain string) error {
	cm.logger.WithField("domain", domain).Info("Revoking SSL certificate")

	err := cm.provider.RevokeCertificate(ctx, domain)
	if err != nil {
		cm.logger.WithError(err).WithField("domain", domain).Error("Failed to revoke SSL certificate")
		return fmt.Errorf("failed to revoke SSL certificate: %w", err)
	}

	cm.logger.WithField("domain", domain).Info("SSL certificate revoked successfully")
	return nil
}

// IsCertificateValid checks if a certificate is valid and not expired
func (cm *CertificateManager) IsCertificateValid(cert *Certificate) bool {
	if cert == nil {
		return false
	}

	now := time.Now()
	return cert.Status == "active" && now.Before(cert.ExpiresAt)
}

// IsCertificateExpiringSoon checks if a certificate expires within the given duration
func (cm *CertificateManager) IsCertificateExpiringSoon(cert *Certificate, threshold time.Duration) bool {
	if cert == nil {
		return false
	}

	now := time.Now()
	expiryThreshold := now.Add(threshold)
	return cert.ExpiresAt.Before(expiryThreshold)
}

// GetTLSConfig creates a TLS configuration from a certificate
func (cm *CertificateManager) GetTLSConfig(cert *Certificate) (*tls.Config, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}

	tlsCert, err := tls.X509KeyPair(cert.Certificate, cert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	return config, nil
}
