package domain

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// DomainVerifier handles domain ownership verification using TXT records
type DomainVerifier struct {
	logger *logrus.Logger
}

// NewDomainVerifier creates a new domain verifier
func NewDomainVerifier(logger *logrus.Logger) *DomainVerifier {
	return &DomainVerifier{
		logger: logger,
	}
}

// VerificationChallenge represents a domain verification challenge
type VerificationChallenge struct {
	Domain    string    `json:"domain"`
	TXTRecord string    `json:"txt_record"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Verified  bool      `json:"verified"`
}

// CreateChallenge creates a new domain verification challenge
func (v *DomainVerifier) CreateChallenge(domain string) (*VerificationChallenge, error) {
	// Generate a unique TXT record value
	txtRecord := fmt.Sprintf("biarbala-verification-%d", time.Now().UnixNano())
	
	challenge := &VerificationChallenge{
		Domain:    domain,
		TXTRecord: txtRecord,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour), // Challenge expires in 24 hours
		Verified:  false,
	}

	v.logger.WithFields(logrus.Fields{
		"domain":      domain,
		"txt_record": txtRecord,
		"expires_at": challenge.ExpiresAt,
	}).Info("Created domain verification challenge")

	return challenge, nil
}

// VerifyChallenge verifies a domain ownership challenge
func (v *DomainVerifier) VerifyChallenge(ctx context.Context, challenge *VerificationChallenge) (bool, error) {
	if challenge.Verified {
		return true, nil
	}

	if time.Now().After(challenge.ExpiresAt) {
		return false, fmt.Errorf("verification challenge has expired")
	}

	// Check TXT record
	txtRecords, err := v.lookupTXT(ctx, challenge.Domain)
	if err != nil {
		v.logger.WithError(err).WithField("domain", challenge.Domain).Error("Failed to lookup TXT records")
		return false, fmt.Errorf("failed to lookup TXT records: %w", err)
	}

	// Check if our TXT record exists
	for _, record := range txtRecords {
		if strings.TrimSpace(record) == challenge.TXTRecord {
			challenge.Verified = true
			v.logger.WithFields(logrus.Fields{
				"domain":      challenge.Domain,
				"txt_record":  challenge.TXTRecord,
			}).Info("Domain verification successful")
			return true, nil
		}
	}

	v.logger.WithFields(logrus.Fields{
		"domain":      challenge.Domain,
		"txt_record":  challenge.TXTRecord,
		"found_records": txtRecords,
	}).Warn("Domain verification failed - TXT record not found")

	return false, fmt.Errorf("TXT record not found or does not match")
}

// lookupTXT performs a DNS TXT record lookup
func (v *DomainVerifier) lookupTXT(ctx context.Context, domain string) ([]string, error) {
	// Create a custom resolver with timeout
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 10 * time.Second,
			}
			return d.DialContext(ctx, network, address)
		},
	}

	// Lookup TXT records
	txtRecords, err := resolver.LookupTXT(ctx, domain)
	if err != nil {
		return nil, err
	}

	return txtRecords, nil
}

// GetVerificationInstructions returns human-readable instructions for domain verification
func (v *DomainVerifier) GetVerificationInstructions(challenge *VerificationChallenge) string {
	return fmt.Sprintf(`To verify ownership of %s, add the following TXT record to your domain's DNS settings:

TXT Record Name: %s
TXT Record Value: %s

After adding the record, wait a few minutes for DNS propagation, then call the verification endpoint.

Note: This challenge expires at %s`,
		challenge.Domain,
		challenge.Domain,
		challenge.TXTRecord,
		challenge.ExpiresAt.Format(time.RFC3339))
}
