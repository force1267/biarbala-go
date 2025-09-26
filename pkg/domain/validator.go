package domain

import (
	"fmt"
	"regexp"
	"strings"

	petname "github.com/dustinkirkland/golang-petname"
)

const (
	MainDomain = "biarbala.ir"
	MinLength  = 6
)

// SubdomainValidator validates subdomain names according to Biarbala rules
type SubdomainValidator struct{}

// NewSubdomainValidator creates a new subdomain validator
func NewSubdomainValidator() *SubdomainValidator {
	return &SubdomainValidator{}
}

// ValidateSubdomain validates a subdomain name according to Biarbala rules
func (v *SubdomainValidator) ValidateSubdomain(subdomain string) error {
	if subdomain == "" {
		return fmt.Errorf("subdomain cannot be empty")
	}

	// Check minimum length
	if len(subdomain) < MinLength {
		return fmt.Errorf("subdomain must be at least %d characters long", MinLength)
	}

	// Check for valid characters (only digits, alphabet, and dash)
	validCharsRegex := regexp.MustCompile(`^[a-zA-Z0-9-]+$`)
	if !validCharsRegex.MatchString(subdomain) {
		return fmt.Errorf("subdomain can only contain letters, numbers, and dashes")
	}

	// Check for at least one dash
	if !strings.Contains(subdomain, "-") {
		return fmt.Errorf("subdomain must contain at least one dash")
	}

	// Check that dash is not at the beginning or end
	if strings.HasPrefix(subdomain, "-") || strings.HasSuffix(subdomain, "-") {
		return fmt.Errorf("subdomain cannot start or end with a dash")
	}

	// Check for consecutive dashes
	if strings.Contains(subdomain, "--") {
		return fmt.Errorf("subdomain cannot contain consecutive dashes")
	}

	return nil
}

// ValidateCustomDomain validates a custom domain name
func (v *SubdomainValidator) ValidateCustomDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}

	// Check that it's not our main domain
	if domain == MainDomain {
		return fmt.Errorf("cannot use main domain as custom domain")
	}

	// Check that it's not a subdomain of our main domain
	if strings.HasSuffix(domain, "."+MainDomain) {
		return fmt.Errorf("cannot use subdomain of main domain as custom domain")
	}

	return nil
}

// GenerateSubdomain generates a meaningful subdomain name using petname library
func (v *SubdomainValidator) GenerateSubdomain() string {
	// Generate a three-part pet name in format: adverb-adjective-animal
	// Using petname library with 3 words and dash separator
	// Ensure the generated name meets our minimum length requirement
	petName := ""
	for len(petName) < MinLength {
		petName = petname.Generate(3, "-")
	}

	return petName
}

// IsSubdomainOfMainDomain checks if a domain is a subdomain of our main domain
func (v *SubdomainValidator) IsSubdomainOfMainDomain(domain string) bool {
	return strings.HasSuffix(domain, "."+MainDomain)
}

// ExtractSubdomainFromDomain extracts the subdomain part from a full domain
func (v *SubdomainValidator) ExtractSubdomainFromDomain(domain string) string {
	if v.IsSubdomainOfMainDomain(domain) {
		subdomain := strings.TrimSuffix(domain, "."+MainDomain)
		return subdomain
	}
	return ""
}
