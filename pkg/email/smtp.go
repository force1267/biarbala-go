package email

import (
	"fmt"
	"net/smtp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/force1267/biarbala-go/pkg/config"
)

// EmailService handles email sending functionality
type EmailService struct {
	config *config.EmailConfig
	logger *logrus.Logger
}

// EmailMessage represents an email message
type EmailMessage struct {
	To      []string
	Subject string
	Body    string
	HTML    string
}

// NewEmailService creates a new email service
func NewEmailService(cfg *config.EmailConfig, logger *logrus.Logger) *EmailService {
	return &EmailService{
		config: cfg,
		logger: logger,
	}
}

// SendEmail sends an email message
func (s *EmailService) SendEmail(msg *EmailMessage) error {
	if !s.config.Enabled {
		s.logger.Debug("Email service is disabled, skipping email send")
		return nil
	}

	// Validate message
	if len(msg.To) == 0 {
		return fmt.Errorf("no recipients specified")
	}

	if msg.Subject == "" {
		return fmt.Errorf("email subject is required")
	}

	if msg.Body == "" && msg.HTML == "" {
		return fmt.Errorf("email body or HTML content is required")
	}

	// Create email content
	content := s.buildEmailContent(msg)

	// Send email
	return s.sendSMTPEmail(msg.To, content)
}

// SendVerificationEmail sends an email verification email
func (s *EmailService) SendVerificationEmail(to, verificationCode string) error {
	subject := "Verify your Biarbala account"
	body := fmt.Sprintf(`
Hello!

Thank you for signing up for Biarbala. Please verify your email address by clicking the link below:

%s/verify-email?code=%s

This link will expire in 24 hours.

If you didn't create an account with Biarbala, please ignore this email.

Best regards,
The Biarbala Team
`, s.config.BaseURL, verificationCode)

	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Verify your Biarbala account</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #f8f9fa; padding: 20px; text-align: center; }
        .content { padding: 20px; }
        .button { display: inline-block; background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; margin: 20px 0; }
        .footer { background-color: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome to Biarbala!</h1>
        </div>
        <div class="content">
            <p>Hello!</p>
            <p>Thank you for signing up for Biarbala. Please verify your email address by clicking the button below:</p>
            <p style="text-align: center;">
                <a href="%s/verify-email?code=%s" class="button">Verify Email Address</a>
            </p>
            <p>This link will expire in 24 hours.</p>
            <p>If you didn't create an account with Biarbala, please ignore this email.</p>
        </div>
        <div class="footer">
            <p>Best regards,<br>The Biarbala Team</p>
        </div>
    </div>
</body>
</html>
`, s.config.BaseURL, verificationCode)

	msg := &EmailMessage{
		To:      []string{to},
		Subject: subject,
		Body:    body,
		HTML:    html,
	}

	return s.SendEmail(msg)
}

// SendOTPEmail sends an OTP verification email
func (s *EmailService) SendOTPEmail(to, otpCode string) error {
	subject := "Your Biarbala verification code"
	body := fmt.Sprintf(`
Hello!

Your verification code for Biarbala is: %s

This code will expire in 10 minutes.

If you didn't request this code, please ignore this email.

Best regards,
The Biarbala Team
`, otpCode)

	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Your Biarbala verification code</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #f8f9fa; padding: 20px; text-align: center; }
        .content { padding: 20px; }
        .otp-code { font-size: 32px; font-weight: bold; color: #007bff; text-align: center; padding: 20px; background-color: #f8f9fa; border-radius: 8px; margin: 20px 0; }
        .footer { background-color: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Verification Code</h1>
        </div>
        <div class="content">
            <p>Hello!</p>
            <p>Your verification code for Biarbala is:</p>
            <div class="otp-code">%s</div>
            <p>This code will expire in 10 minutes.</p>
            <p>If you didn't request this code, please ignore this email.</p>
        </div>
        <div class="footer">
            <p>Best regards,<br>The Biarbala Team</p>
        </div>
    </div>
</body>
</html>
`, otpCode)

	msg := &EmailMessage{
		To:      []string{to},
		Subject: subject,
		Body:    body,
		HTML:    html,
	}

	return s.SendEmail(msg)
}

// SendPasswordResetEmail sends a password reset email
func (s *EmailService) SendPasswordResetEmail(to, resetCode string) error {
	subject := "Reset your Biarbala password"
	body := fmt.Sprintf(`
Hello!

You requested to reset your password for Biarbala. Click the link below to reset your password:

%s/reset-password?code=%s

This link will expire in 1 hour.

If you didn't request a password reset, please ignore this email.

Best regards,
The Biarbala Team
`, s.config.BaseURL, resetCode)

	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Reset your Biarbala password</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #f8f9fa; padding: 20px; text-align: center; }
        .content { padding: 20px; }
        .button { display: inline-block; background-color: #dc3545; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; margin: 20px 0; }
        .footer { background-color: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Password Reset Request</h1>
        </div>
        <div class="content">
            <p>Hello!</p>
            <p>You requested to reset your password for Biarbala. Click the button below to reset your password:</p>
            <p style="text-align: center;">
                <a href="%s/reset-password?code=%s" class="button">Reset Password</a>
            </p>
            <p>This link will expire in 1 hour.</p>
            <p>If you didn't request a password reset, please ignore this email.</p>
        </div>
        <div class="footer">
            <p>Best regards,<br>The Biarbala Team</p>
        </div>
    </div>
</body>
</html>
`, s.config.BaseURL, resetCode)

	msg := &EmailMessage{
		To:      []string{to},
		Subject: subject,
		Body:    body,
		HTML:    html,
	}

	return s.SendEmail(msg)
}

// buildEmailContent builds the email content with headers
func (s *EmailService) buildEmailContent(msg *EmailMessage) string {
	var content strings.Builder

	// Email headers
	content.WriteString(fmt.Sprintf("From: %s <%s>\r\n", s.config.FromName, s.config.FromEmail))
	content.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(msg.To, ", ")))
	content.WriteString(fmt.Sprintf("Subject: %s\r\n", msg.Subject))
	content.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))
	content.WriteString("MIME-Version: 1.0\r\n")

	if msg.HTML != "" {
		// Multipart email with both text and HTML
		boundary := "boundary123456789"
		content.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n", boundary))
		content.WriteString("\r\n")

		// Text part
		content.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		content.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		content.WriteString("\r\n")
		content.WriteString(msg.Body)
		content.WriteString("\r\n")

		// HTML part
		content.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		content.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
		content.WriteString("\r\n")
		content.WriteString(msg.HTML)
		content.WriteString("\r\n")

		content.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	} else {
		// Plain text email
		content.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		content.WriteString("\r\n")
		content.WriteString(msg.Body)
	}

	return content.String()
}

// sendSMTPEmail sends email via SMTP
func (s *EmailService) sendSMTPEmail(to []string, content string) error {
	// Create SMTP client
	var client *smtp.Client
	var err error

	// Use standard SMTP connection
	client, err = smtp.Dial(s.config.SMTPHost)

	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer client.Quit()

	// Authenticate if credentials are provided
	if s.config.SMTPUsername != "" && s.config.SMTPPassword != "" {
		auth := smtp.PlainAuth("", s.config.SMTPUsername, s.config.SMTPPassword, s.config.SMTPHost)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("failed to authenticate with SMTP server: %w", err)
		}
	}

	// Set sender
	if err := client.Mail(s.config.FromEmail); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}

	// Set recipients
	for _, recipient := range to {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("failed to set recipient %s: %w", recipient, err)
		}
	}

	// Send email content
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to get data writer: %w", err)
	}

	if _, err := writer.Write([]byte(content)); err != nil {
		return fmt.Errorf("failed to write email content: %w", err)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to close data writer: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"to":      to,
		"subject": content[:50] + "...",
	}).Info("Email sent successfully")

	return nil
}

// Health checks if the email service is healthy
func (s *EmailService) Health() error {
	if !s.config.Enabled {
		return nil
	}

	// Try to connect to SMTP server
	var client *smtp.Client
	var err error

	// Use standard SMTP connection
	client, err = smtp.Dial(s.config.SMTPHost)

	if err != nil {
		return fmt.Errorf("email service health check failed: %w", err)
	}

	client.Quit()
	return nil
}
