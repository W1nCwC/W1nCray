package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// acmeUser implements registration.User and is persisted per email.
type acmeUser struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.Email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

func (m *Manager) accountDir(email string) string {
	name := unsafeChars.ReplaceAllString(email, "_")
	if name == "" {
		name = "default"
	}
	return filepath.Join(m.Dir, "accounts", name)
}

// loadUser loads or creates the ACME account of email.
func (m *Manager) loadUser(email string) (*acmeUser, error) {
	dir := m.accountDir(email)
	keyPath := filepath.Join(dir, "account.key")
	regPath := filepath.Join(dir, "account.json")

	u := &acmeUser{Email: email}
	if b, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, errors.New("invalid ACME account key")
		}
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse ACME account key: %w", err)
		}
		u.key = k
		if rb, err := os.ReadFile(regPath); err == nil {
			_ = json.Unmarshal(rb, u)
			u.Email = email
		}
		return u, nil
	}

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	u.key = k
	return u, nil
}

func (m *Manager) saveUser(u *acmeUser) error {
	b, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(m.accountDir(u.Email), "account.json"), b, 0o600)
}

// obtain requests a certificate for cfg.CertDomain from Let's Encrypt.
func (m *Manager) obtain(cfg *Config) (certPEM, keyPEM []byte, err error) {
	user, err := m.loadUser(cfg.Email)
	if err != nil {
		return nil, nil, err
	}
	lc := lego.NewConfig(user)
	lc.CADirURL = lego.LEDirectoryProduction
	lc.Certificate.KeyType = certcrypto.EC256
	client, err := lego.NewClient(lc)
	if err != nil {
		return nil, nil, fmt.Errorf("create ACME client: %w", err)
	}

	switch cfg.CertMode {
	case ModeHTTP:
		port := cfg.HTTPPort
		if port <= 0 {
			port = 80
		}
		err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", strconv.Itoa(port)))
	case ModeTLS:
		err = client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer("", "443"))
	case ModeDNS:
		if cfg.Provider == "" {
			return nil, nil, errors.New("dns mode requires a DNS provider")
		}
		// lego DNS providers read their credentials from the environment.
		applyDNSEnv(cfg.DNSEnv)
		p, perr := newDNSProvider(cfg.Provider)
		if perr != nil {
			return nil, nil, fmt.Errorf("DNS provider %s: %w", cfg.Provider, perr)
		}
		err = client.Challenge.SetDNS01Provider(p)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("set ACME challenge: %w", err)
	}

	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, nil, fmt.Errorf("ACME registration: %w", err)
		}
		user.Registration = reg
		if err := m.saveUser(user); err != nil {
			return nil, nil, err
		}
	}

	res, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: []string{cfg.CertDomain},
		Bundle:  true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("obtain certificate for %s: %w", cfg.CertDomain, err)
	}
	return res.Certificate, res.PrivateKey, nil
}

// applyDNSEnv exports the DNS provider credentials to the process environment.
// The names are upper-cased: the config loader (viper) lower-cases map keys,
// so "CLOUDFLARE_API_KEY" arrives as "cloudflare_api_key", while lego reads the
// upper-case variable and environment names are case-sensitive on Linux. Without
// this, DNS-01 issuance and renewal fail with "credentials missing".
func applyDNSEnv(env map[string]string) {
	for k, v := range env {
		os.Setenv(strings.ToUpper(strings.TrimSpace(k)), v)
	}
}
