// Copyright 2015 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package mitm provides tooling for MITMing TLS connections. It provides
// tooling to create CA certs and generate TLS configs that can be used to MITM
// a TLS connection with a provided CA certificate.
package mitm

//mitm：faketlsserver使用的TLS配置封装

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/google/martian/v3/h2"
	"github.com/google/martian/v3/log"
)

// MaxSerialNumber is the upper boundary that is used to create unique serial
// numbers for the certificate. This can be any unsigned integer up to 20
// bytes (2^(8*20)-1).
var MaxSerialNumber = big.NewInt(0).SetBytes(bytes.Repeat([]byte{255}, 20))

// Config is a set of configuration values that are used to build TLS configs
// capable of MITM.
type Config struct {
	ca                     *x509.Certificate
	capriv                 interface{}
	priv                   *rsa.PrivateKey
	keyID                  []byte
	validity               time.Duration
	org                    string
	h2Config               *h2.Config
	getCertificate         func(*tls.ClientHelloInfo) (*tls.Certificate, error) //根据tls握手信息获取证书
	roots                  *x509.CertPool
	skipVerify             bool
	handshakeErrorCallback func(*http.Request, error)

	certmu sync.RWMutex
	certs  map[string]*tls.Certificate //存储certs
}

// NewAuthority creates a new CA certificate and associated
// private key.
func NewAuthority(name, organization string, validity time.Duration) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	pub := priv.Public()

	// Subject Key Identifier support for end entity certificate.
	// https://www.ietf.org/rfc/rfc3280.txt (section 4.2.1.2)
	pkixpub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	h := sha1.New()
	h.Write(pkixpub)
	keyID := h.Sum(nil)

	// TODO: keep a map of used serial numbers to avoid potentially reusing a
	// serial multiple times.
	serial, err := rand.Int(rand.Reader, MaxSerialNumber)
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{organization},
		},
		SubjectKeyId:          keyID,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-validity),
		NotAfter:              time.Now().Add(validity),
		DNSNames:              []string{name},
		IsCA:                  true,
	}

	raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, nil, err
	}

	// Parse certificate bytes so that we have a leaf certificate.
	x509c, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, nil, err
	}

	return x509c, priv, nil
}

// NewConfig creates a MITM config using the CA certificate and
// private key to generate on-the-fly certificates.
func NewConfig(ca *x509.Certificate, privateKey interface{}) (*Config, error) {
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	pub := priv.Public()

	// Subject Key Identifier support for end entity certificate.
	// https://www.ietf.org/rfc/rfc3280.txt (section 4.2.1.2)
	pkixpub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	h := sha1.New()
	h.Write(pkixpub)
	keyID := h.Sum(nil)

	return &Config{
		ca:       ca,
		capriv:   privateKey,
		priv:     priv,
		keyID:    keyID,
		validity: time.Hour,
		org:      "Martian Proxy",
		certs:    make(map[string]*tls.Certificate),
		roots:    roots,
	}, nil
}

// SetValidity sets the validity window around the current time that the
// certificate is valid for.
func (c *Config) SetValidity(validity time.Duration) {
	c.validity = validity
}

// SkipTLSVerify skips the TLS certification verification check.
func (c *Config) SkipTLSVerify(skip bool) {
	c.skipVerify = skip
}

// SetOrganization sets the organization of the certificate.
func (c *Config) SetOrganization(org string) {
	c.org = org
}

// SetH2Config configures processing of HTTP/2 streams.
func (c *Config) SetH2Config(h2Config *h2.Config) {
	c.h2Config = h2Config
}

// H2Config returns the current HTTP/2 configuration.
func (c *Config) H2Config() *h2.Config {
	return c.h2Config
}

// SetHandshakeErrorCallback sets the handshakeErrorCallback function.
func (c *Config) SetHandshakeErrorCallback(cb func(*http.Request, error)) {
	c.handshakeErrorCallback = cb
}

// HandshakeErrorCallback calls the handshakeErrorCallback function in this
// Config, if it is non-nil. Request is the connect request that this handshake
// is being executed through.
func (c *Config) HandshakeErrorCallback(r *http.Request, err error) {
	if c.handshakeErrorCallback != nil {
		c.handshakeErrorCallback(r, err)
	}
}

// TLS returns a *tls.Config that will generate certificates on-the-fly using
// the SNI extension in the TLS ClientHello.
func (c *Config) TLS() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: c.skipVerify, //跳过证书校验
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if clientHello.ServerName == "" {
				return nil, errors.New("mitm: SNI not provided, failed to build certificate")
			}

			//获取sni对应的证书
			return c.cert(clientHello.ServerName)
		},
		NextProtos: []string{"http/1.1"},
		/*
			InsecureSkipVerify: 这个字段设置为 c.skipVerify，用于确定是否跳过服务器证书验证。如果设置为 true，客户端将不会验证服务器的证书，这可能导致安全问题。通常，这个选项仅用于测试或调试。
			GetCertificate: 这是一个函数，它接收一个 *tls.ClientHelloInfo 参数，并返回一个 *tls.Certificate 和一个错误。在这个例子中，函数首先检查客户端的 "Server Name Indication" (SNI) 是否为空。如果为空，函数返回一个错误，表示无法生成证书。如果 SNI 不为空，函数使用 c.cert(clientHello.ServerName) 为指定的服务器名生成证书。
			NextProtos: 这是一个字符串切片，包含了支持的应用层协议。在这个例子中，它设置为 ["http/1.1"]，表示仅支持 HTTP/1.1 协议。
		*/
	}
}

// TLSForHost returns a *tls.Config that will generate certificates on-the-fly
// using SNI from the connection, or fall back to the provided hostname.

// 优先使用servername，如果servername为空则使用hostname
func (c *Config) TLSForHost(hostname string) *tls.Config {
	nextProtos := []string{"http/1.1"}
	if c.h2AllowedHost(hostname) {
		//服务其提供HTTP2+HTTP1.1的选项
		nextProtos = []string{"h2", "http/1.1"}
	}
	return &tls.Config{
		InsecureSkipVerify: c.skipVerify,
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := clientHello.ServerName
			if host == "" {
				host = hostname
			}

			return c.cert(host)
		},
		NextProtos: nextProtos,
	}
}

func (c *Config) h2AllowedHost(host string) bool {
	return c.h2Config != nil &&
		c.h2Config.AllowedHostsFilter != nil &&
		c.h2Config.AllowedHostsFilter(host)
}

// 根据sni获取证书
func (c *Config) cert(hostname string) (*tls.Certificate, error) {
	// Remove the port if it exists.
	host, _, err := net.SplitHostPort(hostname)
	if err == nil {
		hostname = host
	}

	c.certmu.RLock()
	tlsc, ok := c.certs[hostname]
	c.certmu.RUnlock()

	if ok {
		log.Debugf("mitm: cache hit for %s", hostname)

		// Check validity of the certificate for hostname match, expiry, etc. In
		// particular, if the cached certificate has expired, create a new one.
		if _, err := tlsc.Leaf.Verify(x509.VerifyOptions{
			DNSName: hostname,
			Roots:   c.roots,
		}); err == nil {
			return tlsc, nil
		}

		log.Debugf("mitm: invalid certificate in cache for %s", hostname)
	}

	log.Debugf("mitm: cache miss for %s", hostname)

	serial, err := rand.Int(rand.Reader, MaxSerialNumber)
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{c.org},
		},
		SubjectKeyId:          c.keyID,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-c.validity),
		NotAfter:              time.Now().Add(c.validity),
	}

	if ip := net.ParseIP(hostname); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{hostname}
	}

	raw, err := x509.CreateCertificate(rand.Reader, tmpl, c.ca, c.priv.Public(), c.capriv)
	if err != nil {
		return nil, err
	}

	// Parse certificate bytes so that we have a leaf certificate.
	x509c, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, err
	}

	tlsc = &tls.Certificate{
		Certificate: [][]byte{raw, c.ca.Raw},
		PrivateKey:  c.priv,
		Leaf:        x509c,
	}

	c.certmu.Lock()
	c.certs[hostname] = tlsc
	c.certmu.Unlock()

	return tlsc, nil
}
