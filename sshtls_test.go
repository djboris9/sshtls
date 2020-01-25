package sshtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"testing"
)

const cert = `-----BEGIN CERTIFICATE-----
MIIDrTCCApWgAwIBAgIUPWG3/X2cNrVhaQnL0/ISKcRG9l0wDQYJKoZIhvcNAQEL
BQAwZjELMAkGA1UEBhMCQ0gxDTALBgNVBAgMBEJlcm4xDTALBgNVBAcMBEJlcm4x
DzANBgNVBAoMBnNzaHRsczEUMBIGA1UECwwLc3NodGxzLWRldnMxEjAQBgNVBAMM
CWxvY2FsaG9zdDAeFw0yMDAxMjQyMTU5MjVaFw0zMDAxMjEyMTU5MjVaMGYxCzAJ
BgNVBAYTAkNIMQ0wCwYDVQQIDARCZXJuMQ0wCwYDVQQHDARCZXJuMQ8wDQYDVQQK
DAZzc2h0bHMxFDASBgNVBAsMC3NzaHRscy1kZXZzMRIwEAYDVQQDDAlsb2NhbGhv
c3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChUvUf468UF+u43k2h
nnIQLP7KBf0QjZFKhmEhXsTKZfkOFzGsUG6SOGXI4NgeavcBEsYoRnXiIWviuJL0
UAsLKXrMWypvEVQryFqwrTd+N20Argwcrroe9gQSjx+s5lqS7crOHH/sa6QuIROQ
mu1FFmWKI8EMFZPB03fHJEVEtDfbCfZI3YTa3OjLn2lmqF7bhnwptr3dlhdZgf1d
ov37ZhIf9iAjLpZ9oVbVOqXRdFVEZ2fy8bVGa5IwH3z4Wa9QGv4WMtM4n2mwJTql
lqsQRjL71WBPANey9bCOAPK7RLMg3wPfkZHh4mQAuld8l5mxxnwlyvsNICErFmHL
CinNAgMBAAGjUzBRMB0GA1UdDgQWBBSdsYKXzT8VgaOciga2cRFU7Z2sPzAfBgNV
HSMEGDAWgBSdsYKXzT8VgaOciga2cRFU7Z2sPzAPBgNVHRMBAf8EBTADAQH/MA0G
CSqGSIb3DQEBCwUAA4IBAQBiLzM2SEWW6IiEIavemTuv8njo+PcXGO6rfGoAKJn1
WUnMC/Y3M7SUZ9f96q5ULdh4sho5sy43ddWen+ZUvNEz48jAHvZMssyNz3F6Ee9I
GIYjTjkzGzo6ypBjwNkqhqzmzYebTv4mwUcgdLdkr3F3GTx+PGs1v6KFObooTPF4
Zfe48b/BQlR4zgtlVTVgC7jUgTFKRPh40xPgmBcn6rrYd5fbfSb4rALi0O8IROUL
k8ichqQIKdKdG88v28CMffHQ5FZ7/7JSbNa2wc2vGoQfYpd25JI5RL/2tGHSLEbI
1PElXzDk/D1KDNpc/58TvjhZKopku5Coth+jwMQ5Z00S
-----END CERTIFICATE-----`

const key = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQChUvUf468UF+u4
3k2hnnIQLP7KBf0QjZFKhmEhXsTKZfkOFzGsUG6SOGXI4NgeavcBEsYoRnXiIWvi
uJL0UAsLKXrMWypvEVQryFqwrTd+N20Argwcrroe9gQSjx+s5lqS7crOHH/sa6Qu
IROQmu1FFmWKI8EMFZPB03fHJEVEtDfbCfZI3YTa3OjLn2lmqF7bhnwptr3dlhdZ
gf1dov37ZhIf9iAjLpZ9oVbVOqXRdFVEZ2fy8bVGa5IwH3z4Wa9QGv4WMtM4n2mw
JTqllqsQRjL71WBPANey9bCOAPK7RLMg3wPfkZHh4mQAuld8l5mxxnwlyvsNICEr
FmHLCinNAgMBAAECggEAS6bIdpziBG03SGlPRGQ2HynKjdiDFRkeMjGUKP71D+kE
AzyTObg6Me2qpanzD0if7mvsawSn0VRU8GwX1eQXWbOo914lJxKcQy/gf4urQ1Ag
mLoFygmSFGTQAhgGBaG8hbxnZ4Jr5uWPh2ZRc3WDoOtg0If1xoHz2Wgeek+jABU4
on+VKbt5YRTi6vME1X1kilVat+PSRrivqHtj3FDgCV2lAHjhRMYwqoW5s+lRy/x8
T25gpydeNMyheeMiNmNh58inCyoVY3MyatEIa2w/6LxjuzFnBtFZzQDB+6cxlHsX
nYHJgQJ72C8KOE45XuMp8VbFeXEy+fNsm5X2iOkFwQKBgQDN12/qMNVkIQ1C5ln8
YHClr79N2vGDiqOhKJajW/KoWL+YxUOhkAtKu8HpIYyZVNZKCyvj9HVmx+wpJMaq
1IsoDcgDJErKzm85bnYvgK78db/in5iOVYdfP+Sta/FyMvzE3DaODmAMyPDEXIlM
6HPd3e+gd7CnrP4FW9n9eIjPPQKBgQDIonuSQErwt2001AEIGJmD2IoF47HPRetr
ekErtkO8YawPbnTfZ0Cr5wD4hWp61EclElfceiqYthm8AUEljv1hjpZUBGF+WAH5
0BYfeTJ0umzjL1r/TbGsxj5GyuvD6BOV3gXrq0J0o/gkeVS8vFW0pJyVl1+eLQsO
Lo624Uxt0QKBgHm1/D+udk7JWE0JZYXcBF+DxosjfZC5Bj3BgSjAsn+mUkvjwDSk
tniPAn51zuvPBRIs/tu/7TdD2TkOvMW//TRGydBJwkueupdr4EgAP/eZLEe09ICc
w/mnDvEYFWDgEyPXzg47I8ILgomo6apm/DPhCdKJUxQiLuU+RWwhvEtFAoGBAI9n
q8F2WNpDkTgQTIh35MpbbRQWkpIfXMzeflR7G2E7wtrozXqc95mnLId1/Qy8S/nQ
aaJ6Y5XxmuVJVEI/ORaQ7xwwYWsIBqmDNTzbyNesJIYh4/3Vj6h5riu1gNzvNYiK
QFsZdw+d35BadNnOF8hdXFqD7uFFOsCxQGqxEIrxAoGAGIYofPQ1Tv+s40JpxjYL
hWxakddKZynCiJRsCv7KCtvkoS4XQbQFjgThqKUbZfX7t+yYGYb91pKU0RadkC/8
xKSRTSso9UDUUIsaLJ3utHiy9t/ssX5+rR0Okw4rJxBxMFEUPtM7YoUOj4TIiHF6
ut39aGZ3CWTvKzHpJ4mZRF0=
-----END PRIVATE KEY-----`

func startServer() (*http.Server, string, error) {
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(cert))

	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	tlsConfig.BuildNameToCertificate()

	// Create a Server instance to listen on port 8443 with the TLS config
	echoHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, r.URL.RequestURI())
	})

	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
		Handler:   echoHandler,
	}

	// Listen to HTTPS connections with the server certificate and wait
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}

	go func() {
		if err := server.ServeTLS(l, "cert.pem", "key.pem"); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	addr := fmt.Sprintf("https://%s/", l.Addr().String())
	addr = strings.ReplaceAll(addr, "127.0.0.1", "localhost")
	return server, addr, nil
}

func testClient(client *http.Client, target string) error {
	r, err := client.Get(target)
	if err != nil {
		return err
	}

	defer r.Body.Close()
	_, err = ioutil.ReadAll(r.Body)

	//t.Logf("Got answer: %s", body)
	return err
}

func TestNormalTLSClient(t *testing.T) {
	// Start server
	srv, addr, err := startServer()
	if err != nil {
		t.Fatal(err)
		return
	}
	defer srv.Shutdown(nil)

	// Build client
	clientCert, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		t.Fatal(err)
		return
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(cert))

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{clientCert},
			},
		},
	}

	// Test client
	err = testClient(client, addr)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSSHTLSClientWithoutAgent(t *testing.T) {
	// Start server
	srv, addr, err := startServer()
	if err != nil {
		t.Fatal(err)
		return
	}
	defer srv.Shutdown(nil)

	// Build client
	agt := Agent{
		Cert: []byte(cert),
		Key:  []byte(key),
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(cert))

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:              caCertPool,
				GetClientCertificate: agt.CertAgent,
			},
		},
	}

	// Test client
	err = testClient(client, addr)
	if err != nil {
		t.Fatal(err)
	}
}
