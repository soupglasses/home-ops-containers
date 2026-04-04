package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"maps"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/home-operations/containers/testhelpers"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var baseEnv = map[string]string{
	"LDAP_SUFFIX":        "dc=test,dc=com",
	"LDAP_ROOT_PASSWORD": "testpass",
	"LDAP_ORGANISATION":  "Test",
}

func ldapsEnv() map[string]string {
	env := make(map[string]string, len(baseEnv)+2)
	maps.Copy(env, baseEnv)
	env["LDAP_URLS"] = "ldaps://0.0.0.0:636/"
	env["LDAPTLS_REQCERT"] = "never"
	return env
}

func runLDAP(t *testing.T, ctx context.Context, image string, env map[string]string, opts ...testcontainers.ContainerCustomizer) testcontainers.Container {
	t.Helper()

	opts = append([]testcontainers.ContainerCustomizer{testcontainers.WithEnv(env)}, opts...)

	c, err := testcontainers.Run(ctx, image, opts...)
	testcontainers.CleanupContainer(t, c)
	require.NoError(t, err)
	return c
}

func withTLSFiles(dir string) testcontainers.ContainerCustomizer {
	return testcontainers.WithFiles(
		testcontainers.ContainerFile{HostFilePath: filepath.Join(dir, "tls.crt"), ContainerFilePath: "/config/tls/tls.crt", FileMode: 0o444},
		testcontainers.ContainerFile{HostFilePath: filepath.Join(dir, "tls.key"), ContainerFilePath: "/config/tls/tls.key", FileMode: 0o444},
		testcontainers.ContainerFile{HostFilePath: filepath.Join(dir, "ca.crt"), ContainerFilePath: "/config/tls/ca.crt", FileMode: 0o444},
	)
}

func Test(t *testing.T) {
	ctx := context.Background()
	image := testhelpers.GetTestImage("ghcr.io/home-operations/openldap:rolling")

	t.Run("anonymous base search", func(t *testing.T) {
		c := runLDAP(t, ctx, image, baseEnv,
			testcontainers.WithExposedPorts("389/tcp"),
			testcontainers.WithWaitStrategy(wait.ForListeningPort("389/tcp")),
		)

		exitCode, _, err := c.Exec(ctx, []string{
			"ldapsearch", "-x", "-H", "ldap://localhost",
			"-b", "", "-s", "base", "(objectclass=*)", "namingContexts",
		})
		require.NoError(t, err)
		require.Equal(t, 0, exitCode, "anonymous root DSE search should succeed")
	})

	t.Run("authenticated search", func(t *testing.T) {
		c := runLDAP(t, ctx, image, baseEnv,
			testcontainers.WithExposedPorts("389/tcp"),
			testcontainers.WithWaitStrategy(wait.ForListeningPort("389/tcp")),
		)

		exitCode, _, err := c.Exec(ctx, []string{
			"ldapsearch", "-x", "-H", "ldap://localhost",
			"-D", "cn=admin,dc=test,dc=com", "-w", "testpass",
			"-b", "dc=test,dc=com", "(objectclass=*)",
		})
		require.NoError(t, err)
		require.Equal(t, 0, exitCode, "authenticated search should succeed")
	})

	t.Run("ldaps authenticated search", func(t *testing.T) {
		tlsDir := generateTestCerts(t)

		c := runLDAP(t, ctx, image, ldapsEnv(),
			testcontainers.WithExposedPorts("636/tcp"),
			testcontainers.WithWaitStrategy(wait.ForListeningPort("636/tcp")),
			withTLSFiles(tlsDir),
		)

		exitCode, _, err := c.Exec(ctx, []string{
			"ldapsearch", "-x", "-H", "ldaps://localhost",
			"-D", "cn=admin,dc=test,dc=com", "-w", "testpass",
			"-b", "dc=test,dc=com", "(objectclass=*)",
		})
		require.NoError(t, err)
		require.Equal(t, 0, exitCode, "LDAPS authenticated search should succeed")
	})

	t.Run("ldaps only rejects plain ldap", func(t *testing.T) {
		tlsDir := generateTestCerts(t)

		c := runLDAP(t, ctx, image, ldapsEnv(),
			testcontainers.WithExposedPorts("636/tcp"),
			testcontainers.WithWaitStrategy(wait.ForListeningPort("636/tcp")),
			withTLSFiles(tlsDir),
		)

		exitCode, _, err := c.Exec(ctx, []string{
			"ldapsearch", "-x", "-H", "ldap://localhost",
			"-b", "", "-s", "base", "(objectclass=*)",
		})
		require.NoError(t, err)
		require.NotEqual(t, 0, exitCode, "plain LDAP should fail when only LDAPS is configured")
	})
}

func generateTestCerts(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)
	writePEM(t, filepath.Join(dir, "ca.crt"), "CERTIFICATE", caCertDER)

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	require.NoError(t, err)
	writePEM(t, filepath.Join(dir, "tls.crt"), "CERTIFICATE", serverCertDER)

	serverKeyDER, err := x509.MarshalECPrivateKey(serverKey)
	require.NoError(t, err)
	writePEM(t, filepath.Join(dir, "tls.key"), "EC PRIVATE KEY", serverKeyDER)

	return dir
}

func writePEM(t *testing.T, path, blockType string, data []byte) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	require.NoError(t, pem.Encode(f, &pem.Block{Type: blockType, Bytes: data}))
}
