package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"maps"
	"math/big"
	"os"
	"path/filepath"
	"strings"
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
}

var customOrgEnv = map[string]string{
	"LDAP_SUFFIX":            "dc=test,dc=com",
	"LDAP_ROOT_PASSWORD":     "testpass",
	"LDAP_ORGANIZATION_NAME": "Test Organization",
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

	t.Run("custom organization name", func(t *testing.T) {
		c := runLDAP(t, ctx, image, customOrgEnv,
			testcontainers.WithExposedPorts("389/tcp"),
			testcontainers.WithWaitStrategy(wait.ForListeningPort("389/tcp")),
		)

		exitCode, output, err := c.Exec(ctx, []string{
			"ldapsearch", "-x", "-H", "ldap://localhost",
			"-D", "cn=admin,dc=test,dc=com", "-w", "testpass",
			"-b", "dc=test,dc=com", "(objectclass=organization)", "o",
		})
		require.NoError(t, err)
		require.Equal(t, 0, exitCode, "search for organization should succeed")
		outputBytes, err := io.ReadAll(output)
		require.NoError(t, err)
		require.Contains(t, string(outputBytes), "Test Organization")
	})

	t.Run("overlays can be enabled", func(t *testing.T) {
		env := make(map[string]string, len(baseEnv)+1)
		maps.Copy(env, baseEnv)
		env["LDAP_OVERLAYS"] = "memberof,refint"

		c := runLDAP(t, ctx, image, env,
			testcontainers.WithExposedPorts("389/tcp"),
			testcontainers.WithWaitStrategy(wait.ForListeningPort("389/tcp")),
		)

		exitCode, _, err := c.Exec(ctx, []string{
			"ldapsearch", "-x", "-H", "ldap://localhost",
			"-b", "", "-s", "base", "(objectclass=*)",
		})
		require.NoError(t, err)
		require.Equal(t, 0, exitCode, "server should start with overlays enabled")
	})

	t.Run("starttls authenticated search", func(t *testing.T) {
		tlsDir := generateTestCerts(t)

		c := runLDAP(t, ctx, image, baseEnv,
			testcontainers.WithExposedPorts("389/tcp"),
			testcontainers.WithWaitStrategy(wait.ForListeningPort("389/tcp")),
			withTLSFiles(tlsDir),
		)

		exitCode, _, err := c.Exec(ctx, []string{
			"sh", "-c", "LDAPTLS_REQCERT=never ldapsearch -ZZ -x -H ldap://localhost -D cn=admin,dc=test,dc=com -w testpass -b dc=test,dc=com '(objectclass=*)'",
		})
		require.NoError(t, err)
		require.Equal(t, 0, exitCode, "StartTLS authenticated search should succeed")
	})

	t.Run("tls required rejects plain ldap on 389", func(t *testing.T) {
		tlsDir := generateTestCerts(t)

		c := runLDAP(t, ctx, image, baseEnv,
			testcontainers.WithExposedPorts("389/tcp"),
			testcontainers.WithWaitStrategy(wait.ForListeningPort("389/tcp")),
			withTLSFiles(tlsDir),
		)

		exitCode, _, err := c.Exec(ctx, []string{
			"ldapsearch", "-x", "-H", "ldap://localhost",
			"-b", "", "-s", "base", "(objectclass=*)",
		})
		require.NoError(t, err)
		require.NotEqual(t, 0, exitCode, "plain LDAP should fail when TLS is required")
	})

	t.Run("ldaps remains available on 636", func(t *testing.T) {
		tlsDir := generateTestCerts(t)

		c := runLDAP(t, ctx, image, baseEnv,
			testcontainers.WithExposedPorts("389/tcp", "636/tcp"),
			testcontainers.WithWaitStrategy(wait.ForListeningPort("389/tcp"), wait.ForListeningPort("636/tcp")),
			withTLSFiles(tlsDir),
		)

		exitCode, _, err := c.Exec(ctx, []string{
			"sh", "-c", "LDAPTLS_REQCERT=never ldapsearch -x -H ldaps://localhost -D cn=admin,dc=test,dc=com -w testpass -b dc=test,dc=com '(objectclass=*)'",
		})
		require.NoError(t, err)
		require.Equal(t, 0, exitCode, "LDAPS on 636 should be available")
	})

	t.Run("passwords are hashed with ARGON2", func(t *testing.T) {
		c := runLDAP(t, ctx, image, baseEnv,
			testcontainers.WithExposedPorts("389/tcp"),
			testcontainers.WithWaitStrategy(wait.ForListeningPort("389/tcp")),
		)

		// Add a test user without a password
		ldif := `dn: cn=testuser,dc=test,dc=com
objectClass: inetOrgPerson
cn: testuser
sn: User`

		exitCode, _, err := c.Exec(ctx, []string{
			"sh", "-c", "echo '" + ldif + "' | ldapadd -x -H ldap://localhost -D cn=admin,dc=test,dc=com -w testpass",
		})
		require.NoError(t, err)
		require.Equal(t, 0, exitCode, "adding test user should succeed")

		// Set password via ldappasswd which uses the server's password-hash setting
		exitCode, _, err = c.Exec(ctx, []string{
			"ldappasswd", "-x", "-H", "ldap://localhost",
			"-D", "cn=admin,dc=test,dc=com", "-w", "testpass",
			"-s", "newpassword", "cn=testuser,dc=test,dc=com",
		})
		require.NoError(t, err)
		require.Equal(t, 0, exitCode, "setting password via ldappasswd should succeed")

		// Retrieve the user's password hash and verify it uses ARGON2
		exitCode, output, err := c.Exec(ctx, []string{
			"ldapsearch", "-x", "-H", "ldap://localhost",
			"-D", "cn=admin,dc=test,dc=com", "-w", "testpass",
			"-b", "cn=testuser,dc=test,dc=com", "userPassword",
		})
		require.NoError(t, err)
		require.Equal(t, 0, exitCode, "searching for user password should succeed")

		outputBytes, err := io.ReadAll(output)
		require.NoError(t, err)
		outputStr := string(outputBytes)

		// Extract base64-encoded userPassword (LDIF uses :: for base64 values)
		// LDIF folds long lines with leading space on continuation lines
		var b64Value strings.Builder
		inPassword := false
		for _, line := range strings.Split(outputStr, "\n") {
			if strings.HasPrefix(line, "userPassword:: ") {
				b64Value.WriteString(strings.TrimPrefix(line, "userPassword:: "))
				inPassword = true
			} else if inPassword && strings.HasPrefix(line, " ") {
				b64Value.WriteString(strings.TrimPrefix(line, " "))
			} else if inPassword {
				break
			}
		}
		decoded, err := base64.StdEncoding.DecodeString(b64Value.String())
		require.NoError(t, err)
		require.Contains(t, string(decoded), "{ARGON2}", "password should be hashed with ARGON2")
	})

	t.Run("admin password is hashed with ARGON2", func(t *testing.T) {
		c := runLDAP(t, ctx, image, baseEnv,
			testcontainers.WithExposedPorts("389/tcp"),
			testcontainers.WithWaitStrategy(wait.ForListeningPort("389/tcp")),
		)

		// Read the slapd.conf to check the rootpw hash
		exitCode, output, err := c.Exec(ctx, []string{
			"grep", "^rootpw", "/config/slapd.conf",
		})
		require.NoError(t, err)
		require.Equal(t, 0, exitCode, "grep rootpw should succeed")

		outputBytes, err := io.ReadAll(output)
		require.NoError(t, err)
		require.Contains(t, string(outputBytes), "{ARGON2}", "admin password should be hashed with ARGON2")
	})

	t.Run("cleartext passwords in LDIF are hashed via ppolicy", func(t *testing.T) {
		c := runLDAP(t, ctx, image, baseEnv,
			testcontainers.WithExposedPorts("389/tcp"),
			testcontainers.WithWaitStrategy(wait.ForListeningPort("389/tcp")),
		)

		// Add a user with a cleartext password
		ldif := `dn: cn=testuser,dc=test,dc=com
objectClass: inetOrgPerson
cn: testuser
sn: User
userPassword: cleartextpassword`

		exitCode, _, err := c.Exec(ctx, []string{
			"sh", "-c", "echo '" + ldif + "' | ldapadd -x -H ldap://localhost -D cn=admin,dc=test,dc=com -w testpass",
		})
		require.NoError(t, err)
		require.Equal(t, 0, exitCode, "adding test user should succeed")

		// Retrieve the user's password hash and verify it was hashed
		exitCode, output, err := c.Exec(ctx, []string{
			"ldapsearch", "-x", "-H", "ldap://localhost",
			"-D", "cn=admin,dc=test,dc=com", "-w", "testpass",
			"-b", "cn=testuser,dc=test,dc=com", "userPassword",
		})
		require.NoError(t, err)
		require.Equal(t, 0, exitCode, "searching for user password should succeed")

		outputBytes, err := io.ReadAll(output)
		require.NoError(t, err)
		outputStr := string(outputBytes)

		// Extract base64-encoded userPassword
		var b64Value strings.Builder
		inPassword := false
		for _, line := range strings.Split(outputStr, "\n") {
			if strings.HasPrefix(line, "userPassword:: ") {
				b64Value.WriteString(strings.TrimPrefix(line, "userPassword:: "))
				inPassword = true
			} else if inPassword && strings.HasPrefix(line, " ") {
				b64Value.WriteString(strings.TrimPrefix(line, " "))
			} else if inPassword {
				break
			}
		}
		decoded, err := base64.StdEncoding.DecodeString(b64Value.String())
		require.NoError(t, err)
		require.Contains(t, string(decoded), "{ARGON2}", "cleartext password should be hashed with ARGON2 via ppolicy")
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
