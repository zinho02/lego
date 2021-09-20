package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli"
	"github.com/zinho02/lego/v4/certcrypto"
	"github.com/zinho02/lego/v4/lego"
	"github.com/zinho02/lego/v4/log"
	"github.com/zinho02/lego/v4/registration"
)

const filePerm os.FileMode = 0o600

func setup(ctx *cli.Context, accountsStorage *AccountsStorage) (*Account, *lego.Client) {
	keyType := getKeyType(ctx)
	privateKey := accountsStorage.GetPrivateKey(keyType)

	var account *Account
	if accountsStorage.ExistsAccountFilePath() {
		account = accountsStorage.LoadAccount(privateKey)
	} else {
		account = &Account{Email: accountsStorage.GetUserID(), key: privateKey}
	}

	client := newClient(ctx, account, keyType)

	return account, client
}

func newClient(ctx *cli.Context, acc registration.User, keyType certcrypto.KeyType) *lego.Client {
	config := lego.NewConfig(acc)
	config.CADirURL = ctx.GlobalString("server")

	config.Certificate = lego.CertificateConfig{
		KeyType: keyType,
		Timeout: time.Duration(ctx.GlobalInt("cert.timeout")) * time.Second,
	}
	config.UserAgent = fmt.Sprintf("lego-cli/%s", ctx.App.Version)

	if ctx.GlobalIsSet("http-timeout") {
		config.HTTPClient.Timeout = time.Duration(ctx.GlobalInt("http-timeout")) * time.Second
	}

	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatalf("Could not create client: %v", err)
	}

	if client.GetExternalAccountRequired() && !ctx.GlobalIsSet("eab") {
		log.Fatal("Server requires External Account Binding. Use --eab with --kid and --hmac.")
	}

	return client
}

// getKeyType the type from which private keys should be generated.
func getKeyType(ctx *cli.Context) certcrypto.KeyType {
	keyType := ctx.GlobalString("key-type")
	switch strings.ToUpper(keyType) {
	case "RSA2048":
		return certcrypto.RSA2048
	case "RSA4096":
		return certcrypto.RSA4096
	case "RSA8192":
		return certcrypto.RSA8192
	case "EC256":
		return certcrypto.EC256
	case "EC384":
		return certcrypto.EC384
	case "DILITHIUM5":
		return certcrypto.Dilithium5
	case "DILITHIUM5-AES":
		return certcrypto.Dilithium5AES
	case "FALCON-1024":
		return certcrypto.Falcon1024
	case "RAINBOW-V-CLASSIC":
		return certcrypto.RainbowVClassic
	case "RAINBOW-V-CIRCUMZENITHAL":
		return certcrypto.RainbowVCircumzenithal
	case "RAINBOW-V-COMPRESSED":
		return certcrypto.RainbowVCompressed
	case "SPHINCS+-HARAKA-256S-SIMPLE":
		return certcrypto.SphincsPlusHaraka256sSimple
	case "SPHINCS+-HARAKA-256F-SIMPLE":
		return certcrypto.SphincsPlusHaraka256fSimple
	case "SPHINCS+-HARAKA-256S-ROBUST":
		return certcrypto.SphincsPlusHaraka256sRobust
	case "SPHINCS+-HARAKA-256F-ROBUST":
		return certcrypto.SphincsPlusHaraka256fRobust
	case "SPHINCS+-SHA256-256S-SIMPLE":
		return certcrypto.SphincsPlusSHA256256sSimple
	case "SPHINCS+-SHA256-256F-SIMPLE":
		return certcrypto.SphincsPlusSHA256256fSimple
	case "SPHINCS+-SHA256-256S-ROBUST":
		return certcrypto.SphincsPlusHaraka256sRobust
	case "SPHINCS+-SHA256-256F-ROBUST":
		return certcrypto.SphincsPlusHaraka256fRobust
	case "SPHINCS+-SHAKE256-256S-SIMPLE":
		return certcrypto.SphincsPlusSHAKE256256sSimple
	case "SPHINCS+-SHAKE256-256F-SIMPLE":
		return certcrypto.SphincsPlusSHAKE256256fSimple
	case "SPHINCS+-SHAKE256-256S-ROBUST":
		return certcrypto.SphincsPlusSHAKE256256sRobust
	case "SPHINCS+-SHAKE256-256F-ROBUST":
		return certcrypto.SphincsPlusSHAKE256256fRobust
	case "DILITHIUM2":
		return certcrypto.Dilithium2
	case "DILITHIUM2-AES":
		return certcrypto.Dilithium2AES
	case "FALCON-512":
		return certcrypto.Falcon512
	case "RAINBOW-I-CLASSIC":
		return certcrypto.RainbowIClassic
	case "RAINBOW-I-CIRCUMZENITHAL":
		return certcrypto.RainbowICircumzenithal
	case "RAINBOW-I-COMPRESSED":
		return certcrypto.RainbowICompressed
	case "SPHINCS+-HARAKA-128S-SIMPLE":
		return certcrypto.SphincsPlusHaraka128sSimple
	case "SPHINCS+-HARAKA-128F-SIMPLE":
		return certcrypto.SphincsPlusHaraka128fSimple
	case "SPHINCS+-HARAKA-128S-ROBUST":
		return certcrypto.SphincsPlusHaraka128sRobust
	case "SPHINCS+-HARAKA-128F-ROBUST":
		return certcrypto.SphincsPlusHaraka128fRobust
	case "SPHINCS+-SHA256-128S-SIMPLE":
		return certcrypto.SphincsPlusSHA256128sSimple
	case "SPHINCS+-SHA256-128F-SIMPLE":
		return certcrypto.SphincsPlusSHA256128fSimple
	case "SPHINCS+-SHA256-128S-ROBUST":
		return certcrypto.SphincsPlusSHA256128sRobust
	case "SPHINCS+-SHA256-128F-ROBUST":
		return certcrypto.SphincsPlusSHA256128fRobust
	case "SPHINCS+-SHAKE256-128S-SIMPLE":
		return certcrypto.SphincsPlusSHAKE256128sSimple
	case "SPHINCS+-SHAKE256-128F-SIMPLE":
		return certcrypto.SphincsPlusSHAKE256128fSimple
	case "SPHINCS+-SHAKE256-128S-ROBUST":
		return certcrypto.SphincsPlusSHAKE256128sRobust
	case "SPHINCS+-SHAKE256-128F-ROBUST":
		return certcrypto.SphincsPlusSHAKE256128fRobust
	}

	log.Fatalf("Unsupported KeyType: %s", keyType)
	return ""
}

func getEmail(ctx *cli.Context) string {
	email := ctx.GlobalString("email")
	if email == "" {
		log.Fatal("You have to pass an account (email address) to the program using --email or -m")
	}
	return email
}

func createNonExistingFolder(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, 0o700)
	} else if err != nil {
		return err
	}
	return nil
}

func readCSRFile(filename string) (*x509.CertificateRequest, error) {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	raw := bytes

	// see if we can find a PEM-encoded CSR
	var p *pem.Block
	rest := bytes
	for {
		// decode a PEM block
		p, rest = pem.Decode(rest)

		// did we fail?
		if p == nil {
			break
		}

		// did we get a CSR?
		if p.Type == "CERTIFICATE REQUEST" || p.Type == "NEW CERTIFICATE REQUEST" {
			raw = p.Bytes
		}
	}

	// no PEM-encoded CSR
	// assume we were given a DER-encoded ASN.1 CSR
	// (if this assumption is wrong, parsing these bytes will fail)
	return x509.ParseCertificateRequest(raw)
}
