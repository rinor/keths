package main

import (
	"crypto/ecdsa"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

const ethsignerKeyTemplate = `[signing]
type = "file-based-signer"
key-file = "/opt/ethsigner/keys/validator"
password-file = "/opt/ethsigner/keys/password"
`

func main() {
	var passphrase = flag.String("p", os.Getenv("KETHS_PASSPHRASE"), "passphrase used to encypt web3 store. env: [KETHS_PASSPHRASE]")

	flag.Parse()

	if len(*passphrase) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	/* private key */
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	privateKeyBytes := crypto.FromECDSA(privateKey)
	private := hexutil.Encode(privateKeyBytes)[2:] // [2:] 0x stripped

	/* public key */
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("error casting public key to ECDSA")
	}
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	public := hexutil.Encode(publicKeyBytes)[4:] // [4:] 0x04 stripped

	/* address */
	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex() // EIP55-compliant

	/* kestore */
	ks := keystore.NewKeyStore(".", 8192, keystore.StandardScryptP) // 8192 != keystore.StandardScryptN = 262144

	accountStore, err := ks.ImportECDSA(privateKey, *passphrase)
	if err != nil {
		log.Fatal(err)
	}
	if accountStore.Address.Hex() != address {
		log.Fatalf("PubkeyToAddress: [%s] expected to be equal to address in store: [%s]", address, accountStore.Address.Hex())
	}

	fmt.Printf("address : %s\n", address)
	fmt.Printf("pub key : %s\n", public)

	// custom stuff - hardcoded for now
	err = ioutil.WriteFile("key", []byte(private), 0644)
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("key.pub", []byte(public), 0644)
	if err != nil {
		log.Fatal(err)
	}

	var (
		keyFile           = address[2:] + ".key"
		passwordFile      = address[2:] + ".password"
		ethsignerTemplate = `[signing]
type = "file-based-signer"
key-file = "/opt/ethsigner/keys/` + keyFile + `"
password-file = "/opt/ethsigner/keys/` + passwordFile + `"
`
	)
	err = ioutil.WriteFile(passwordFile, []byte(*passphrase), 0644)
	if err != nil {
		log.Fatal(err)
	}
	err = os.Rename(accountStore.URL.Path, filepath.Dir(accountStore.URL.Path)+"/"+keyFile)
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile(address[2:]+".toml", []byte(ethsignerTemplate), 0644)
	if err != nil {
		log.Fatal(err)
	}
}
