package main

import (
	"crypto/ecdsa"
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	var (
		passphrase = flag.String("p", os.Getenv("KETHS_PASSPHRASE"), "passphrase used to encypt web3 store. env: [KETHS_PASSPHRASE]")
		pk         = flag.String("k", os.Getenv("KETHS_PRIVATEKEY"), "existing private key used to create web3 store. env: [KETHS_PRIVATEKEY]")
		scryptN    = flag.Int("scryptN", keystore.StandardScryptN, "the N parameter of Scrypt encryption algorithm")
		scryptP    = flag.Int("scryptP", keystore.StandardScryptP, "the P parameter of Scrypt encryption algorithm")
		storePath  = flag.String("d", "keystore", "folder path to store the keys")

		privateKey *ecdsa.PrivateKey
		err        error
	)

	flag.Parse()

	if len(*passphrase) == 0 {
		log.Println("WARN: no passphrase set ...")
	}

	/* private key */
	if len(*pk) > 0 {
		privateKey, err = crypto.HexToECDSA(*pk)
	} else {
		privateKey, err = crypto.GenerateKey()
	}
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

	/* keystore */
	ks := keystore.NewKeyStore(*storePath, *scryptN, *scryptP)

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
	err = os.WriteFile(path.Join(*storePath, address[2:]+".node.key"), []byte(private), 0400)
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile(path.Join(*storePath, address[2:]+".node.pub"), []byte(public), 0444)
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
	err = os.WriteFile(path.Join(*storePath, passwordFile), []byte(*passphrase), 0400)
	if err != nil {
		log.Fatal(err)
	}
	err = os.Rename(accountStore.URL.Path, filepath.Dir(accountStore.URL.Path)+"/"+keyFile)
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile(path.Join(*storePath, strings.ToLower(address[2:])+".toml"), []byte(ethsignerTemplate), 0444)
	if err != nil {
		log.Fatal(err)
	}
}
