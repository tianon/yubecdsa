package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"log/slog"
	"maps"
	"math/big"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"time"

	"github.com/alexflint/go-arg"
	"github.com/go-piv/piv-go/v2/piv"
)

var pivClient = piv.Client{Shared: true}

// a helper for "piv.Open" that supports either a card string like "opensc-tool --list-readers" outputs ("Yubico YubiKey CCID 00 00") or a serial number ("NNNNNN") via linear search (yes, horrifying, but we have no choice because we have to open a card to check the serial number)
func open(cardOrSerial string) (*piv.YubiKey, error) {
	yubi, topErr := pivClient.Open(cardOrSerial)
	if topErr == nil {
		return yubi, nil
	}

	// only continue if cardOrSerial is numeric (serials are uint32)
	lookingForSerial64, err := strconv.ParseUint(cardOrSerial, 10, 32)
	if err != nil {
		return nil, err
	}
	lookingForSerial := uint32(lookingForSerial64)

	cards, err := pivClient.Cards()
	if err != nil {
		return nil, err
	}

	// if "lookingForSerial" is less than len(cards), it's probably an index like "0", "1", etc
	if int(lookingForSerial) < len(cards) {
		return pivClient.Open(cards[lookingForSerial])
	}

	for _, card := range cards {
		if yubi, err := pivClient.Open(card); err == nil {
			if serial, err := yubi.Serial(); err == nil && serial == lookingForSerial {
				return yubi, nil
			}
			yubi.Close()
		}
	}

	return nil, topErr
}

type Card struct {
	*piv.YubiKey `arg:"-"`
}

func (c *Card) UnmarshalText(b []byte) error {
	yubi, err := open(string(b))
	if err != nil {
		return err
	}
	c.YubiKey = yubi
	return nil
}

type Slot piv.Slot

func (s *Slot) UnmarshalText(b []byte) error {
	slotKey, err := strconv.ParseUint(string(b), 16, 8) // "9c", etc
	if err != nil {
		return err
	}
	object, ok := slotObjectMap[uint8(slotKey)]
	if !ok {
		return fmt.Errorf("'%02x' is not a valid slot for ECDSA", slotKey)
	}
	s.Key = uint32(slotKey)
	s.Object = object
	return nil
}

type HexString []byte

func (s *HexString) UnmarshalText(src []byte) error {
	dst := make([]byte, hex.DecodedLen(len(src)))

	n, err := hex.Decode(dst, src)
	if err != nil {
		return err
	}

	*s = dst[:n]
	return nil
}

type cardArg struct {
	Card Card `arg:"required,env:CARD" help:"selected card; serial number ('12345'), card string ('Yubico YubiKey CCID 00 00'), or index ('0')"`
}
type slotArg struct {
	Slot Slot `arg:"required,env:SLOT" help:"selected slot ('9c', etc)"`
}
type pinArg struct {
	// TODO add support for reading PIN from a file?  maybe have this create/provide a KeyAuth struct directly with a suitable PINPrompt so it can pull up a file's contents?  look at more weird go-arg stuff?
	// TODO allow for a "prompt" special case that asks for the pin interactively?
	PIN string `arg:"env:PIN" default:"123456" help:"authentication PIN"` // https://pkg.go.dev/github.com/go-piv/piv-go/v2/piv#DefaultPIN
}
type managementArg struct {
	// TODO add support for reading from a file?  prompt?  see above
	ManagementKey HexString `arg:"env:MANAGEMENT_KEY" help:"management key" default:"010203040506070801020304050607080102030405060708"` // https://pkg.go.dev/github.com/go-piv/piv-go/v2/piv#DefaultManagementKey
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	_ = ctx // TODO use context

	var slogLevel = new(slog.LevelVar) // defaults to Info
	slogHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slogLevel,
	})
	slog.SetDefault(slog.New(slogHandler))

	var args struct {
		List *struct{} `arg:"subcommand:list" help:"list all connected cards (and their serials)"`

		Info *struct {
			cardArg
		} `arg:"subcommand:info" help:"query more information about a specific card (and optionally a slot)"`

		// TODO add a really heinous required flag like `--please-be-destructive=yes` to "generate" (and add a similarly nuclear "reset" subcommand)
		Generate *struct {
			cardArg
			slotArg
			pinArg
			managementArg
		} `arg:"subcommand:generate" help:"generate a new key (WILL OVERWRITE)"`

		Sign *struct {
			cardArg
			slotArg
			pinArg
			Digest HexString `arg:"positional,required" placeholder:"SHA256"`
		} `arg:"subcommand:sign" help:"sign a digest"`
	}
	p, err := arg.NewParser(arg.Config{
		EnvPrefix: "YUBECDSA_",

		Program: os.Args[0],
	}, &args)
	if err != nil {
		log.Fatal(err)
	}
	p.MustParse(os.Args[1:])

	switch {
	default:
		fallthrough // the "list" command is what we should do if we get no explict subcommand
	case args.List != nil:
		// TODO machine-readable output

		cards, err := pivClient.Cards()
		if err != nil {
			log.Fatalf("failed to list cards: %v", err)
		}
		for _, card := range cards {
			serialString := "unknown"
			if yubi, err := pivClient.Open(card); err == nil {
				if serial, err := yubi.Serial(); err == nil {
					serialString = strconv.FormatUint(uint64(serial), 10)
				} // TODO verbose flag for errors?
				yubi.Close()
			} // TODO verbose flag for errors?
			fmt.Printf("%-10s %s\n", serialString, card) // 10 characters is the maximum width of a uint32
		}

	case args.Info != nil:
		// TODO machine-readable output

		sub := args.Info
		yubi := sub.Card
		defer yubi.Close()

		if serial, err := yubi.Serial(); err == nil {
			fmt.Printf("Serial: %d\n", serial)
		} else {
			fmt.Printf("Serial: ERROR: %v\n", err) // TODO errors to logger instead of output?
		}

		v := yubi.Version()
		fmt.Printf("Version: %d.%d.%d\n", v.Major, v.Minor, v.Patch)

		if retries, err := yubi.Retries(); err == nil {
			fmt.Printf("Retries: %d\n", retries)
		} else {
			fmt.Printf("Retries: ERROR: %v\n", err) // TODO errors to logger instead of output?
		}

		// TODO Metadata

		// Go sucks, so without this nonsense expression, the map iteration order is random (my kindom for an order-preserving native map type)
		for _, k := range slices.Sorted(maps.Keys(slotObjectMap)) {
			slot := piv.Slot{Key: uint32(k), Object: slotObjectMap[k]}
			cert, err := yubi.Certificate(slot)
			if err != nil {
				continue // TODO errors to logger? (have to filter "not found" type errors)
			}

			fmt.Printf("Slot %02x certificate public key:\n", slot.Key)
			// TODO better (full) certificate printout like "yubico-piv-tool --action read-certificate --slot 9c | openssl x509 -text"
			// print out public key in PEM format
			pubBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
			if err != nil {
				log.Fatalf("failed to marshal public key for slot %02x: %v", slot.Key, err)
			}
			pem.Encode(os.Stdout, &pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: pubBytes,
			})

			// TODO KeyInfo?
		}

		// TODO subcommand to get *just* the public key of a given slot out of the x509 cert?

	case args.Generate != nil:
		sub := args.Generate
		yubi := sub.Card
		defer yubi.Close()
		slot := piv.Slot(sub.Slot)

		// "GenerateKey" + "SetCertificate" so the public key is retrievable later

		now := time.Now() // store the current time of generation so we can embed it into our x509 (which is all bogus anyhow so this is just informational)
		pub, err := yubi.GenerateKey(sub.ManagementKey, slot, piv.Key{
			// TODO args for all these parameters?
			Algorithm:   piv.AlgorithmEC256,
			PINPolicy:   piv.PINPolicyAlways,
			TouchPolicy: piv.TouchPolicyNever,
		})
		if err != nil {
			log.Fatalf("failed to GenerateKey: %v", err)
		}

		auth := piv.KeyAuth{PIN: sub.PIN}
		priv, err := yubi.PrivateKey(slot, pub, auth)
		if err != nil {
			log.Fatalf("failed to PrivateKey: %v", err)
		}

		cert := &x509.Certificate{
			PublicKey: pub,

			NotBefore: now,
			// TODO Subject?  Issuer?  NotAfter?  KeyUsage?  https://pkg.go.dev/crypto/x509#Certificate
			// TODO maybe we set Issuer to something that identifies yubecdsa as the tool that triggered the key generation? 👀

			// specifying this avoids CreateCertificate using "rand" (which we set to nil below)
			SerialNumber: big.NewInt(0),
		}
		cert.Raw, err = x509.CreateCertificate(nil, cert, cert, pub, priv)
		if err != nil {
			log.Fatalf("failed to CreateCertificate: %v", err)
		}

		err = yubi.SetCertificate(sub.ManagementKey, slot, cert)
		if err != nil {
			log.Fatalf("failed to SetCertificate: %v", err)
		}

		// print out "pub" in PEM format
		pubBytes, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			log.Fatalf("failed to marshal public key: %v", err)
		}
		pem.Encode(os.Stdout, &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubBytes,
		})

	case args.Sign != nil:
		sub := args.Sign
		yubi := sub.Card
		defer yubi.Close()
		slot := piv.Slot(sub.Slot)

		// TODO get cert earlier and just make sure our hash is at most as many bytes as our algorithm can handle?  ie, P-256 can handle at most 32 (256/8), but P-384 can handle up to 48 (384/8), and eventually Yubi might support P-521 which can handle up to 65 bytes (just slightly bigger than 512) -- see "pubKey.Params().BitSize"
		if len(sub.Digest) != 32 {
			p.FailSubcommand(fmt.Sprintf("digest must be exactly 32 bytes (not %d)", len(sub.Digest)), "sign")
		}

		auth := piv.KeyAuth{PIN: sub.PIN}

		// we need a public key so that it knows which algorithm to use -- we'll try querying the corresponding certificate from the key and use that if it exists, but otherwise we'll fall back to something fake that hard-codes ECDSA P-256
		var pub any
		if cert, err := yubi.Certificate(slot); err == nil {
			pub = cert.PublicKey
		} else {
			// the public key is used primarily for determining what kind of signature we're trying to make (https://github.com/go-piv/piv-go/blob/2fae46569ad594c2c4bdd57f696967ac396e1d5e/v2/piv/key.go#L1000) and the bit size / algorithm to use (https://github.com/go-piv/piv-go/blob/2fae46569ad594c2c4bdd57f696967ac396e1d5e/v2/piv/key.go#L1330)
			pub = &ecdsa.PublicKey{
				Curve: elliptic.P256(),
			}
		}

		priv, err := yubi.PrivateKey(slot, pub, auth)
		if err != nil {
			log.Fatalf("failed to PrivateKey: %v", err)
		}

		signer, ok := priv.(crypto.Signer)
		if !ok {
			panic("piv library returned something that is not a Signer")
		}

		// we provide a nil rand reader because the on-device RNG should be used instead
		signature, err := signer.Sign(nil, sub.Digest, nil)
		if err != nil {
			log.Fatalf("failed to Sign: %v", err)
		}

		fmt.Println(base64.StdEncoding.EncodeToString(signature))
	}
}
