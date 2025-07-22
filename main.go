package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"log/slog"
	"math/big"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/alexflint/go-arg"
	"pault.ag/go/ykpiv"
)

// a helper for "ykpiv.New" that supports either a card string like "opensc-tool --list-readers" outputs ("Yubico YubiKey CCID 00 00") or a serial number ("NNNNNN") via linear search (yes, horrifying, but we have no choice because we have to open a card to check the serial number)
func open(cardOrSerial string, opts ykpiv.Options) (*ykpiv.Yubikey, error) {
	opts.Reader = cardOrSerial
	yubi, topErr := ykpiv.New(opts)
	if topErr == nil {
		return yubi, nil
	}

	// only continue if cardOrSerial is numeric (serials are uint32)
	lookingForSerial64, err := strconv.ParseUint(cardOrSerial, 10, 32)
	if err != nil {
		return nil, err
	}
	lookingForSerial := uint32(lookingForSerial64)

	cards, err := ykpiv.Readers()
	if err != nil {
		return nil, err
	}

	// if "lookingForSerial" is less than len(cards), it's probably an index like "0", "1", etc
	if int(lookingForSerial) < len(cards) {
		opts.Reader = cards[lookingForSerial]
		return ykpiv.New(opts)
	}

	for _, opts.Reader = range cards {
		if yubi, err := ykpiv.New(opts); err == nil {
			if serial, err := yubi.Serial(); err == nil && serial == lookingForSerial {
				return yubi, nil
			}
			yubi.Close()
		}
	}

	return nil, topErr
}

type Slot ykpiv.SlotId

func (s *Slot) UnmarshalText(b []byte) error {
	slotKey, err := strconv.ParseUint(string(b), 16, 8) // "9c", etc
	if err != nil {
		return err
	}
	object, ok := slotObjectMap[uint8(slotKey)]
	if !ok {
		return fmt.Errorf("'%02x' is not a valid slot for ECDSA", slotKey)
	}
	s.Key = int32(slotKey)
	s.Certificate = int32(object)
	s.Name = fmt.Sprintf("slot %02x", slotKey) // TODO add Name to slot-map.go if we commit to ykpiv
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
	Card string `arg:"required,env:CARD" help:"selected card; serial number ('12345'), card string ('Yubico YubiKey CCID 00 00'), or index ('0')"`
}
type slotArg struct {
	Slot Slot `arg:"required,env:SLOT" help:"selected slot ('9c', etc)"`
}
type pinArg struct {
	// TODO add support for reading PIN from a file?  maybe have this create/provide a KeyAuth struct directly with a suitable PINPrompt so it can pull up a file's contents?  look at more weird go-arg stuff?
	// TODO allow for a "prompt" special case that asks for the pin interactively?
	PIN string `arg:"env:PIN" default:"123456" help:"authentication PIN"` // https://pkg.go.dev/github.com/go-piv/piv-go/v2/piv#DefaultPIN
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

		Generate *struct {
			cardArg
			slotArg
			pinArg
			// TODO management key?
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

		cards, err := ykpiv.Readers()
		if err != nil {
			log.Fatalf("failed to list cards: %v", err)
		}
		for _, card := range cards {
			serialString := "unknown"
			if yubi, err := ykpiv.New(ykpiv.Options{Reader: card}); err == nil {
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
		yubi, err := open(sub.Card, ykpiv.Options{})
		if err != nil {
			p.FailSubcommand(err.Error(), "info")
		}
		defer yubi.Close()

		if serial, err := yubi.Serial(); err == nil {
			fmt.Printf("Serial: %d\n", serial)
		} else {
			fmt.Printf("Serial: ERROR: %v\n", err) // TODO errors to logger instead of output?
		}

		if v, err := yubi.Version(); err == nil {
			fmt.Printf("Version: %s\n", string(v))
		} else {
			fmt.Printf("Version: ERROR: %v\n", err) // TODO errors to logger instead of output?
		}

		if retries, err := yubi.PINRetries(); err == nil {
			fmt.Printf("Retries: %d\n", retries)
		} else {
			fmt.Printf("Retries: ERROR: %v\n", err) // TODO errors to logger instead of output?
		}

		// TODO Metadata

		// TODO Go sucks, so this map order is gonna be random (my kindom for an order-preserving native map type)
		for k, o := range slotObjectMap {
			slot := ykpiv.SlotId{Key: int32(k), Certificate: int32(o), Name: fmt.Sprintf("slot %02x", k)} // TODO name in slotObjectMap
			cert, err := yubi.GetCertificate(slot)
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
		yubi, err := open(sub.Card, ykpiv.Options{PIN: &sub.PIN})
		if err != nil {
			p.FailSubcommand(err.Error(), "info")
		}
		defer yubi.Close()
		slot := ykpiv.SlotId(sub.Slot)

		// TODO var managementKey []byte = piv.DefaultManagementKey // TODO user-specifiable

		// "GenerateKey" + "SetCertificate" so the public key is retrievable later

		now := time.Now() // store the current time of generation so we can embed it into our x509 (which is all bogus anyhow so this is just informational)
		// TODO args for these parameters?
		slotObj, err := yubi.GenerateECWithPolicies(slot, 256, ykpiv.PinPolicyAlways, ykpiv.TouchPolicyNever)
		if err != nil {
			log.Fatalf("failed to GenerateKey: %v", err)
		}
		pub := slotObj.PublicKey

		cert := &x509.Certificate{
			PublicKey: pub,

			NotBefore: now,
			// TODO Subject?  Issuer?  NotAfter?  KeyUsage?  https://pkg.go.dev/crypto/x509#Certificate

			// specifying this avoids CreateCertificate using "rand" (which we set to nil below)
			SerialNumber: big.NewInt(0),
		}
		cert.Raw, err = x509.CreateCertificate(nil, cert, cert, pub, slotObj)
		if err != nil {
			log.Fatalf("failed to CreateCertificate: %v", err)
		}

		err = slotObj.Update(*cert)
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
		yubi, err := open(sub.Card, ykpiv.Options{PIN: &sub.PIN, ManagementKey: []byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		}})
		if err != nil {
			p.FailSubcommand(err.Error(), "info")
		}
		defer yubi.Close()
		slot := ykpiv.SlotId(sub.Slot)

		// TODO get cert earlier and just make sure our hash is at most as many bytes as our algorithm can handle?  ie, P-256 can handle at most 32 (256/8), but P-384 can handle up to 48 (384/8), and eventually Yubi might support P-521 which can handle up to 65 bytes (just slightly bigger than 512) -- see "pubKey.Params().BitSize"
		if len(sub.Digest) != 32 {
			p.FailSubcommand(fmt.Sprintf("digest must be exactly 32 bytes (not %d)", len(sub.Digest)), "sign")
		}

		slotObj, err := yubi.Slot(slot)
		if err != nil {
			log.Fatalf("failed to Slot: %v", err)
		}

		// we provide a nil rand reader because the on-device RNG should be used instead
		signature, err := slotObj.Sign(nil, sub.Digest, nil)
		if err != nil {
			log.Fatalf("failed to Sign: %v", err)
		}

		fmt.Println(base64.StdEncoding.EncodeToString(signature))
	}
}
