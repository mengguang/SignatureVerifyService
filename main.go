package main

//go:generate zenrpc

import (
	"github.com/semrush/zenrpc"
	"os"
	"log"
	"net/http"
	"crypto/ecdsa"
	"math/big"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"sort"
	"fmt"
	"github.com/BurntSushi/toml"
)

type Config struct {
	ValidPublicKeys []string
	ListenAddress string
}

var config Config

func IsValidPublicKey(hexPublicKey string) bool {
	i := sort.SearchStrings(config.ValidPublicKeys,hexPublicKey)
	if i < len(config.ValidPublicKeys) && config.ValidPublicKeys[i] == hexPublicKey {
		return true
	} else {
		return false
	}
}

func InitConfig() bool {
	_, err := toml.DecodeFile("./config.toml",&config)
	if err != nil {
		fmt.Println(err)
		return false
	}
	sort.Strings(config.ValidPublicKeys)
	fmt.Println(config.ValidPublicKeys)
	return true
}

// Verify checks a raw ECDSA signature.
// Returns true if it's valid and false if not.
func Verify(data, signature []byte, pubkey *ecdsa.PublicKey) bool {
	digest := make([]byte, 32)
	copy(digest, data)

	curveOrderByteSize := pubkey.Curve.Params().P.BitLen() / 8

	r, s := new(big.Int), new(big.Int)
	r.SetBytes(signature[:curveOrderByteSize])
	s.SetBytes(signature[curveOrderByteSize:])

	return ecdsa.Verify(pubkey, digest, r, s)
}

// UnmarshalPubkey converts bytes to a secp256r1 public key.
// pub[0] == 4
func UnmarshalPubkey(hexPub string) (*ecdsa.PublicKey, error) {
	b, err := hex.DecodeString(hexPub)
	if err != nil {
		return nil, errors.New("invalid hex string")
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), b)
	if x == nil {
		return nil, errors.New("invalid public key")
	}

	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

type SignatureVerifyService struct{ zenrpc.Service }

func (s SignatureVerifyService) SignatureVerify(hexData string, hexSignature string, hexPublicKey string) (bool, error) {

	if IsValidPublicKey(hexPublicKey) == false {
		return false,nil
	}

	publicKey, err := UnmarshalPubkey(hexPublicKey)
	if err != nil {
		return false, err
	}

	data, err := hex.DecodeString(hexData)
	if err != nil {
		return false, err
	}

	signature, err := hex.DecodeString(hexSignature)
	if err != nil {
		return false, err
	}

	if len(signature) > 64 {
		signature = signature[:64]
	}

	result := Verify(data, signature, publicKey)

	return result, nil
}

func main() {

	InitConfig()

	//hexData := "09CA7E4EAA6E8AE9C7D261167129184883644D07DFBA7CBFBC4C8A2E08360D5B"
	//hexSignature := "61D7A05A330263D4E097272621FFC3A642DB7E77FC595C0A50EE31CB1AF9D0862BC21BA93321D39CCE0501884E9E288B43CE763B3B9A95326C8926DB7F31971801"
	//hexPublicKey := "0495A2B34A43E229414642780F85C34C3C880D0C7F579012AA57AE82E090DB7E795CF7BCE19180B11487246D80C1CB249FA3AC9181A22374AA0525592C97CC4B48"
	//
	//result,err := SignatureVerifyService{}.SignatureVerify(hexData,hexSignature,hexPublicKey)
	//fmt.Printf("err: %v, result: %v\n",err,result)

	rpc := zenrpc.NewServer(zenrpc.Options{ExposeSMD: true})
	rpc.Register("", SignatureVerifyService{}) // public
	rpc.Use(zenrpc.Logger(log.New(os.Stderr, "", log.LstdFlags)))

	http.Handle("/", rpc)

	log.Printf("starting arithsrv on %s", config.ListenAddress)
	log.Fatal(http.ListenAndServe(config.ListenAddress, nil))
}
