package main

//go:generate zenrpc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/semrush/zenrpc"
	"log"
	"math/big"
	"net/http"
	"os"
	"sort"
)

type Config struct {
	ValidPublicKeys []string
	ListenAddress   string
}

var config Config

func InitConfig() bool {
	_, err := toml.DecodeFile("./config.toml", &config)
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

func (s SignatureVerifyService) GetAllPublicKey() ([]string, error) {
	return config.ValidPublicKeys, nil
}

func (s SignatureVerifyService) IsValidPublicKey(hexPublicKey string) bool {
	i := sort.SearchStrings(config.ValidPublicKeys, hexPublicKey)
	if i < len(config.ValidPublicKeys) && config.ValidPublicKeys[i] == hexPublicKey {
		return true
	} else {
		return false
	}
}

func (s SignatureVerifyService) SignatureVerifySha256(data string, hexSignature string, hexPublicKey string) (bool, error) {

	if s.IsValidPublicKey(hexPublicKey) == false {
		return false, nil
	}

	publicKey, err := UnmarshalPubkey(hexPublicKey)
	if err != nil {
		return false, err
	}

	hash := sha256.Sum256([]byte(data))

	signature, err := hex.DecodeString(hexSignature)
	if err != nil {
		return false, err
	}

	if len(signature) > 64 {
		signature = signature[:64]
	}

	result := Verify(hash[:], signature, publicKey)

	return result, nil
}

func (s SignatureVerifyService) SignatureVerify(hexData string, hexSignature string, hexPublicKey string) (bool, error) {

	if s.IsValidPublicKey(hexPublicKey) == false {
		return false, nil
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

	//hexData := "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
	//hexSignature := "35215044a33db08a980b27d3fa4d35207653be6a21307ac3298bef211aa777e015e7185757ded69c23cb8bbce85fc9ed2e41e1dbf13cea08175ffdabc0231b57"
	//hexPublicKey := "04bc59533025bafae89863f729d907b2d301642a471e7a1bb7b578f6bf2ccd21c2201e51f263e3656254bcc497bab50156600be7c33830e407df2910eff878a331"
	//
	//result,err := SignatureVerifyService{}.SignatureVerify(hexData,hexSignature,hexPublicKey)
	//fmt.Printf("err: %v, result: %v\n",err,result)

	rpc := zenrpc.NewServer(zenrpc.Options{ExposeSMD: true})
	rpc.Register("", SignatureVerifyService{})
	rpc.Use(zenrpc.Logger(log.New(os.Stderr, "", log.LstdFlags)))

	http.Handle("/signature_verify_service", rpc)

	log.Printf("starting arithsrv on %s", config.ListenAddress)
	log.Fatal(http.ListenAndServe(config.ListenAddress, nil))
}
