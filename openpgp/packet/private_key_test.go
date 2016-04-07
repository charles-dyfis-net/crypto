// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"
)

type TestSigner struct {
	expectedDigest []byte
	returnSig      []byte
	invokedFlag    *bool
}

func (s TestSigner) Public() crypto.PublicKey {
	return nil
}

func (s TestSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	*s.invokedFlag = true
	if bytes.Compare(s.expectedDigest, digest) == 0 {
		return s.returnSig, nil
	} else {
		return nil, fmt.Errorf("Unexpected digest seen: Expected +%v, got %+v", s.expectedDigest, digest)
	}
}

func TestExternalSigRSA(t *testing.T) {
	externalSigWasRun := false

	testDigestExpected, err := hex.DecodeString(testDigestExpectedHexRSA)
	if err != nil {
		fmt.Errorf("Unable to set up test: expected-digest value not hex")
		return
	}
	testRSASignatureReturned := []byte(testRSASignatureReturnedStr)

	packet, err := Read(readerFromHex(privKeyRSAHex))
	if err != nil {
		t.Errorf("failed to parse: %s", err)
		return
	}
	privKey := packet.(*PrivateKey)
	privKey.Encrypted = false
	privKey.PrivateKey = nil
	privKey.ExternalSigner = &TestSigner{
		expectedDigest: testDigestExpected,
		returnSig:      testRSASignatureReturned,
		invokedFlag:    &externalSigWasRun,
	}

	config := Config{}

	sig := &Signature{
		SigType:      SigTypeBinary,
		PubKeyAlgo:   privKey.PublicKey.PubKeyAlgo,
		Hash:         crypto.SHA256,
		CreationTime: time.Unix(testSigCreationTime, 0),
		IssuerKeyId:  &privKey.PublicKey.KeyId,
	}

	hash := sig.Hash.New()
	io.Copy(hash, strings.NewReader(testMessageContent))

	err = sig.Sign(hash, privKey, &config)
	if err != nil {
		t.Errorf("Error returned by signing function: %s", err)
		return
	}

	if bytes.Compare(sig.RSASignature.bytes, testRSASignatureReturned) != 0 {
		t.Error("Content returned by external function not honored")
		return
	}

	if externalSigWasRun == false {
		t.Errorf("External signing function not run")
	}

}

func TestExternalSigDSA(t *testing.T) {

	testDigestExpected, err := hex.DecodeString(testDigestExpectedHexDSA)
	if err != nil {
		t.Fatalf("Test setup: expected-digest value not hex: %s", err)
	}

	type asn1Signature struct {
		R, S *big.Int
	}
	testSig := new(asn1Signature)
	testSig.R = big.NewInt(testDSAsigR)
	testSig.S = big.NewInt(testDSAsigS)
	testSigBytes, err := asn1.Marshal(*testSig)
	if err != nil {
		t.Fatalf("Test setup: Unable to generate ASN.1 dummy signature: %s", err)
	}

	externalSigWasRun := false

	config := Config{}
	var params dsa.Parameters
	err = dsa.GenerateParameters(&params, config.Random(), dsa.L1024N160)
	if err != nil {
		t.Fatal(err)
	}
	var dsaPrivKey dsa.PrivateKey
	dsaPrivKey.Parameters = params
	err = dsa.GenerateKey(&dsaPrivKey, config.Random())
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := NewDSAPrivateKey(time.Unix(testSigCreationTime, 0), &dsaPrivKey).Serialize(&buf); err != nil {
		t.Fatal(err)
	}

	p, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}

	privKey, ok := p.(*PrivateKey)
	if !ok {
		t.Fatal("didn't parse private key")
	}
	privKey.ExternalSigner = &TestSigner{
		expectedDigest: testDigestExpected,
		returnSig:      testSigBytes,
		invokedFlag:    &externalSigWasRun,
	}

	// FIXME: Need to make IssuerKeyId constant?
	sig := &Signature{
		SigType:      SigTypeBinary,
		PubKeyAlgo:   PubKeyAlgoDSA,
		Hash:         crypto.SHA256,
		CreationTime: time.Unix(testSigCreationTime, 0),
	}

	hash := sig.Hash.New()
	io.Copy(hash, strings.NewReader(testMessageContent))

	err = sig.Sign(hash, privKey, &config)
	if err != nil {
		t.Fatalf("Error returned by signing function: %s", err)
	}

	rMPI := fromBig(testSig.R)
	sMPI := fromBig(testSig.S)
	if bytes.Compare(sig.DSASigR.bytes, rMPI.bytes) != 0 {
		t.Errorf("R value returned by external function not honored (expected %+v, got %+v)", rMPI.bytes, sig.DSASigR.bytes)
	}
	if bytes.Compare(sig.DSASigS.bytes, sMPI.bytes) != 0 {
		t.Errorf("S value returned by external function not honored (expected +%v, got %+v)", sMPI.bytes, sig.DSASigS.bytes)
	}

	if externalSigWasRun == false {
		t.Errorf("External signing function not run")
	}

}

func TestExternalSigECDSA(t *testing.T) {

	testDigestExpected, err := hex.DecodeString(testDigestExpectedHexECDSA)
	if err != nil {
		t.Fatalf("Test setup: expected-digest value not hex: %s", err)
	}

	type asn1Signature struct {
		R, S *big.Int
	}
	testSig := new(asn1Signature)
	testSig.R = big.NewInt(testDSAsigR)
	testSig.S = big.NewInt(testDSAsigS)
	testSigBytes, err := asn1.Marshal(*testSig)
	if err != nil {
		t.Fatalf("Test setup: Unable to generate ASN.1 dummy signature: %s", err)
	}

	externalSigWasRun := false

	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := NewECDSAPrivateKey(time.Now(), ecdsaPriv).Serialize(&buf); err != nil {
		t.Fatal(err)
	}

	p, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}

	privKey, ok := p.(*PrivateKey)
	if !ok {
		t.Fatal("didn't parse private key")
	}
	privKey.ExternalSigner = &TestSigner{
		expectedDigest: testDigestExpected,
		returnSig:      testSigBytes,
		invokedFlag:    &externalSigWasRun,
	}

	// FIXME: Need to make IssuerKeyId constant?
	sig := &Signature{
		SigType:      SigTypeBinary,
		PubKeyAlgo:   PubKeyAlgoECDSA,
		Hash:         crypto.SHA256,
		CreationTime: time.Unix(testSigCreationTime, 0),
	}

	hash := sig.Hash.New()
	io.Copy(hash, strings.NewReader(testMessageContent))

	config := Config{}
	err = sig.Sign(hash, privKey, &config)
	if err != nil {
		t.Fatalf("Error returned by signing function: %s", err)
	}

	rMPI := fromBig(testSig.R)
	sMPI := fromBig(testSig.S)
	if bytes.Compare(sig.ECDSASigR.bytes, rMPI.bytes) != 0 {
		t.Errorf("R value returned by external function not honored (expected %+v, got %+v)", rMPI.bytes, sig.DSASigR.bytes)
	}
	if bytes.Compare(sig.ECDSASigS.bytes, sMPI.bytes) != 0 {
		t.Errorf("S value returned by external function not honored (expected +%v, got %+v)", sMPI.bytes, sig.DSASigS.bytes)
	}

	if externalSigWasRun == false {
		t.Errorf("External signing function not run")
	}

}

var privateKeyTests = []struct {
	privateKeyHex string
	creationTime  time.Time
}{
	{
		privKeyRSAHex,
		time.Unix(0x4cc349a8, 0),
	},
	{
		privKeyElGamalHex,
		time.Unix(0x4df9ee1a, 0),
	},
}

func TestPrivateKeyRead(t *testing.T) {
	for i, test := range privateKeyTests {
		packet, err := Read(readerFromHex(test.privateKeyHex))
		if err != nil {
			t.Errorf("#%d: failed to parse: %s", i, err)
			continue
		}

		privKey := packet.(*PrivateKey)

		if !privKey.Encrypted {
			t.Errorf("#%d: private key isn't encrypted", i)
			continue
		}

		err = privKey.Decrypt([]byte("wrong password"))
		if err == nil {
			t.Errorf("#%d: decrypted with incorrect key", i)
			continue
		}

		err = privKey.Decrypt([]byte("testing"))
		if err != nil {
			t.Errorf("#%d: failed to decrypt: %s", i, err)
			continue
		}

		if !privKey.CreationTime.Equal(test.creationTime) || privKey.Encrypted {
			t.Errorf("#%d: bad result, got: %#v", i, privKey)
		}
	}
}

func populateHash(hashFunc crypto.Hash, msg []byte) (hash.Hash, error) {
	h := hashFunc.New()
	if _, err := h.Write(msg); err != nil {
		return nil, err
	}
	return h, nil
}

func TestECDSAPrivateKey(t *testing.T) {
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := NewECDSAPrivateKey(time.Now(), ecdsaPriv).Serialize(&buf); err != nil {
		t.Fatal(err)
	}

	p, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}

	priv, ok := p.(*PrivateKey)
	if !ok {
		t.Fatal("didn't parse private key")
	}

	sig := &Signature{
		PubKeyAlgo: PubKeyAlgoECDSA,
		Hash:       crypto.SHA256,
	}
	msg := []byte("Hello World!")

	h, err := populateHash(sig.Hash, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := sig.Sign(h, priv, nil); err != nil {
		t.Fatal(err)
	}

	if h, err = populateHash(sig.Hash, msg); err != nil {
		t.Fatal(err)
	}
	if err := priv.VerifySignature(h, sig); err != nil {
		t.Fatal(err)
	}
}

func TestIssue11505(t *testing.T) {
	// parsing a rsa private key with p or q == 1 used to panic due to a divide by zero
	_, _ = Read(readerFromHex("9c3004303030300100000011303030000000000000010130303030303030303030303030303030303030303030303030303030303030303030303030303030303030"))
}

// Generated with `gpg --export-secret-keys "Test Key 2"`
const privKeyRSAHex = "9501fe044cc349a8010400b70ca0010e98c090008d45d1ee8f9113bd5861fd57b88bacb7c68658747663f1e1a3b5a98f32fda6472373c024b97359cd2efc88ff60f77751adfbf6af5e615e6a1408cfad8bf0cea30b0d5f53aa27ad59089ba9b15b7ebc2777a25d7b436144027e3bcd203909f147d0e332b240cf63d3395f5dfe0df0a6c04e8655af7eacdf0011010001fe0303024a252e7d475fd445607de39a265472aa74a9320ba2dac395faa687e9e0336aeb7e9a7397e511b5afd9dc84557c80ac0f3d4d7bfec5ae16f20d41c8c84a04552a33870b930420e230e179564f6d19bb153145e76c33ae993886c388832b0fa042ddda7f133924f3854481533e0ede31d51278c0519b29abc3bf53da673e13e3e1214b52413d179d7f66deee35cac8eacb060f78379d70ef4af8607e68131ff529439668fc39c9ce6dfef8a5ac234d234802cbfb749a26107db26406213ae5c06d4673253a3cbee1fcbae58d6ab77e38d6e2c0e7c6317c48e054edadb5a40d0d48acb44643d998139a8a66bb820be1f3f80185bc777d14b5954b60effe2448a036d565c6bc0b915fcea518acdd20ab07bc1529f561c58cd044f723109b93f6fd99f876ff891d64306b5d08f48bab59f38695e9109c4dec34013ba3153488ce070268381ba923ee1eb77125b36afcb4347ec3478c8f2735b06ef17351d872e577fa95d0c397c88c71b59629a36aec"

const testMessageContent = "Signed Content"
const testSigCreationTime = 80352345 // timestamp of golang "Hello World" commit
const testDigestExpectedHexRSA = "b8baada425fde377a1f342df0c936ff26a21cee84fe2052acd852df590fdbef3"
const testDigestExpectedHexDSA = "669ecbc624417360024e1cd98b3cbde2e18d741807df4f5673c42f363393c32a"
const testDigestExpectedHexECDSA = "7b156c02be031b33b54f6c2788fe9fa7cd1fad2e1dcb63026f458d9596c66f57"

// Intentionally using a bad value here to ensure that the external implementation is trusted
const testRSASignatureReturnedStr = "Fake Signature"

// Likewise
const testDSAsigR = 31337
const testDSAsigS = 41443

// Generated by `gpg --export-secret-keys` followed by a manual extraction of
// the ElGamal subkey from the packets.
const privKeyElGamalHex = "9d0157044df9ee1a100400eb8e136a58ec39b582629cdadf830bc64e0a94ed8103ca8bb247b27b11b46d1d25297ef4bcc3071785ba0c0bedfe89eabc5287fcc0edf81ab5896c1c8e4b20d27d79813c7aede75320b33eaeeaa586edc00fd1036c10133e6ba0ff277245d0d59d04b2b3421b7244aca5f4a8d870c6f1c1fbff9e1c26699a860b9504f35ca1d700030503fd1ededd3b840795be6d9ccbe3c51ee42e2f39233c432b831ddd9c4e72b7025a819317e47bf94f9ee316d7273b05d5fcf2999c3a681f519b1234bbfa6d359b4752bd9c3f77d6b6456cde152464763414ca130f4e91d91041432f90620fec0e6d6b5116076c2985d5aeaae13be492b9b329efcaf7ee25120159a0a30cd976b42d7afe030302dae7eb80db744d4960c4df930d57e87fe81412eaace9f900e6c839817a614ddb75ba6603b9417c33ea7b6c93967dfa2bcff3fa3c74a5ce2c962db65b03aece14c96cbd0038fc"
