package saltpack_test

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/keybase/saltpack"
	"github.com/keybase/saltpack/basic"
	"github.com/stretchr/testify/require"
)

func RawBoxKeyFromSigningKey(signingKey basic.SigningSecretKey) (*[32]byte, *[32]byte) {
	rawSigningKey := signingKey.GetRawSecretKey()
	signingKeyBytes := rawSigningKey[:]
	boxPrivateKeyBytes := Ed25519PrivateKeyToCurve25519(signingKeyBytes) // convert to curve25519 private key\
	boxPrivateKeyBytes32 := new([32]byte)
	copy(boxPrivateKeyBytes32[:], boxPrivateKeyBytes[:])

	rawPublicKeyBytes := signingKey.GetPublicKey().ToKID()
	boxPublicKeyBytes := Ed25519PublicKeyToCurve25519(rawPublicKeyBytes) // convert to curve25519 public key
	boxPublicKeyBytes32 := new([32]byte)
	copy(boxPublicKeyBytes32[:], boxPublicKeyBytes[:])

	return boxPrivateKeyBytes32, boxPublicKeyBytes32
}

// workaround using kr.ImportSigningKey due to the fact that kr.GenerateSigningKey(), contrary to the documentation
// does not add the signing key to the keyring
func AddSigningKeyToKeyring(kr *basic.Keyring, signingKey basic.SigningSecretKey) {
	privBytes64 := signingKey.GetRawSecretKey()
	pubBytes := signingKey.GetPublicKey().ToKID()
	pubBytes32 := [32]byte(pubBytes[:])
	kr.ImportSigningKey(&pubBytes32, privBytes64)
}

func TestSignCryptWithKeyConversion(t *testing.T) {
	msg := []byte("hello world")

	// recipients

	//recipient 1
	recipient1Kr := basic.NewKeyring()
	sk1, err := recipient1Kr.GenerateSigningKey()
	AddSigningKeyToKeyring(recipient1Kr, *sk1)

	require.NoError(t, err)
	// signing key is the basis for the box key
	bk1PrivBytes, bk1PubBytes := RawBoxKeyFromSigningKey(*sk1)
	recipient1Kr.ImportBoxKey(bk1PrivBytes, bk1PubBytes)
	bk1 := recipient1Kr.GetAllBoxSecretKeys()[0]
	require.NoError(t, err)

	// recipient 2
	recipient2Kr := basic.NewKeyring()
	sk2, err := recipient2Kr.GenerateSigningKey()
	require.NoError(t, err)
	AddSigningKeyToKeyring(recipient2Kr, *sk2)
	// signing key is the basis for the box key
	bk2PrivBytes, bk2PubBytes := RawBoxKeyFromSigningKey(*sk2)
	recipient2Kr.ImportBoxKey(bk2PrivBytes, bk2PubBytes)
	bk2 := recipient2Kr.GetAllBoxSecretKeys()[0]

	// sender
	senderKr := basic.NewKeyring()
	// signing key is the basis for the encryption key
	senderSk, err := senderKr.GenerateSigningKey()
	require.NoError(t, err)
	AddSigningKeyToKeyring(senderKr, *senderSk)
	rawEncKeyPrivateBytes, rawEncKeyPublicBytes := RawBoxKeyFromSigningKey(*senderSk)
	senderKr.ImportBoxKey(rawEncKeyPrivateBytes, rawEncKeyPublicBytes)

	receiverBoxKeys := []saltpack.BoxPublicKey{
		bk1.GetPublicKey(),
		bk2.GetPublicKey(),
	}

	// signcrypt

	sealed, err := saltpack.SigncryptSeal(msg, senderKr, senderSk, receiverBoxKeys, nil)
	require.NoError(t, err)
	require.NotNil(t, sealed)

	// now decrypt and verify

	senderPub, opened, err := saltpack.SigncryptOpen(sealed, recipient1Kr, nil)
	require.NoError(t, err)
	require.Equal(t, senderSk.GetPublicKey(), senderPub)
	require.Equal(t, msg, opened)
}

func TestSigncrypt(t *testing.T) {
	msg := []byte("hello world")

	// recipients
	recipient1Kr := basic.NewKeyring()
	bk1, err := recipient1Kr.GenerateBoxKey()
	require.NoError(t, err)

	recipient2Kr := basic.NewKeyring()
	bk2, err := recipient2Kr.GenerateBoxKey()
	require.NoError(t, err)

	// sender
	senderKr := basic.NewKeyring()
	senderSk, err := senderKr.GenerateSigningKey()
	require.NoError(t, err)

	receiverBoxKeys := []saltpack.BoxPublicKey{
		bk1.GetPublicKey(),
		bk2.GetPublicKey(),
	}

	// signcrypt

	sealed, err := saltpack.SigncryptSeal(msg, senderKr, senderSk, receiverBoxKeys, nil)
	require.NoError(t, err)
	require.NotNil(t, sealed)

	// now decrypt and verify

	senderPub, opened, err := saltpack.SigncryptOpen(sealed, recipient1Kr, nil)
	require.NoError(t, err)
	require.Equal(t, senderSk.GetPublicKey(), senderPub)
	require.Equal(t, msg, opened)
}

func ExampleEncryptArmor62Seal() {
	var err error

	// Make a new Keyring, initialized to be empty
	keyring := basic.NewKeyring()

	// The test message
	msg := []byte("The Magic Words are Squeamish Ossifrage")

	// Make a secret key for the sender
	var sender saltpack.BoxSecretKey
	sender, err = keyring.GenerateBoxKey()
	if err != nil {
		return
	}

	// new keyring for the receiver
	keyring2 := basic.NewKeyring()
	// And one for the receiver
	var receiver saltpack.BoxSecretKey
	receiver, err = keyring2.GenerateBoxKey()
	if err != nil {
		return
	}

	publicKeyBytes := receiver.GetPublicKey().ToRawBoxKeyPointer()

	publicKey := basic.PublicKey{
		RawBoxKey: *publicKeyBytes,
	}

	// AllReceivers can contain more receivers (like the sender)
	// but for now, just the one.
	var ciphertext string
	allReceivers := []saltpack.BoxPublicKey{publicKey}
	ciphertext, err = saltpack.EncryptArmor62Seal(saltpack.CurrentVersion(), msg, sender, allReceivers, "")
	if err != nil {
		return
	}

	// The decrypted message should match the input mesasge.
	var msg2 []byte
	_, msg2, _, err = saltpack.Dearmor62DecryptOpen(saltpack.CheckKnownMajorVersion, ciphertext, keyring2)
	if err != nil {
		return
	}

	fmt.Println(string(msg2))

	// Output:
	// The Magic Words are Squeamish Ossifrage
}

func ExampleNewEncryptArmor62Stream() {

	var err error

	// Make a new Keyring, initialized to be empty
	keyring := basic.NewKeyring()

	// The test message
	plaintext := "The Magic Words are Squeamish Ossifrage"

	// Make a secret key for the sender
	var sender saltpack.BoxSecretKey
	sender, err = keyring.GenerateBoxKey()
	if err != nil {
		return
	}

	// And one for the receiver
	var receiver saltpack.BoxSecretKey
	receiver, err = keyring.GenerateBoxKey()
	if err != nil {
		return
	}

	// AllReceivers can contain more receivers (like the sender)
	// but for now, just the one.
	var output bytes.Buffer
	allReceivers := []saltpack.BoxPublicKey{receiver.GetPublicKey()}
	var input io.WriteCloser
	input, err = saltpack.NewEncryptArmor62Stream(saltpack.CurrentVersion(), &output, sender, allReceivers, "")
	if err != nil {
		return
	}
	// Write plaintext into the returned WriteCloser stream
	_, err = input.Write([]byte(plaintext))
	if err != nil {
		return
	}
	// And close when we're done
	input.Close()

	// The decrypted message
	var plaintextOutput io.Reader
	_, plaintextOutput, _, err = saltpack.NewDearmor62DecryptStream(saltpack.CheckKnownMajorVersion, &output, keyring)
	if err != nil {
		return
	}

	// Copy all of the data out of the output decrypted stream, and into standard
	// output, here for testing / comparison purposes.
	_, err = io.Copy(os.Stdout, plaintextOutput)
	if err != nil {
		return
	}
	os.Stdout.Write([]byte{'\n'})

	// Output:
	// The Magic Words are Squeamish Ossifrage
}

func ExampleSignArmor62() {

	var err error

	// Make a new Keyring, initialized to be empty
	keyring := basic.NewKeyring()

	// The test message
	msg := []byte("The Magic Words are Squeamish Ossifrage")

	// Make a secret key for the sender
	var signer saltpack.SigningSecretKey
	signer, err = keyring.GenerateSigningKey()
	if err != nil {
		return
	}

	var signed string
	signed, err = saltpack.SignArmor62(saltpack.CurrentVersion(), msg, signer, "")
	if err != nil {
		return
	}

	// The verified message should match the input mesasge.
	var verifiedMsg []byte
	var signingPublicKey saltpack.SigningPublicKey
	signingPublicKey, verifiedMsg, _, err = saltpack.Dearmor62Verify(saltpack.CheckKnownMajorVersion, signed, keyring)
	if err != nil {
		return
	}

	if saltpack.PublicKeyEqual(signingPublicKey, signer.GetPublicKey()) {
		fmt.Println("The right key")
	}

	fmt.Println(string(verifiedMsg))

	// Output:
	// The right key
	// The Magic Words are Squeamish Ossifrage
}

func ExampleNewSignArmor62Stream() {

	var err error

	// Make a new Keyring, initialized to be empty
	keyring := basic.NewKeyring()

	// The test message
	msg := []byte("The Magic Words are Squeamish Ossifrage")

	// Make a secret key for the sender
	var signer saltpack.SigningSecretKey
	signer, err = keyring.GenerateSigningKey()
	if err != nil {
		return
	}

	// Make a new signature stream. We write the input data into
	// the input stream, and we read output out of the output stream.
	// In this case, the output stream is just a buffer.
	var input io.WriteCloser
	var output bytes.Buffer
	input, err = saltpack.NewSignArmor62Stream(saltpack.CurrentVersion(), &output, signer, "")
	if err != nil {
		return
	}

	// Write the message into the input stream, and then close
	_, err = input.Write(msg)
	if err != nil {
		return
	}
	input.Close()

	// The verified message. We pass the signed stream as the first argument
	// as a stream (here a bytes.Buffer which is output from above), and read the
	// verified data out of verified stream.
	var verifiedStream io.Reader
	var signingPublicKey saltpack.SigningPublicKey
	signingPublicKey, verifiedStream, _, err = saltpack.NewDearmor62VerifyStream(saltpack.CheckKnownMajorVersion, &output, keyring)
	if err != nil {
		return
	}

	// Assert we got the right key back.
	if saltpack.PublicKeyEqual(signingPublicKey, signer.GetPublicKey()) {
		fmt.Println("The right key")
	}

	// Copy all of the data out of the verified stream, and into standard
	// output, here for testing / comparison purposes.
	_, err = io.Copy(os.Stdout, verifiedStream)
	if err != nil {
		return
	}
	_, err = os.Stdout.Write([]byte{'\n'})
	if err != nil {
		return
	}

	// Output:
	// The right key
	// The Magic Words are Squeamish Ossifrage
}
