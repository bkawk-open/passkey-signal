package seal

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/mdlayher/vsock"
)

const (
	parentCID       = 3     // vsock CID of the parent EC2 instance
	kmsProxyPort    = 8000  // vsock port → KMS via vsock-proxy
	credProxyPort   = 9000  // vsock port → IMDS credential proxy
	rsaKeyBits      = 2048
)

// KMSSealer seals Share B using AWS KMS with Nitro attestation.
// The data key never leaves the enclave unencrypted.
type KMSSealer struct {
	keyID  string // KMS key alias or ARN
	region string
}

func NewKMSSealer(keyID, region string) *KMSSealer {
	return &KMSSealer{keyID: keyID, region: region}
}

func (k *KMSSealer) Mode() string { return "kms" }

// sealedData is the JSON structure stored as the sealed share.
type sealedData struct {
	KMSCiphertext  string `json:"k"` // KMS-encrypted data key (base64)
	EncryptedShare string `json:"e"` // AES-GCM encrypted share (base64)
	Nonce          string `json:"n"` // AES-GCM nonce (base64)
}

// Seal encrypts data using a KMS data key bound to this enclave's attestation.
func (k *KMSSealer) Seal(data []byte) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Generate ephemeral RSA key pair for KMS recipient envelope
	rsaKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return "", fmt.Errorf("rsa keygen: %w", err)
	}
	rsaPubDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal rsa pub: %w", err)
	}

	// Get NSM attestation document embedding the RSA public key
	attestDoc, err := getAttestationDocument(rsaPubDER)
	if err != nil {
		return "", fmt.Errorf("nsm attestation: %w", err)
	}

	// Create KMS client over vsock
	client, err := k.newKMSClient(ctx)
	if err != nil {
		return "", fmt.Errorf("kms client: %w", err)
	}

	// GenerateDataKey with attestation — KMS returns the data key
	// encrypted under both the KMS key (CiphertextBlob) and our RSA
	// public key (CiphertextForRecipient).
	genOut, err := client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:   aws.String(k.keyID),
		KeySpec: types.DataKeySpecAes256,
		Recipient: &types.RecipientInfo{
			AttestationDocument:    attestDoc,
			KeyEncryptionAlgorithm: types.KeyEncryptionMechanismRsaesOaepSha256,
		},
	})
	if err != nil {
		return "", fmt.Errorf("kms GenerateDataKey: %w", err)
	}

	// CiphertextForRecipient is a CMS EnvelopedData (RFC 5652) — parse it
	// to extract the RSA-OAEP encrypted content encryption key, then decrypt.
	dataKey, err := decryptCMSEnvelope(rsaKey, genOut.CiphertextForRecipient)
	if err != nil {
		return "", fmt.Errorf("decrypt cms envelope: %w", err)
	}
	defer zeroBytes(dataKey)

	// AES-256-GCM encrypt the share
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return "", fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	encrypted := gcm.Seal(nil, nonce, data, nil)

	// Pack sealed data as JSON → base64
	sd := sealedData{
		KMSCiphertext:  base64.StdEncoding.EncodeToString(genOut.CiphertextBlob),
		EncryptedShare: base64.StdEncoding.EncodeToString(encrypted),
		Nonce:          base64.StdEncoding.EncodeToString(nonce),
	}
	jsonBytes, err := json.Marshal(sd)
	if err != nil {
		return "", fmt.Errorf("marshal sealed: %w", err)
	}
	return base64.StdEncoding.EncodeToString(jsonBytes), nil
}

// Unseal decrypts a sealed share using KMS with fresh attestation.
func (k *KMSSealer) Unseal(sealed string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Parse sealed data
	jsonBytes, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	var sd sealedData
	if err := json.Unmarshal(jsonBytes, &sd); err != nil {
		return nil, fmt.Errorf("json unmarshal: %w", err)
	}
	kmsCiphertext, err := base64.StdEncoding.DecodeString(sd.KMSCiphertext)
	if err != nil {
		return nil, fmt.Errorf("decode kms ciphertext: %w", err)
	}
	encryptedShare, err := base64.StdEncoding.DecodeString(sd.EncryptedShare)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted share: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(sd.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}

	// Generate ephemeral RSA key pair
	rsaKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, fmt.Errorf("rsa keygen: %w", err)
	}
	rsaPubDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal rsa pub: %w", err)
	}

	// Get fresh attestation
	attestDoc, err := getAttestationDocument(rsaPubDER)
	if err != nil {
		return nil, fmt.Errorf("nsm attestation: %w", err)
	}

	// Create KMS client and decrypt
	client, err := k.newKMSClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("kms client: %w", err)
	}

	decOut, err := client.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob: kmsCiphertext,
		Recipient: &types.RecipientInfo{
			AttestationDocument:    attestDoc,
			KeyEncryptionAlgorithm: types.KeyEncryptionMechanismRsaesOaepSha256,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("kms Decrypt: %w", err)
	}

	// CiphertextForRecipient is a CMS EnvelopedData — parse and decrypt
	dataKey, err := decryptCMSEnvelope(rsaKey, decOut.CiphertextForRecipient)
	if err != nil {
		return nil, fmt.Errorf("decrypt cms envelope: %w", err)
	}
	defer zeroBytes(dataKey)

	// AES-256-GCM decrypt the share
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, encryptedShare, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm decrypt: %w", err)
	}
	return plaintext, nil
}

// getAttestationDocument returns a signed NSM attestation document
// with the given public key embedded.
func getAttestationDocument(publicKeyDER []byte) ([]byte, error) {
	sess, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, fmt.Errorf("open nsm: %w", err)
	}
	defer sess.Close()

	res, err := sess.Send(&request.Attestation{
		PublicKey: publicKeyDER,
	})
	if err != nil {
		return nil, fmt.Errorf("nsm send: %w", err)
	}
	if res.Attestation == nil || res.Attestation.Document == nil {
		return nil, fmt.Errorf("nsm returned empty attestation")
	}
	return res.Attestation.Document, nil
}

// newKMSClient creates a KMS client that routes through the vsock proxy
// and uses IMDS credentials fetched from the host.
func (k *KMSSealer) newKMSClient(ctx context.Context) (*kms.Client, error) {
	creds, err := fetchCredentials()
	if err != nil {
		return nil, fmt.Errorf("fetch creds: %w", err)
	}

	hostname := fmt.Sprintf("kms.%s.amazonaws.com", k.region)

	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := vsock.Dial(parentCID, kmsProxyPort, nil)
			if err != nil {
				return nil, fmt.Errorf("vsock dial %d:%d: %w", parentCID, kmsProxyPort, err)
			}
			tlsConn := tls.Client(conn, &tls.Config{
				ServerName: hostname,
				MinVersion: tls.VersionTLS12,
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, fmt.Errorf("tls handshake: %w", err)
			}
			return tlsConn, nil
		},
	}

	client := kms.New(kms.Options{
		Region:      k.region,
		Credentials: &staticCredentials{creds: creds},
		HTTPClient:  &http.Client{Transport: transport, Timeout: 30 * time.Second},
	})
	return client, nil
}

// imdsCredentials is the JSON returned by the IMDS credential endpoint.
type imdsCredentials struct {
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
}

// staticCredentials implements aws.CredentialsProvider.
type staticCredentials struct {
	creds aws.Credentials
}

func (s *staticCredentials) Retrieve(ctx context.Context) (aws.Credentials, error) {
	return s.creds, nil
}

// fetchCredentials gets IAM role credentials from the host via the
// vsock credential proxy (which reads from IMDS).
func fetchCredentials() (aws.Credentials, error) {
	conn, err := vsock.Dial(parentCID, credProxyPort, nil)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("vsock dial cred proxy: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	data, err := io.ReadAll(conn)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("read creds: %w", err)
	}

	var ic imdsCredentials
	if err := json.Unmarshal(data, &ic); err != nil {
		return aws.Credentials{}, fmt.Errorf("parse creds: %w", err)
	}

	return aws.Credentials{
		AccessKeyID:     ic.AccessKeyID,
		SecretAccessKey: ic.SecretAccessKey,
		SessionToken:    ic.Token,
	}, nil
}

// decryptCMSEnvelope parses a CMS EnvelopedData structure (RFC 5652)
// returned by KMS as CiphertextForRecipient. KMS uses BER encoding
// (with indefinite lengths), so we parse manually instead of using
// Go's encoding/asn1 which only supports DER.
//
// Structure: ContentInfo → EnvelopedData → RecipientInfos →
//   KeyTransRecipientInfo → encryptedKey (RSA-OAEP encrypted data key)
func decryptCMSEnvelope(rsaKey *rsa.PrivateKey, cmsData []byte) ([]byte, error) {
	// ContentInfo is SEQUENCE { OID, [0] EXPLICIT content }
	contentInfoChildren, err := berChildren(cmsData)
	if err != nil {
		return nil, fmt.Errorf("parse ContentInfo: %w", err)
	}
	if len(contentInfoChildren) < 2 {
		return nil, fmt.Errorf("ContentInfo has %d children, need >= 2", len(contentInfoChildren))
	}

	// contentInfoChildren[1] is [0] EXPLICIT EnvelopedData
	envelopedDataRaw, err := berContent(contentInfoChildren[1])
	if err != nil {
		return nil, fmt.Errorf("unwrap EnvelopedData context tag: %w", err)
	}

	// EnvelopedData is SEQUENCE { version INTEGER, recipientInfos SET, encryptedContentInfo SEQUENCE }
	envelopedChildren, err := berChildren(envelopedDataRaw)
	if err != nil {
		return nil, fmt.Errorf("parse EnvelopedData: %w", err)
	}
	if len(envelopedChildren) < 2 {
		return nil, fmt.Errorf("EnvelopedData has %d children, need >= 2", len(envelopedChildren))
	}

	// recipientInfos is SET OF KeyTransRecipientInfo
	// Each KeyTransRecipientInfo is SEQUENCE { version, rid, keyEncAlg, encryptedKey }
	recipientSetChildren, err := berChildren(envelopedChildren[1])
	if err != nil {
		return nil, fmt.Errorf("parse recipientInfos SET: %w", err)
	}
	if len(recipientSetChildren) < 1 {
		return nil, fmt.Errorf("no recipient infos found")
	}

	// Parse the first KeyTransRecipientInfo
	ktriChildren, err := berChildren(recipientSetChildren[0])
	if err != nil {
		return nil, fmt.Errorf("parse KeyTransRecipientInfo: %w", err)
	}
	if len(ktriChildren) < 4 {
		return nil, fmt.Errorf("KeyTransRecipientInfo has %d children, need >= 4", len(ktriChildren))
	}

	// encryptedKey is the 4th element (index 3), an OCTET STRING
	encryptedKey, err := berContent(ktriChildren[3])
	if err != nil {
		return nil, fmt.Errorf("extract encryptedKey: %w", err)
	}

	// RSA-OAEP decrypt the encrypted key to get the data key
	dataKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaKey, encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("rsa decrypt: %w", err)
	}

	return dataKey, nil
}

// berReadTLV reads a BER tag-length-value from data and returns the
// full element bytes and remaining bytes. Handles indefinite length.
func berReadTLV(data []byte) (element, rest []byte, err error) {
	if len(data) < 2 {
		return nil, nil, fmt.Errorf("truncated TLV")
	}

	// Parse tag (skip high-tag-number form for simplicity)
	pos := 1
	if data[0]&0x1f == 0x1f {
		for pos < len(data) && data[pos]&0x80 != 0 {
			pos++
		}
		pos++ // consume last tag byte
	}
	if pos >= len(data) {
		return nil, nil, fmt.Errorf("truncated tag")
	}

	// Parse length
	lenByte := data[pos]
	pos++

	if lenByte == 0x80 {
		// Indefinite length — scan for end-of-contents (00 00)
		depth := 1
		scan := pos
		for scan < len(data)-1 && depth > 0 {
			if data[scan] == 0x00 && data[scan+1] == 0x00 {
				depth--
				if depth == 0 {
					element = data[:scan+2]
					rest = data[scan+2:]
					return element, rest, nil
				}
				scan += 2
			} else {
				// Skip nested TLV
				_, inner, err := berReadTLV(data[scan:])
				if err != nil {
					scan++
					continue
				}
				scan = len(data) - len(inner)
			}
		}
		return nil, nil, fmt.Errorf("unterminated indefinite length")
	}

	var contentLen int
	if lenByte < 0x80 {
		contentLen = int(lenByte)
	} else {
		numBytes := int(lenByte & 0x7f)
		if pos+numBytes > len(data) {
			return nil, nil, fmt.Errorf("truncated length")
		}
		for i := 0; i < numBytes; i++ {
			contentLen = contentLen<<8 | int(data[pos])
			pos++
		}
	}

	end := pos + contentLen
	if end > len(data) {
		return nil, nil, fmt.Errorf("content exceeds data (need %d, have %d)", end, len(data))
	}
	return data[:end], data[end:], nil
}

// berContent returns the content bytes of a BER TLV element,
// stripping the tag and length.
func berContent(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("truncated TLV")
	}
	pos := 1
	if data[0]&0x1f == 0x1f {
		for pos < len(data) && data[pos]&0x80 != 0 {
			pos++
		}
		pos++
	}
	if pos >= len(data) {
		return nil, fmt.Errorf("truncated tag")
	}

	lenByte := data[pos]
	pos++

	if lenByte == 0x80 {
		// Indefinite: content is everything up to final 00 00
		// Find the matching end-of-contents
		end := len(data) - 2
		if end < pos {
			return nil, fmt.Errorf("no room for end-of-contents")
		}
		// Verify trailing 00 00
		if data[len(data)-2] == 0x00 && data[len(data)-1] == 0x00 {
			return data[pos : len(data)-2], nil
		}
		return data[pos:], nil
	}

	var contentLen int
	if lenByte < 0x80 {
		contentLen = int(lenByte)
	} else {
		numBytes := int(lenByte & 0x7f)
		if pos+numBytes > len(data) {
			return nil, fmt.Errorf("truncated length")
		}
		for i := 0; i < numBytes; i++ {
			contentLen = contentLen<<8 | int(data[pos])
			pos++
		}
	}

	end := pos + contentLen
	if end > len(data) {
		return nil, fmt.Errorf("content exceeds data")
	}
	return data[pos:end], nil
}

// berChildren returns the child TLV elements of a constructed BER element.
func berChildren(data []byte) ([][]byte, error) {
	content, err := berContent(data)
	if err != nil {
		return nil, err
	}
	var children [][]byte
	for len(content) > 0 {
		elem, rest, err := berReadTLV(content)
		if err != nil {
			return nil, err
		}
		children = append(children, elem)
		content = rest
	}
	return children, nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
