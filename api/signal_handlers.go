package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

// -- Request/Response types --

type signalKeyUploadRequest struct {
	CredentialID      string                   `json:"credentialId"`
	IdentityPublicKey string                   `json:"identityPublicKey"`
	SignedPreKey      signalSignedPreKeyReq    `json:"signedPreKey"`
	OneTimePreKeys    []signalOneTimePreKeyReq `json:"oneTimePreKeys"`
}

type signalSignedPreKeyReq struct {
	KeyID               int    `json:"keyId"`
	PublicKey           string `json:"publicKey"`
	Signature           string `json:"signature"`
	EncryptedPrivateKey string `json:"encryptedPrivateKey"`
	IV                  string `json:"iv"`
	Salt                string `json:"salt"`
}

type signalOneTimePreKeyReq struct {
	KeyID               int    `json:"keyId"`
	PublicKey           string `json:"publicKey"`
	EncryptedPrivateKey string `json:"encryptedPrivateKey"`
	IV                  string `json:"iv"`
	Salt                string `json:"salt"`
}

type signalReplenishRequest struct {
	CredentialID   string                   `json:"credentialId"`
	OneTimePreKeys []signalOneTimePreKeyReq `json:"oneTimePreKeys"`
}

type signalPreKeyBundleResponse struct {
	Phone       string                   `json:"phone"`
	Credentials []signalCredentialBundle  `json:"credentials"`
}

type signalCredentialBundle struct {
	CredentialID      string                   `json:"credentialId"`
	IdentityPublicKey string                   `json:"identityPublicKey"`
	SignedPreKey      *signalSignedPreKeyResp  `json:"signedPreKey"`
	OneTimePreKey     *signalOneTimePreKeyResp `json:"oneTimePreKey,omitempty"`
}

type signalSignedPreKeyResp struct {
	KeyID     int    `json:"keyId"`
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
}

type signalOneTimePreKeyResp struct {
	KeyID     int    `json:"keyId"`
	PublicKey string `json:"publicKey"`
}

// -- Handlers --

func handleSignalKeyUpload(ctx context.Context, db *dynamodb.Client, headers map[string]string, body string) (events.APIGatewayV2HTTPResponse, error) {
	tok, err := authenticateRequest(ctx, db, headers)
	if err != nil {
		return jsonResp(401, map[string]string{"error": "unauthorized"})
	}
	phone := tok.Phone

	var req signalKeyUploadRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		return jsonResp(400, map[string]string{"error": "invalid JSON"})
	}

	if req.CredentialID == "" || req.IdentityPublicKey == "" {
		return jsonResp(400, map[string]string{"error": "credentialId and identityPublicKey required"})
	}

	if req.SignedPreKey.PublicKey == "" || req.SignedPreKey.Signature == "" {
		return jsonResp(400, map[string]string{"error": "signedPreKey required"})
	}

	// Check that this credential belongs to the user
	cred, err := getCredentialForUser(ctx, db, phone, req.CredentialID)
	if err != nil || cred == nil {
		return jsonResp(403, map[string]string{"error": "credential not found"})
	}

	now := time.Now().UTC().Format(time.RFC3339)

	// Store identity
	identItem := SignalIdentityItem{
		PK:                "USER#" + phone,
		SK:                "SIGIDENT#" + req.CredentialID,
		CredentialID:      req.CredentialID,
		IdentityPublicKey: req.IdentityPublicKey,
		CreatedAt:         now,
	}
	if err := putSignalIdentity(ctx, db, identItem); err != nil {
		log.Printf("failed to store signal identity: %v", err)
		return jsonResp(500, map[string]string{"error": "internal error"})
	}

	// Store signed prekey
	spkItem := SignalSignedPreKeyItem{
		PK:                  "USER#" + phone,
		SK:                  fmt.Sprintf("SIGSPK#%s#%d", req.CredentialID, req.SignedPreKey.KeyID),
		KeyID:               req.SignedPreKey.KeyID,
		PublicKey:           req.SignedPreKey.PublicKey,
		Signature:           req.SignedPreKey.Signature,
		EncryptedPrivateKey: req.SignedPreKey.EncryptedPrivateKey,
		IV:                  req.SignedPreKey.IV,
		Salt:                req.SignedPreKey.Salt,
		CreatedAt:           now,
	}
	if err := putSignalSignedPreKey(ctx, db, spkItem); err != nil {
		log.Printf("failed to store signed prekey: %v", err)
		return jsonResp(500, map[string]string{"error": "internal error"})
	}

	// Store one-time prekeys
	if len(req.OneTimePreKeys) > 0 {
		var otpkItems []SignalOneTimePreKeyItem
		for _, otpk := range req.OneTimePreKeys {
			otpkItems = append(otpkItems, SignalOneTimePreKeyItem{
				PK:                  "USER#" + phone,
				SK:                  fmt.Sprintf("SIGOTPK#%s#%d", req.CredentialID, otpk.KeyID),
				KeyID:               otpk.KeyID,
				PublicKey:           otpk.PublicKey,
				EncryptedPrivateKey: otpk.EncryptedPrivateKey,
				IV:                  otpk.IV,
				Salt:                otpk.Salt,
				Consumed:            false,
			})
		}
		if err := putSignalOneTimePreKeys(ctx, db, otpkItems); err != nil {
			log.Printf("failed to store OTPKs: %v", err)
			return jsonResp(500, map[string]string{"error": "internal error"})
		}
	}

	log.Printf("signal keys uploaded for %s cred %s...", phone, truncate(req.CredentialID, 16))
	return jsonResp(200, map[string]string{"status": "ok"})
}

func handleSignalKeyBundle(ctx context.Context, db *dynamodb.Client, headers map[string]string, queryParams map[string]string) (events.APIGatewayV2HTTPResponse, error) {
	_, err := authenticateRequest(ctx, db, headers)
	if err != nil {
		return jsonResp(401, map[string]string{"error": "unauthorized"})
	}

	targetPhone := queryParams["phone"]
	if targetPhone == "" {
		return jsonResp(400, map[string]string{"error": "phone parameter required"})
	}

	// Get all signal identities for the target user
	identities, err := getUserSignalIdentities(ctx, db, targetPhone)
	if err != nil {
		log.Printf("failed to get signal identities: %v", err)
		return jsonResp(500, map[string]string{"error": "internal error"})
	}

	if len(identities) == 0 {
		return jsonResp(404, map[string]string{"error": "no signal keys found for user"})
	}

	var bundles []signalCredentialBundle
	for _, ident := range identities {
		bundle := signalCredentialBundle{
			CredentialID:      ident.CredentialID,
			IdentityPublicKey: ident.IdentityPublicKey,
		}

		// Get signed prekey
		spk, err := getSignalSignedPreKey(ctx, db, targetPhone, ident.CredentialID)
		if err != nil {
			log.Printf("failed to get signed prekey: %v", err)
			continue
		}
		if spk != nil {
			bundle.SignedPreKey = &signalSignedPreKeyResp{
				KeyID:     spk.KeyID,
				PublicKey: spk.PublicKey,
				Signature: spk.Signature,
			}
		}

		// Consume one OTPK
		otpk, err := consumeSignalOneTimePreKey(ctx, db, targetPhone, ident.CredentialID)
		if err != nil {
			log.Printf("failed to consume OTPK: %v", err)
		}
		if otpk != nil {
			bundle.OneTimePreKey = &signalOneTimePreKeyResp{
				KeyID:     otpk.KeyID,
				PublicKey: otpk.PublicKey,
			}
		}

		bundles = append(bundles, bundle)
	}

	resp := signalPreKeyBundleResponse{
		Phone:       targetPhone,
		Credentials: bundles,
	}

	return jsonResp(200, resp)
}

func handleSignalKeyReplenish(ctx context.Context, db *dynamodb.Client, headers map[string]string, body string) (events.APIGatewayV2HTTPResponse, error) {
	tok, err := authenticateRequest(ctx, db, headers)
	if err != nil {
		return jsonResp(401, map[string]string{"error": "unauthorized"})
	}
	phone := tok.Phone

	var req signalReplenishRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		return jsonResp(400, map[string]string{"error": "invalid JSON"})
	}

	if req.CredentialID == "" || len(req.OneTimePreKeys) == 0 {
		return jsonResp(400, map[string]string{"error": "credentialId and oneTimePreKeys required"})
	}

	// Verify credential belongs to user
	cred, err := getCredentialForUser(ctx, db, phone, req.CredentialID)
	if err != nil || cred == nil {
		return jsonResp(403, map[string]string{"error": "credential not found"})
	}

	var otpkItems []SignalOneTimePreKeyItem
	for _, otpk := range req.OneTimePreKeys {
		otpkItems = append(otpkItems, SignalOneTimePreKeyItem{
			PK:                  "USER#" + phone,
			SK:                  fmt.Sprintf("SIGOTPK#%s#%d", req.CredentialID, otpk.KeyID),
			KeyID:               otpk.KeyID,
			PublicKey:           otpk.PublicKey,
			EncryptedPrivateKey: otpk.EncryptedPrivateKey,
			IV:                  otpk.IV,
			Salt:                otpk.Salt,
			Consumed:            false,
		})
	}

	if err := putSignalOneTimePreKeys(ctx, db, otpkItems); err != nil {
		log.Printf("failed to store OTPKs: %v", err)
		return jsonResp(500, map[string]string{"error": "internal error"})
	}

	log.Printf("signal OTPKs replenished for %s cred %s...", phone, truncate(req.CredentialID, 16))
	return jsonResp(200, map[string]string{"status": "ok"})
}

func handleSignalKeyCount(ctx context.Context, db *dynamodb.Client, headers map[string]string, queryParams map[string]string) (events.APIGatewayV2HTTPResponse, error) {
	tok, err := authenticateRequest(ctx, db, headers)
	if err != nil {
		return jsonResp(401, map[string]string{"error": "unauthorized"})
	}
	phone := tok.Phone

	credID := queryParams["credentialId"]
	if credID == "" {
		return jsonResp(400, map[string]string{"error": "credentialId parameter required"})
	}

	// Check if identity exists
	ident, err := getSignalIdentity(ctx, db, phone, credID)
	if err != nil {
		log.Printf("failed to get signal identity: %v", err)
		return jsonResp(500, map[string]string{"error": "internal error"})
	}

	count, nextKeyId, err := countUnconsumedOTPKs(ctx, db, phone, credID)
	if err != nil {
		log.Printf("failed to count OTPKs: %v", err)
		return jsonResp(500, map[string]string{"error": "internal error"})
	}

	return jsonResp(200, map[string]interface{}{
		"count":       count,
		"nextKeyId":   nextKeyId,
		"hasIdentity": ident != nil,
	})
}

// getCredentialForUser checks that a credential belongs to the given phone.
func getCredentialForUser(ctx context.Context, db *dynamodb.Client, phone string, credID string) (*CredentialItem, error) {
	creds, err := getUserCredentials(ctx, db, phone)
	if err != nil {
		return nil, err
	}
	for _, c := range creds {
		if c.CredentialID == credID {
			return &c, nil
		}
	}
	return nil, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
