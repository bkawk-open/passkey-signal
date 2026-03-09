package main

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/google/uuid"
)

// FROST v2 DKG + signing handlers.
// These proxy to the enclave (or embedded mock) like v1 DKG.

// -- Request/Response types --

type frostDKGSessionResponse struct {
	SessionID string `json:"session_id"`
}

type frostDKGRound1ProxyRequest struct {
	SessionID    string `json:"session_id"`
	ClientR1Data string `json:"client_r1_data"`
}

type frostDKGCompleteProxyRequest struct {
	SessionID    string `json:"session_id"`
	ClientR1Data string `json:"client_r1_data"`
	ClientR2Data string `json:"client_r2_data"`
}

type frostDKGCompleteProxyResponse struct {
	VerificationKey    string `json:"verification_key"`
	EnclavePublicShare string `json:"enclave_public_share"`
	SealedShareB       string `json:"sealed_share_b"`
	SealMode           string `json:"seal_mode"`
	GroupCommitments   string `json:"group_commitments"`
	EnclaveR2Data      string `json:"enclave_r2_data"`
}

// -- Handlers --

func handleFrostDKGSession(ctx context.Context, db *dynamodb.Client, headers map[string]string) (events.APIGatewayV2HTTPResponse, error) {
	tok, err := authenticateRequest(ctx, db, headers)
	if err != nil {
		return jsonResp(401, map[string]string{"error": "unauthorized"})
	}

	sessionID := uuid.New().String()
	item := DKGSessionItem{
		PK:        "DKG#" + sessionID,
		SK:        "SESSION",
		UserID:    tok.UserID,
		Phone:     tok.Phone,
		ExpiresAt: time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339),
		TTL:       time.Now().Add(1 * time.Hour).Unix(),
	}

	if err := putDKGSession(ctx, db, item); err != nil {
		log.Printf("failed to create FROST DKG session: %v", err)
		return jsonResp(500, map[string]string{"error": "internal error"})
	}

	return jsonResp(200, frostDKGSessionResponse{SessionID: sessionID})
}

func handleFrostDKGRound1(enclaveURL string, body string) (events.APIGatewayV2HTTPResponse, error) {
	if enclaveURL != "" {
		return proxyToEnclave(enclaveURL, "/frost/dkg/round1", body)
	}
	// No embedded mock for FROST DKG — requires enclave or use v1
	return jsonResp(501, map[string]string{"error": "FROST DKG requires enclave", "code": "NOT_IMPLEMENTED"})
}

func handleFrostDKGComplete(ctx context.Context, db *dynamodb.Client, enclaveURL string, body string) (events.APIGatewayV2HTTPResponse, error) {
	if enclaveURL != "" {
		resp, err := proxyToEnclave(enclaveURL, "/frost/dkg/complete", body)
		if err != nil {
			return resp, err
		}

		// Store wallet with v2 DKG version
		if resp.StatusCode == 200 {
			storeFrostWalletFromComplete(ctx, db, resp.Body, body)
		}

		return resp, nil
	}
	return jsonResp(501, map[string]string{"error": "FROST DKG requires enclave", "code": "NOT_IMPLEMENTED"})
}

func storeFrostWalletFromComplete(ctx context.Context, db *dynamodb.Client, respBody string, requestBody string) {
	var data frostDKGCompleteProxyResponse
	if err := json.Unmarshal([]byte(respBody), &data); err != nil {
		log.Printf("failed to parse FROST DKG complete response: %v", err)
		return
	}

	if data.SealedShareB == "" {
		log.Printf("no sealed_share_b in FROST DKG complete response")
		return
	}

	// Get user from DKG session
	var reqBody struct {
		SessionID string `json:"session_id"`
	}
	userID := ""
	if err := json.Unmarshal([]byte(requestBody), &reqBody); err == nil && reqBody.SessionID != "" {
		sess, err := getDKGSession(ctx, db, reqBody.SessionID)
		if err != nil {
			log.Printf("failed to look up DKG session %s: %v", reqBody.SessionID, err)
		} else if sess != nil {
			userID = sess.UserID
		}
	}

	item := WalletItem{
		PK:               "WALLET#" + data.VerificationKey,
		SK:               "DATA",
		UserID:           userID,
		JointPublicKey:   data.VerificationKey,
		SealedShareB:     data.SealedShareB,
		SealMode:         data.SealMode,
		GroupCommitments: data.GroupCommitments,
		CreatedAt:        time.Now().UTC().Format(time.RFC3339),
	}

	if err := putWallet(ctx, db, item); err != nil {
		log.Printf("failed to store FROST wallet: %v", err)
		return
	}
	log.Printf("FROST wallet stored for verification key %s...", truncate(data.VerificationKey, 32))
}

func handleFrostSignBegin(enclaveURL string, body string) (events.APIGatewayV2HTTPResponse, error) {
	if enclaveURL != "" {
		return proxyToEnclave(enclaveURL, "/frost/sign/begin", body)
	}
	return jsonResp(501, map[string]string{"error": "FROST signing requires enclave", "code": "NOT_IMPLEMENTED"})
}

func handleFrostSignFinish(enclaveURL string, body string) (events.APIGatewayV2HTTPResponse, error) {
	if enclaveURL != "" {
		return proxyToEnclave(enclaveURL, "/frost/sign/finish", body)
	}
	return jsonResp(501, map[string]string{"error": "FROST signing requires enclave", "code": "NOT_IMPLEMENTED"})
}
