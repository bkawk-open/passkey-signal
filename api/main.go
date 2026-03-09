package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	dbClient   *dynamodb.Client
	smsClient  *sns.Client
	webAuthn   *webauthn.WebAuthn
	enclaveURL string
)

func init() {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatalf("unable to load AWS config: %v", err)
	}
	dbClient = dynamodb.NewFromConfig(cfg)

	// SNS client in eu-west-2 for SMS
	smsRegion := os.Getenv("SMS_REGION")
	if smsRegion == "" {
		smsRegion = "eu-west-2"
	}
	smsCfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(smsRegion))
	if err != nil {
		log.Fatalf("unable to load SMS config: %v", err)
	}
	smsClient = sns.NewFromConfig(smsCfg)

	webAuthn, err = newWebAuthn()
	if err != nil {
		log.Fatalf("unable to init webauthn: %v", err)
	}

	enclaveURL = os.Getenv("ENCLAVE_URL")
	if enclaveURL != "" {
		log.Printf("DKG mode: enclave at %s", enclaveURL)
		checkEnclaveHealth()
	} else {
		log.Printf("DKG mode: embedded mock")
	}
}

var allowedOrigins = map[string]bool{
	"https://passkey-signal.bkawk.com": true,
}

func handler(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	origin := request.Headers["origin"]

	// Handle CORS preflight
	if request.RequestContext.HTTP.Method == "OPTIONS" {
		return corsResponse(events.APIGatewayV2HTTPResponse{StatusCode: 204}, origin), nil
	}

	var resp events.APIGatewayV2HTTPResponse
	var err error

	route := request.RequestContext.HTTP.Method + " " + request.RawPath
	switch route {
	case "POST /auth/begin":
		resp, err = handleAuthBegin(ctx, dbClient, webAuthn, smsClient, request.Body)
	case "POST /auth/verify-otp":
		resp, err = handleVerifyOTP(ctx, dbClient, webAuthn, request.Body)
	case "POST /register/finish":
		resp, err = handleRegisterFinish(ctx, dbClient, webAuthn, request.Body, request.Headers)
	case "POST /login/begin":
		resp, err = handleLoginBegin(ctx, dbClient, webAuthn)
	case "POST /login/finish":
		resp, err = handleLoginFinish(ctx, dbClient, webAuthn, request.Body)
	case "GET /session":
		resp, err = handleSession(ctx, dbClient, request.Headers)
	case "POST /logout":
		resp, err = handleLogout(ctx, dbClient, request.Headers)
	case "GET /note":
		resp, err = handleGetNote(ctx, dbClient, request.Headers)
	case "PUT /note":
		resp, err = handlePutNote(ctx, dbClient, request.Headers, request.Body)
	case "GET /passkeys":
		resp, err = handleListPasskeys(ctx, dbClient, request.Headers)
	case "POST /passkeys/add/begin":
		resp, err = handleAddPasskeyBegin(ctx, dbClient, webAuthn, request.Headers)
	case "POST /passkeys/add/finish":
		resp, err = handleAddPasskeyFinish(ctx, dbClient, webAuthn, request.Headers, request.Body)
	case "DELETE /passkeys":
		resp, err = handleDeletePasskey(ctx, dbClient, request.Headers, request.Body)
	case "PUT /passkeys/wrapped-key":
		resp, err = handleStoreWrappedKey(ctx, dbClient, request.Headers, request.Body)
	case "GET /passkeys/wrapped-key":
		resp, err = handleGetWrappedKey(ctx, dbClient, request.Headers, request.QueryStringParameters)
	case "POST /invite/create":
		resp, err = handleInviteCreate(ctx, dbClient, webAuthn, request.Headers, request.Body)
	case "GET /invite/info":
		resp, err = handleInviteInfo(ctx, dbClient, request.QueryStringParameters)
	case "POST /invite/register/begin":
		resp, err = handleInviteRegisterBegin(ctx, dbClient, webAuthn, request.Body)
	case "POST /invite/register/finish":
		resp, err = handleInviteRegisterFinish(ctx, dbClient, webAuthn, request.Body, request.Headers)
	case "GET /invite/status":
		resp, err = handleInviteStatus(ctx, dbClient, request.Headers, request.QueryStringParameters)
	case "POST /invite/complete":
		resp, err = handleInviteComplete(ctx, dbClient, request.Headers, request.Body)
	case "POST /device/enrol/begin":
		resp, err = handleDeviceEnrolBegin(ctx, dbClient, request.Headers)
	case "POST /device/enrol/redeem":
		resp, err = handleDeviceEnrolRedeem(ctx, dbClient, request.Body)
	case "POST /device/enrol/deliver":
		resp, err = handleDeviceEnrolDeliver(ctx, dbClient, request.Headers, request.Body)
	case "GET /device/enrol/receive":
		resp, err = handleDeviceEnrolReceive(ctx, dbClient, request.QueryStringParameters)
	case "POST /device/enrol/complete":
		resp, err = handleDeviceEnrolComplete(ctx, dbClient, request.Body)
	case "GET /device/enrol/status":
		resp, err = handleDeviceEnrolStatus(ctx, dbClient, request.Headers, request.QueryStringParameters)
	case "POST /device/auth":
		resp, err = handleDeviceAuth(ctx, dbClient, request.Body)
	case "POST /device/verify":
		resp, err = handleDeviceVerify(ctx, dbClient, request.Body)
	case "DELETE /device":
		resp, err = handleDeleteDevice(ctx, dbClient, request.Headers, request.Body)
	case "GET /devices":
		resp, err = handleListDevices(ctx, dbClient, request.Headers)
	case "POST /v1/dkg/session":
		resp, err = handleDKGSession(ctx, dbClient, request.Headers)
	case "POST /v1/dkg/round1":
		if enclaveURL != "" {
			resp, err = proxyToEnclave(enclaveURL, "/dkg/round1", request.Body)
		} else {
			resp, err = handleDKGRound1(request.Body)
		}
	case "POST /v1/dkg/complete":
		if enclaveURL != "" {
			resp, err = proxyToEnclave(enclaveURL, "/dkg/complete", request.Body)
		} else {
			resp, err = handleDKGComplete(request.Body)
		}
		// Store wallet with sealed Share B after successful DKG complete
		if err == nil && resp.StatusCode == 200 {
			storeWalletFromComplete(ctx, dbClient, resp.Body, request.Body)
		}
	default:
		resp, _ = jsonResp(404, map[string]string{"error": "not found"})
	}

	if err != nil {
		log.Printf("handler error on %s: %v", route, err)
		return corsResponse(events.APIGatewayV2HTTPResponse{StatusCode: 500}, origin), nil
	}

	return corsResponse(resp, origin), nil
}

func corsResponse(resp events.APIGatewayV2HTTPResponse, origin string) events.APIGatewayV2HTTPResponse {
	if resp.Headers == nil {
		resp.Headers = make(map[string]string)
	}
	if allowedOrigins[origin] {
		resp.Headers["Access-Control-Allow-Origin"] = origin
		resp.Headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS"
		resp.Headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
		resp.Headers["Vary"] = "Origin"
	}
	resp.Headers["X-Content-Type-Options"] = "nosniff"
	resp.Headers["Content-Security-Policy"] = "default-src 'none'"
	return resp
}

var enclaveHTTPClient = &http.Client{Timeout: 8 * time.Second}

func storeWalletFromComplete(ctx context.Context, db *dynamodb.Client, respBody string, requestBody string) {
	var data dkgCompleteResponse
	if err := json.Unmarshal([]byte(respBody), &data); err != nil {
		log.Printf("failed to parse DKG complete response for wallet storage: %v", err)
		return
	}

	if data.SealedShareB == "" {
		log.Printf("no sealed_share_b in DKG complete response")
		return
	}

	// Get user from DKG session in DynamoDB
	var reqBody dkgCompleteRequest
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
		PK:             "WALLET#" + data.JointPublicKey,
		SK:             "DATA",
		UserID:         userID,
		JointPublicKey: data.JointPublicKey,
		SealedShareB:   data.SealedShareB,
		SealMode:       data.SealMode,
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
	}

	if err := putWallet(ctx, db, item); err != nil {
		log.Printf("failed to store wallet: %v", err)
		return
	}
	log.Printf("wallet stored for joint key %s", data.JointPublicKey[:16]+"...")
}

func checkEnclaveHealth() {
	if enclaveURL == "" {
		return
	}
	resp, err := enclaveHTTPClient.Get(enclaveURL + "/health")
	if err != nil {
		log.Printf("WARNING: enclave health check failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Printf("WARNING: enclave health check returned %d", resp.StatusCode)
		return
	}
	log.Printf("enclave health check OK")
}

func proxyToEnclave(baseURL, path, body string) (events.APIGatewayV2HTTPResponse, error) {
	url := strings.TrimRight(baseURL, "/") + path
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return events.APIGatewayV2HTTPResponse{}, fmt.Errorf("proxy request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := enclaveHTTPClient.Do(req)
	if err != nil {
		log.Printf("enclave proxy error: %v", err)
		return jsonResp(502, map[string]string{"error": "enclave unreachable", "code": "ENCLAVE_ERROR"})
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return events.APIGatewayV2HTTPResponse{}, fmt.Errorf("proxy read: %w", err)
	}

	return events.APIGatewayV2HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(respBody),
	}, nil
}

func main() {
	lambda.Start(handler)
}
