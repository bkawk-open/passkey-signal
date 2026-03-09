package main

import (
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	frostpkg "passkey-enclave/frost"
	"passkey-enclave/seal"
)

func main() {
	tcpAddr := flag.String("tcp", "", "Listen on TCP address (e.g. :8443) instead of vsock")
	flag.Parse()

	// Use KMS sealing if NSM device is available (real Nitro Enclave).
	// MockSealer is only allowed in dev mode (no NSM device).
	if _, err := os.Stat("/dev/nsm"); err == nil {
		log.Println("NSM device found - using KMS sealer")
		frostpkg.Sealer = seal.NewKMSSealer("alias/passkey-signal-enclave-seal", "us-east-1")
	} else if *tcpAddr != "" {
		log.Println("Dev mode (TCP + no NSM) - using mock sealer")
	} else {
		log.Fatal("FATAL: NSM device not found but running in vsock mode. Refusing to start with mock sealer in production.")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /frost/dkg/round1", handleFrostDKGRound1)
	mux.HandleFunc("POST /frost/dkg/complete", handleFrostDKGComplete)
	mux.HandleFunc("POST /frost/sign/begin", handleFrostSignBegin)
	mux.HandleFunc("POST /frost/sign/finish", handleFrostSignFinish)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// Start session cleanup goroutine
	go func() {
		for {
			time.Sleep(1 * time.Minute)
			frostpkg.CleanExpiredSessions()
		}
	}()

	var listener net.Listener
	var err error

	if *tcpAddr != "" {
		listener, err = net.Listen("tcp", *tcpAddr)
		if err != nil {
			log.Fatalf("failed to listen on TCP %s: %v", *tcpAddr, err)
		}
		log.Printf("Enclave listening on TCP %s", *tcpAddr)
	} else {
		listener, err = listenVsock(5000)
		if err != nil {
			log.Fatalf("failed to listen on vsock port 5000: %v", err)
		}
		log.Printf("Enclave listening on vsock port 5000")
	}

	server := &http.Server{Handler: mux}
	log.Fatal(server.Serve(listener))
}

func handleFrostDKGRound1(w http.ResponseWriter, r *http.Request) {
	var req frostpkg.DKGRound1Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid JSON", "code": "INVALID_REQUEST"})
		return
	}
	status, resp := frostpkg.HandleDKGRound1(req)
	writeJSON(w, status, resp)
}

func handleFrostDKGComplete(w http.ResponseWriter, r *http.Request) {
	var req frostpkg.DKGCompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid JSON", "code": "INVALID_REQUEST"})
		return
	}
	status, resp := frostpkg.HandleDKGComplete(req)
	writeJSON(w, status, resp)
}

func handleFrostSignBegin(w http.ResponseWriter, r *http.Request) {
	var req frostpkg.SignBeginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid JSON", "code": "INVALID_REQUEST"})
		return
	}
	status, resp := frostpkg.HandleSignBegin(req)
	writeJSON(w, status, resp)
}

func handleFrostSignFinish(w http.ResponseWriter, r *http.Request) {
	var req frostpkg.SignFinishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid JSON", "code": "INVALID_REQUEST"})
		return
	}
	status, resp := frostpkg.HandleSignFinish(req)
	writeJSON(w, status, resp)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
