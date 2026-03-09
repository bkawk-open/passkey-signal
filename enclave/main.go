package main

import (
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"passkey-enclave/dkg"
	"passkey-enclave/seal"
)

func main() {
	tcpAddr := flag.String("tcp", "", "Listen on TCP address (e.g. :8443) instead of vsock")
	flag.Parse()

	// Use KMS sealing if NSM device is available (real Nitro Enclave).
	// MockSealer is only allowed in dev mode (no NSM device).
	if _, err := os.Stat("/dev/nsm"); err == nil {
		log.Println("NSM device found - using KMS sealer")
		dkg.Sealer = seal.NewKMSSealer("alias/passkey-signal-enclave-seal", "us-east-1")
	} else if *tcpAddr != "" {
		log.Println("Dev mode (TCP + no NSM) - using mock sealer")
	} else {
		log.Fatal("FATAL: NSM device not found but running in vsock mode. Refusing to start with mock sealer in production.")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /dkg/round1", handleRound1)
	mux.HandleFunc("POST /dkg/complete", handleComplete)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// Start session cleanup goroutine
	go func() {
		for {
			time.Sleep(1 * time.Minute)
			dkg.CleanExpiredSessions()
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

func handleRound1(w http.ResponseWriter, r *http.Request) {
	var req dkg.Round1Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid JSON", "code": "INVALID_REQUEST"})
		return
	}

	status, resp := dkg.HandleRound1(req)
	writeJSON(w, status, resp)
}

func handleComplete(w http.ResponseWriter, r *http.Request) {
	var req dkg.CompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid JSON", "code": "INVALID_REQUEST"})
		return
	}

	status, resp := dkg.HandleComplete(req)
	writeJSON(w, status, resp)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
