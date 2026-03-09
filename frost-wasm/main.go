//go:build js && wasm

package main

import (
	"encoding/hex"
	"encoding/json"
	"syscall/js"

	"github.com/bytemare/dkg"
	"github.com/bytemare/ecc"
	"github.com/bytemare/frost"
	"github.com/bytemare/secret-sharing/keys"
)

const (
	ciphersuite      = dkg.Secp256k1
	frostCiphersuite = frost.Secp256k1
	threshold        = uint16(2)
	maxSigners       = uint16(2)
	clientID         = uint16(1)
	enclaveID        = uint16(2)
)

// Global state for multi-step flows
var (
	clientParticipant *dkg.Participant
	clientR1Data      *dkg.Round1Data
	clientKeyShare    *keys.KeyShare
)

// frostDKGRound1 generates the client's round 1 data.
// Returns JSON: { "client_r1_data": "<hex>" }
func frostDKGRound1(_ js.Value, args []js.Value) interface{} {
	p, err := ciphersuite.NewParticipant(clientID, threshold, maxSigners)
	if err != nil {
		return errorResult(err)
	}

	r1 := p.Start()
	clientParticipant = p
	clientR1Data = r1

	result := map[string]string{
		"client_r1_data": hex.EncodeToString(r1.Encode()),
	}

	return jsonResult(result)
}

// frostDKGRound2 processes the enclave's round 1 data and generates round 2 data.
// Input JSON: { "enclave_r1_data": "<hex>" }
// Returns JSON: { "client_r2_data": "<hex>" }
func frostDKGRound2(_ js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return errorStr("missing argument")
	}

	var input struct {
		EnclaveR1Data string `json:"enclave_r1_data"`
	}
	if err := json.Unmarshal([]byte(args[0].String()), &input); err != nil {
		return errorResult(err)
	}

	enclaveR1Bytes, err := hex.DecodeString(input.EnclaveR1Data)
	if err != nil {
		return errorResult(err)
	}

	var enclaveR1 dkg.Round1Data
	if err := enclaveR1.Decode(enclaveR1Bytes); err != nil {
		return errorResult(err)
	}

	r1DataSet := []*dkg.Round1Data{clientR1Data, &enclaveR1}

	r2Map, err := clientParticipant.Continue(r1DataSet)
	if err != nil {
		return errorResult(err)
	}

	r2ForEnclave, ok := r2Map[enclaveID]
	if !ok {
		return errorStr("no round2 data for enclave")
	}

	result := map[string]string{
		"client_r2_data": hex.EncodeToString(r2ForEnclave.Encode()),
	}

	return jsonResult(result)
}

// frostDKGFinalize finalizes the client's DKG with the enclave's round 2 data.
// Input JSON: { "enclave_r1_data": "<hex>", "enclave_r2_data": "<hex>" }
// Returns JSON: { "key_share": "<hex>", "verification_key": "<hex>", "public_key_share": "<hex>", "config_hex": "<hex>" }
func frostDKGFinalize(_ js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return errorStr("missing argument")
	}

	var input struct {
		EnclaveR1Data      string `json:"enclave_r1_data"`
		EnclaveR2Data      string `json:"enclave_r2_data"`
		EnclavePublicShare string `json:"enclave_public_share"`
	}
	if err := json.Unmarshal([]byte(args[0].String()), &input); err != nil {
		return errorResult(err)
	}

	// Decode enclave R1 data
	enclaveR1Bytes, err := hex.DecodeString(input.EnclaveR1Data)
	if err != nil {
		return errorResult(err)
	}
	var enclaveR1 dkg.Round1Data
	if err := enclaveR1.Decode(enclaveR1Bytes); err != nil {
		return errorResult(err)
	}

	// Decode enclave R2 data for client
	enclaveR2Bytes, err := hex.DecodeString(input.EnclaveR2Data)
	if err != nil {
		return errorResult(err)
	}
	var enclaveR2 dkg.Round2Data
	if err := enclaveR2.Decode(enclaveR2Bytes); err != nil {
		return errorResult(err)
	}

	r1DataSet := []*dkg.Round1Data{clientR1Data, &enclaveR1}

	// Finalize client key share
	ks, err := clientParticipant.Finalize(r1DataSet, []*dkg.Round2Data{&enclaveR2})
	if err != nil {
		return errorResult(err)
	}
	clientKeyShare = ks

	// Compute verification key
	vk, err := dkg.VerificationKeyFromRound1(ciphersuite, r1DataSet)
	if err != nil {
		return errorResult(err)
	}

	// Decode enclave public key share
	var enclavePKS keys.PublicKeyShare
	enclavePKSBytes, err := hex.DecodeString(input.EnclavePublicShare)
	if err != nil {
		return errorResult(err)
	}
	if err := enclavePKS.Decode(enclavePKSBytes); err != nil {
		return errorResult(err)
	}

	// Build FROST configuration for signing
	config := &frost.Configuration{
		Ciphersuite:  frostCiphersuite,
		Threshold:    threshold,
		MaxSigners:   maxSigners,
		VerificationKey: vk,
		SignerPublicKeyShares: []*keys.PublicKeyShare{
			&ks.PublicKeyShare,
			&enclavePKS,
		},
	}
	if err := config.Init(); err != nil {
		return errorResult(err)
	}

	result := map[string]string{
		"key_share":        hex.EncodeToString(ks.Encode()),
		"verification_key": hex.EncodeToString(vk.Encode()),
		"public_key_share": hex.EncodeToString(ks.PublicKeyShare.Encode()),
		"config_hex":       config.Hex(),
	}

	// Clear state
	clientParticipant = nil
	clientR1Data = nil

	return jsonResult(result)
}

// frostSignCommit generates a commitment for signing.
// Input JSON: { "key_share_hex": "<hex>", "config_hex": "<hex>" }
// Returns JSON: { "commitment": "<hex>", "signer_hex": "<hex>" }
func frostSignCommit(_ js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return errorStr("missing argument")
	}

	var input struct {
		KeyShareHex string `json:"key_share_hex"`
		ConfigHex   string `json:"config_hex"`
	}
	if err := json.Unmarshal([]byte(args[0].String()), &input); err != nil {
		return errorResult(err)
	}

	var config frost.Configuration
	if err := config.DecodeHex(input.ConfigHex); err != nil {
		return errorResult(err)
	}
	if err := config.Init(); err != nil {
		return errorResult(err)
	}

	ksBytes, err := hex.DecodeString(input.KeyShareHex)
	if err != nil {
		return errorResult(err)
	}
	var ks keys.KeyShare
	if err := ks.Decode(ksBytes); err != nil {
		return errorResult(err)
	}

	signer, err := config.Signer(&ks)
	if err != nil {
		return errorResult(err)
	}

	commitment := signer.Commit()

	result := map[string]string{
		"commitment": commitment.Hex(),
		"signer_hex": signer.Hex(),
	}

	return jsonResult(result)
}

// frostSignFinish computes the client's signature share.
// Input JSON: { "signer_hex": "<hex>", "message": "<hex>", "commitments_hex": ["<hex>", ...] }
// Returns JSON: { "sig_share": "<hex>" }
func frostSignFinish(_ js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return errorStr("missing argument")
	}

	var input struct {
		SignerHex      string   `json:"signer_hex"`
		Message        string   `json:"message"`
		CommitmentsHex []string `json:"commitments_hex"`
	}
	if err := json.Unmarshal([]byte(args[0].String()), &input); err != nil {
		return errorResult(err)
	}

	var signer frost.Signer
	if err := signer.DecodeHex(input.SignerHex); err != nil {
		return errorResult(err)
	}

	message, err := hex.DecodeString(input.Message)
	if err != nil {
		return errorResult(err)
	}

	var commitments frost.CommitmentList
	for _, ch := range input.CommitmentsHex {
		var c frost.Commitment
		if err := c.DecodeHex(ch); err != nil {
			return errorResult(err)
		}
		commitments = append(commitments, &c)
	}
	commitments.Sort()

	sigShare, err := signer.Sign(message, commitments)
	if err != nil {
		return errorResult(err)
	}

	result := map[string]string{
		"sig_share": sigShare.Hex(),
	}

	return jsonResult(result)
}

// frostVerifySignature verifies a FROST signature.
// Input JSON: { "message": "<hex>", "signature": "<hex>", "verification_key": "<hex>" }
// Returns JSON: { "valid": true/false }
func frostVerifySignature(_ js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return errorStr("missing argument")
	}

	var input struct {
		Message         string `json:"message"`
		Signature       string `json:"signature"`
		VerificationKey string `json:"verification_key"`
	}
	if err := json.Unmarshal([]byte(args[0].String()), &input); err != nil {
		return errorResult(err)
	}

	message, err := hex.DecodeString(input.Message)
	if err != nil {
		return errorResult(err)
	}

	var sig frost.Signature
	if err := sig.DecodeHex(input.Signature); err != nil {
		return errorResult(err)
	}

	vkBytes, err := hex.DecodeString(input.VerificationKey)
	if err != nil {
		return errorResult(err)
	}
	g := ecc.Group(ecc.Secp256k1Sha256)
	vk := g.NewElement()
	if err := vk.Decode(vkBytes); err != nil {
		return errorResult(err)
	}

	err = frost.VerifySignature(frostCiphersuite, message, &sig, vk)
	result := map[string]interface{}{
		"valid": err == nil,
	}

	b, _ := json.Marshal(result)
	return string(b)
}

// Helpers

func jsonResult(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func errorResult(err error) string {
	return jsonResult(map[string]string{"error": err.Error()})
}

func errorStr(msg string) string {
	return jsonResult(map[string]string{"error": msg})
}

func main() {
	c := make(chan struct{})

	js.Global().Set("frostDKGRound1", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return frostDKGRound1(this, args)
	}))
	js.Global().Set("frostDKGRound2", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return frostDKGRound2(this, args)
	}))
	js.Global().Set("frostDKGFinalize", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return frostDKGFinalize(this, args)
	}))
	js.Global().Set("frostSignCommit", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return frostSignCommit(this, args)
	}))
	js.Global().Set("frostSignFinish", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return frostSignFinish(this, args)
	}))
	js.Global().Set("frostVerifySignature", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return frostVerifySignature(this, args)
	}))

	<-c
}
