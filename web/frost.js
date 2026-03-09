(function () {
    'use strict';

    var wasmReady = false;
    var wasmLoading = null;

    async function ensureWasm() {
        if (wasmReady) return;
        if (wasmLoading) {
            await wasmLoading;
            return;
        }

        wasmLoading = (async function () {
            // Load wasm_exec.js if not already loaded
            if (typeof Go === 'undefined') {
                await new Promise(function (resolve, reject) {
                    var script = document.createElement('script');
                    script.src = 'wasm_exec.js';
                    script.onload = resolve;
                    script.onerror = reject;
                    document.head.appendChild(script);
                });
            }

            var go = new Go();
            var result = await WebAssembly.instantiateStreaming(
                fetch('frost.wasm'),
                go.importObject
            );
            go.run(result.instance);
            wasmReady = true;
        })();

        await wasmLoading;
    }

    function parseResult(resultStr) {
        var result = JSON.parse(resultStr);
        if (result.error) {
            throw new Error('FROST: ' + result.error);
        }
        return result;
    }

    // -- DKG --

    async function runDKG(apiBase, sessionID, authToken) {
        await ensureWasm();

        // Step 1: Client generates round 1 data
        var r1Result = parseResult(frostDKGRound1());

        // Step 2: Send to enclave, get enclave's round 1 data
        var r1Resp = await fetch(apiBase + '/v2/dkg/round1', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + authToken,
            },
            body: JSON.stringify({
                session_id: sessionID,
                client_r1_data: r1Result.client_r1_data,
            }),
        });
        if (!r1Resp.ok) {
            var err = await r1Resp.json();
            throw new Error('FROST DKG round1 failed: ' + (err.error || r1Resp.status));
        }
        var r1Data = await r1Resp.json();

        // Step 3: Client generates round 2 data
        var r2Result = parseResult(frostDKGRound2(JSON.stringify({
            enclave_r1_data: r1Data.enclave_r1_data,
        })));

        // Step 4: Send round 2 + finalize (enclave completes DKG and returns sealed share)
        var completeResp = await fetch(apiBase + '/v2/dkg/complete', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + authToken,
            },
            body: JSON.stringify({
                session_id: sessionID,
                client_r1_data: r1Result.client_r1_data,
                client_r2_data: r2Result.client_r2_data,
            }),
        });
        if (!completeResp.ok) {
            var err2 = await completeResp.json();
            throw new Error('FROST DKG complete failed: ' + (err2.error || completeResp.status));
        }
        var completeData = await completeResp.json();

        // Step 5: Client finalizes its key share
        var finalResult = parseResult(frostDKGFinalize(JSON.stringify({
            enclave_r1_data: r1Data.enclave_r1_data,
            enclave_r2_data: completeData.enclave_r2_data,
            enclave_public_share: completeData.enclave_public_share,
        })));

        return {
            keyShareHex: finalResult.key_share,
            verificationKey: finalResult.verification_key,
            publicKeyShareHex: finalResult.public_key_share,
            configHex: finalResult.config_hex,
            sealedShareB: completeData.sealed_share_b,
            sealMode: completeData.seal_mode,
            groupCommitments: completeData.group_commitments,
            dkgVersion: 'v2',
        };
    }

    // -- Signing --

    async function sign(apiBase, walletData, messageHex, authToken) {
        await ensureWasm();

        // Step 1: Client generates commitment
        var commitResult = parseResult(frostSignCommit(JSON.stringify({
            key_share_hex: walletData.keyShareHex,
            config_hex: walletData.configHex,
        })));

        // Step 2: Send commitment to enclave, get enclave commitment
        var beginResp = await fetch(apiBase + '/v2/sign/begin', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + authToken,
            },
            body: JSON.stringify({
                session_id: crypto.randomUUID(),
                wallet_id: walletData.verificationKey,
                message: messageHex,
                sealed_share_b: walletData.sealedShareB,
                seal_mode: walletData.sealMode,
                config_hex: walletData.configHex,
                client_commitment: commitResult.commitment,
            }),
        });
        if (!beginResp.ok) {
            var err = await beginResp.json();
            throw new Error('FROST sign begin failed: ' + (err.error || beginResp.status));
        }
        var beginData = await beginResp.json();

        // Step 3: Client computes signature share
        var sigResult = parseResult(frostSignFinish(JSON.stringify({
            signer_hex: commitResult.signer_hex,
            message: messageHex,
            commitments_hex: [commitResult.commitment, beginData.enclave_commitment],
        })));

        // Step 4: Send sig share to enclave for aggregation
        var finishResp = await fetch(apiBase + '/v2/sign/finish', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + authToken,
            },
            body: JSON.stringify({
                session_id: beginData.session_id || crypto.randomUUID(),
                client_sig_share: sigResult.sig_share,
                client_commitment_hex: commitResult.commitment,
            }),
        });
        if (!finishResp.ok) {
            var err2 = await finishResp.json();
            throw new Error('FROST sign finish failed: ' + (err2.error || finishResp.status));
        }
        var finishData = await finishResp.json();

        return {
            signature: finishData.signature,
        };
    }

    // -- Verify --

    async function verify(messageHex, signatureHex, verificationKeyHex) {
        await ensureWasm();
        var result = parseResult(frostVerifySignature(JSON.stringify({
            message: messageHex,
            signature: signatureHex,
            verification_key: verificationKeyHex,
        })));
        return result.valid;
    }

    // -- Expose API --
    window.FROST = {
        runDKG: runDKG,
        sign: sign,
        verify: verify,
        ensureWasm: ensureWasm,
    };
})();
