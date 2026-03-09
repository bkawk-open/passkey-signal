(function () {
    'use strict';

    // Depends on noble-secp256k1.min.js exposing:
    //   window.nobleSecp256k1 (secp256k1 curve)
    //   window.nobleSha256    (sha256 hash)
    //   window.nobleHkdf      (hkdf key derivation)

    var secp = window.nobleSecp256k1;
    var sha256 = window.nobleSha256;
    var hkdf = window.nobleHkdf;
    var Point = secp.Point;
    var curveN = Point.CURVE().n;

    // -- Hex helpers --

    function bytesToHex(bytes) {
        return Array.from(bytes, function (b) {
            return b.toString(16).padStart(2, '0');
        }).join('');
    }

    function hexToBytes(hex) {
        var bytes = new Uint8Array(hex.length / 2);
        for (var i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    }

    function privKeyToPoint(privKeyBytes) {
        var pubBytes = secp.getPublicKey(privKeyBytes, true);
        return Point.fromHex(bytesToHex(pubBytes));
    }

    // -- Schnorr proof (DKG-POK-v1) --

    function computeChallenge(sessionID, pubKeyHex, commitmentHex) {
        var prefix = new TextEncoder().encode('DKG-POK-v1:');
        var sessionBytes = new TextEncoder().encode(sessionID);
        var lenByte = new Uint8Array([sessionBytes.length]);
        var pubBytes = hexToBytes(pubKeyHex);
        var commitBytes = hexToBytes(commitmentHex);

        var combined = new Uint8Array(prefix.length + 1 + sessionBytes.length + pubBytes.length + commitBytes.length);
        combined.set(prefix, 0);
        combined.set(lenByte, prefix.length);
        combined.set(sessionBytes, prefix.length + 1);
        combined.set(pubBytes, prefix.length + 1 + sessionBytes.length);
        combined.set(commitBytes, prefix.length + 1 + sessionBytes.length + pubBytes.length);

        var hash = sha256(combined);
        // Reduce mod n — return as Uint8Array
        var hashBig = bytesToBigInt(hash);
        var reduced = mod(hashBig, curveN);
        return bigIntToBytes(reduced, 32);
    }

    function generateProof(privateKey, sessionID) {
        var pubPoint = privKeyToPoint(privateKey);
        var pubHex = bytesToHex(pubPoint.toBytes(true));

        // k = random nonce
        var k = secp.utils.randomSecretKey();
        var R = privKeyToPoint(k);
        var rHex = bytesToHex(R.toBytes(true));

        // e = challenge
        var e = computeChallenge(sessionID, pubHex, rHex);

        // s = k - x·e mod n
        var kBig = bytesToBigInt(k);
        var xBig = bytesToBigInt(privateKey);
        var eBig = bytesToBigInt(e);
        var s = mod(kBig - xBig * eBig, curveN);
        var sBytes = bigIntToBytes(s, 32);

        return {
            commitment: rHex,
            response: bytesToHex(sBytes),
        };
    }

    function verifyProof(pubKeyHex, sessionID, commitmentHex, responseHex) {
        var pubPoint = Point.fromHex(pubKeyHex);
        var R = Point.fromHex(commitmentHex);

        var e = computeChallenge(sessionID, pubKeyHex, commitmentHex);
        var s = hexToBytes(responseHex);

        // s·G + e·X should equal R
        var sG = Point.BASE.multiply(bytesToBigInt(s));
        var eX = pubPoint.multiply(bytesToBigInt(e));
        var check = sG.add(eX);

        return check.equals(R);
    }

    // -- BigInt helpers --

    function bytesToBigInt(bytes) {
        var hex = bytesToHex(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
        return BigInt('0x' + (hex || '0'));
    }

    function bigIntToBytes(num, length) {
        var hex = num.toString(16).padStart(length * 2, '0');
        return hexToBytes(hex);
    }

    function mod(a, b) {
        var result = a % b;
        return result >= 0n ? result : result + b;
    }

    // -- DKG share encryption (PRF → HKDF → AES-256-GCM) --

    async function encryptShare(prfOutput, privateKeyBytes) {
        // Random salt ensures unique AES key even if PRF output repeats
        var salt = crypto.getRandomValues(new Uint8Array(32));
        var aesKeyBytes = hkdf(sha256, prfOutput, salt, new TextEncoder().encode('wallet-share-v1'), 32);

        var aesKey = await crypto.subtle.importKey(
            'raw', aesKeyBytes,
            { name: 'AES-GCM' },
            false,
            ['encrypt']
        );

        var iv = crypto.getRandomValues(new Uint8Array(12));
        var ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            aesKey,
            privateKeyBytes
        );

        return {
            ciphertext: bytesToHex(new Uint8Array(ciphertext)),
            iv: bytesToHex(iv),
            salt: bytesToHex(salt),
        };
    }

    async function decryptShare(prfOutput, ciphertextHex, ivHex, saltHex) {
        var salt = saltHex ? hexToBytes(saltHex) : undefined;
        var aesKeyBytes = hkdf(sha256, prfOutput, salt, new TextEncoder().encode('wallet-share-v1'), 32);

        var aesKey = await crypto.subtle.importKey(
            'raw', aesKeyBytes,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );

        var plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: hexToBytes(ivHex) },
            aesKey,
            hexToBytes(ciphertextHex)
        );

        return new Uint8Array(plaintext);
    }

    // -- Main DKG orchestrator --

    async function runClientDKG(apiBase, sessionID, prfOutput, authToken) {
        // Step 1: Generate client key pair
        var clientPrivKey = secp.utils.randomSecretKey();
        var clientPubPoint = privKeyToPoint(clientPrivKey);
        var clientPubHex = bytesToHex(clientPubPoint.toBytes(true));

        // Step 2: Generate Schnorr proof
        var clientProof = generateProof(clientPrivKey, sessionID);

        // Step 3: Round 1 — exchange commitments with enclave
        var r1Resp = await fetch(apiBase + '/v1/dkg/round1', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                session_id: sessionID,
                public_point: clientPubHex,
                proof: clientProof,
            }),
        });

        if (!r1Resp.ok) {
            var err = await r1Resp.json();
            throw new Error('DKG round1 failed: ' + (err.error || err.Code));
        }

        var r1Data = await r1Resp.json();

        // Step 4: Verify enclave's Schnorr proof
        if (!verifyProof(r1Data.public_point, sessionID, r1Data.proof.commitment, r1Data.proof.response)) {
            throw new Error('Enclave Schnorr proof verification failed');
        }

        // Step 5: Derive joint public key X = X₁ + X₂
        var enclavePub = Point.fromHex(r1Data.public_point);
        var jointPub = clientPubPoint.add(enclavePub);
        var jointPubHex = bytesToHex(jointPub.toBytes(true));

        // Step 6: Compute confirmation hash
        var confirmInput = new TextEncoder().encode('DKG-CONFIRM-v1:' + sessionID + jointPubHex);
        var confirmHash = bytesToHex(sha256(confirmInput));

        // Step 7: Round 2 — complete DKG
        var r2Resp = await fetch(apiBase + '/v1/dkg/complete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                session_id: sessionID,
                joint_public_key: jointPubHex,
                confirmation_hash: confirmHash,
            }),
        });

        if (!r2Resp.ok) {
            var err2 = await r2Resp.json();
            throw new Error('DKG complete failed: ' + (err2.error || err2.Code));
        }

        var r2Data = await r2Resp.json();

        // Step 8: Encrypt client share with PRF-derived key (kept in memory for now)
        var encrypted = await encryptShare(prfOutput, clientPrivKey);

        return {
            encryptedShare: encrypted,
            jointPublicKey: r2Data.joint_public_key,
        };
    }

    // -- Expose API --
    window.DKG = {
        runClientDKG: runClientDKG,
        encryptShare: encryptShare,
        decryptShare: decryptShare,
        generateProof: generateProof,
        verifyProof: verifyProof,
    };
})();
