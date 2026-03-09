(function () {
    'use strict';

    // Depends on noble-secp256k1.min.js exposing:
    //   window.nobleEd25519 (Ed25519 signatures)
    //   window.nobleX25519  (X25519 ECDH)
    //   window.nobleSha256  (SHA-256 hash)
    //   window.nobleHkdf    (HKDF key derivation)

    var ed25519 = window.nobleEd25519;
    var x25519 = window.nobleX25519;
    var sha256 = window.nobleSha256;
    var hkdf = window.nobleHkdf;

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

    function bytesToB64url(bytes) {
        var bin = '';
        for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function b64urlToBytes(str) {
        var s = str.replace(/-/g, '+').replace(/_/g, '/');
        while (s.length % 4) s += '=';
        var bin = atob(s);
        var bytes = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        return bytes;
    }

    // -- Identity key derivation --

    function deriveSignalIdentityKey(prfOutput, credentialId) {
        // HKDF-SHA256: PRF output as IKM, no salt, info = "signal-identity-v1:" + credentialId
        var info = new TextEncoder().encode('signal-identity-v1:' + credentialId);
        var seed = hkdf(sha256, new Uint8Array(prfOutput), undefined, info, 32);
        var publicKey = ed25519.getPublicKey(seed);
        return {
            privateKey: seed,
            publicKey: publicKey,
        };
    }

    // -- Signed PreKey generation --

    function generateSignedPreKey(identityPrivKey, keyId) {
        // Random X25519 key pair
        var privKey = crypto.getRandomValues(new Uint8Array(32));
        var pubKey = x25519.getPublicKey(privKey);

        // Sign the public key with the Ed25519 identity key
        var signature = ed25519.sign(pubKey, identityPrivKey);

        return {
            keyId: keyId,
            privateKey: privKey,
            publicKey: pubKey,
            signature: signature,
        };
    }

    // -- One-Time PreKey generation --

    function generateOneTimePreKeys(startId, count) {
        var keys = [];
        for (var i = 0; i < count; i++) {
            var privKey = crypto.getRandomValues(new Uint8Array(32));
            var pubKey = x25519.getPublicKey(privKey);
            keys.push({
                keyId: startId + i,
                privateKey: privKey,
                publicKey: pubKey,
            });
        }
        return keys;
    }

    // -- Private key encryption (PRF → HKDF → AES-256-GCM) --

    async function encryptPreKeyPrivate(prfOutput, credentialId, privKeyBytes) {
        var salt = crypto.getRandomValues(new Uint8Array(32));
        var info = new TextEncoder().encode('signal-prekey-v1:' + credentialId);
        var aesKeyBytes = hkdf(sha256, new Uint8Array(prfOutput), salt, info, 32);

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
            privKeyBytes
        );

        return {
            ciphertext: bytesToB64url(new Uint8Array(ciphertext)),
            iv: bytesToB64url(iv),
            salt: bytesToB64url(salt),
        };
    }

    async function decryptPreKeyPrivate(prfOutput, credentialId, ciphertextB64, ivB64, saltB64) {
        var salt = b64urlToBytes(saltB64);
        var info = new TextEncoder().encode('signal-prekey-v1:' + credentialId);
        var aesKeyBytes = hkdf(sha256, new Uint8Array(prfOutput), salt, info, 32);

        var aesKey = await crypto.subtle.importKey(
            'raw', aesKeyBytes,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );

        var plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: b64urlToBytes(ivB64) },
            aesKey,
            b64urlToBytes(ciphertextB64)
        );

        return new Uint8Array(plaintext);
    }

    // -- API helpers --

    async function uploadKeyBundle(apiBase, token, bundle) {
        var resp = await fetch(apiBase + '/v1/signal/keys/upload', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + token,
            },
            body: JSON.stringify(bundle),
        });
        if (!resp.ok) {
            var err = await resp.json();
            throw new Error('Signal key upload failed: ' + (err.error || resp.status));
        }
        return resp.json();
    }

    async function fetchPreKeyBundle(apiBase, token, targetPhone) {
        var resp = await fetch(apiBase + '/v1/signal/keys/bundle?phone=' + encodeURIComponent(targetPhone), {
            method: 'GET',
            headers: { 'Authorization': 'Bearer ' + token },
        });
        if (!resp.ok) {
            var err = await resp.json();
            throw new Error('Signal bundle fetch failed: ' + (err.error || resp.status));
        }
        return resp.json();
    }

    async function replenishOTPKs(apiBase, token, keys) {
        var resp = await fetch(apiBase + '/v1/signal/keys/replenish', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + token,
            },
            body: JSON.stringify(keys),
        });
        if (!resp.ok) {
            var err = await resp.json();
            throw new Error('OTPK replenish failed: ' + (err.error || resp.status));
        }
        return resp.json();
    }

    async function getOTPKCount(apiBase, token, credentialId) {
        var resp = await fetch(apiBase + '/v1/signal/keys/count?credentialId=' + encodeURIComponent(credentialId), {
            method: 'GET',
            headers: { 'Authorization': 'Bearer ' + token },
        });
        if (!resp.ok) {
            var err = await resp.json();
            throw new Error('OTPK count failed: ' + (err.error || resp.status));
        }
        return resp.json();
    }

    // -- Full key bundle generation and upload --

    async function ensureSignalKeys(apiBase, token, prfOutput, credentialId) {
        // Check if keys already uploaded for this credential
        var countData;
        try {
            countData = await getOTPKCount(apiBase, token, credentialId);
        } catch (e) {
            // 404 means no keys uploaded yet
            countData = { count: -1 };
        }

        if (countData.count >= 0 && countData.hasIdentity) {
            // Keys exist; replenish OTPKs if low
            if (countData.count < 5) {
                await replenishSignalOTPKs(apiBase, token, prfOutput, credentialId, countData.nextKeyId || 0);
            }
            return;
        }

        // Generate full key bundle
        var identity = deriveSignalIdentityKey(prfOutput, credentialId);
        var signedPreKey = generateSignedPreKey(identity.privateKey, 1);
        var otpks = generateOneTimePreKeys(1, 20);

        // Encrypt all private keys
        var encSPK = await encryptPreKeyPrivate(prfOutput, credentialId, signedPreKey.privateKey);
        var encOTPKs = [];
        for (var i = 0; i < otpks.length; i++) {
            var enc = await encryptPreKeyPrivate(prfOutput, credentialId, otpks[i].privateKey);
            encOTPKs.push({
                keyId: otpks[i].keyId,
                publicKey: bytesToB64url(otpks[i].publicKey),
                encryptedPrivateKey: enc.ciphertext,
                iv: enc.iv,
                salt: enc.salt,
            });
        }

        var bundle = {
            credentialId: credentialId,
            identityPublicKey: bytesToB64url(identity.publicKey),
            signedPreKey: {
                keyId: signedPreKey.keyId,
                publicKey: bytesToB64url(signedPreKey.publicKey),
                signature: bytesToB64url(signedPreKey.signature),
                encryptedPrivateKey: encSPK.ciphertext,
                iv: encSPK.iv,
                salt: encSPK.salt,
            },
            oneTimePreKeys: encOTPKs,
        };

        await uploadKeyBundle(apiBase, token, bundle);
        console.log('Signal keys uploaded for credential ' + credentialId.substring(0, 16) + '...');
    }

    async function replenishSignalOTPKs(apiBase, token, prfOutput, credentialId, startId) {
        var otpks = generateOneTimePreKeys(startId, 20);
        var encOTPKs = [];
        for (var i = 0; i < otpks.length; i++) {
            var enc = await encryptPreKeyPrivate(prfOutput, credentialId, otpks[i].privateKey);
            encOTPKs.push({
                keyId: otpks[i].keyId,
                publicKey: bytesToB64url(otpks[i].publicKey),
                encryptedPrivateKey: enc.ciphertext,
                iv: enc.iv,
                salt: enc.salt,
            });
        }

        await replenishOTPKs(apiBase, token, {
            credentialId: credentialId,
            oneTimePreKeys: encOTPKs,
        });
        console.log('Signal OTPKs replenished for credential ' + credentialId.substring(0, 16) + '...');
    }

    // -- Expose API --
    window.Signal = {
        deriveSignalIdentityKey: deriveSignalIdentityKey,
        generateSignedPreKey: generateSignedPreKey,
        generateOneTimePreKeys: generateOneTimePreKeys,
        encryptPreKeyPrivate: encryptPreKeyPrivate,
        decryptPreKeyPrivate: decryptPreKeyPrivate,
        uploadKeyBundle: uploadKeyBundle,
        fetchPreKeyBundle: fetchPreKeyBundle,
        getOTPKCount: getOTPKCount,
        ensureSignalKeys: ensureSignalKeys,
    };
})();
