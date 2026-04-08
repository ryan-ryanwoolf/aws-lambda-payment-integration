package com.ryanwoolf.auth;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Loads RSA keys from PEM text suitable for Lambda environment variables
 * (use real newlines or {@code \n} escapes in a single-line value).
 */
public final class RsaPemKeys {

    private RsaPemKeys() {
    }

    /**
     * PKCS#8 private key: lines between {@code -----BEGIN PRIVATE KEY-----} and
     * {@code -----END PRIVATE KEY-----}.
     */
    // Used to parse the private key from the PEM string
    public static RSAPrivateKey parsePkcs8PrivateKey(String pemFromEnv) {
        String pem = normalizePem(pemFromEnv);
        byte[] der = extractBase64Der(pem, "PRIVATE KEY");
        try {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
            return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (Exception e) {
            throw new IllegalStateException("Invalid JWT RSA private key PEM", e);
        }
    }

    /**
     * SubjectPublicKeyInfo public key: lines between
     * {@code -----BEGIN PUBLIC KEY-----} and {@code -----END PUBLIC KEY-----}.
     */
    // Used to parse the public key from the PEM string
    public static RSAPublicKey parsePublicKey(String pemFromEnv) {
        String pem = normalizePem(pemFromEnv);
        byte[] der = extractBase64Der(pem, "PUBLIC KEY");
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (Exception e) {
            throw new IllegalStateException("Invalid JWT RSA public key PEM", e);
        }
    }

    // Used to normalize the PEM string so that we can compare the expected PEM to
    // the actual PEM
    // Newlines are normalized to \n
    static String normalizePem(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalStateException("PEM string is blank");
        }
        return raw.replace("\\n", "\n").trim();
    }

    private static byte[] extractBase64Der(String pem, String label) {
        String begin = "-----BEGIN " + label + "-----";
        String end = "-----END " + label + "-----";
        int i = pem.indexOf(begin);
        int j = pem.indexOf(end);
        if (i < 0 || j < 0 || j <= i) {
            throw new IllegalStateException("PEM must contain " + begin + " and " + end);
        }
        String b64 = pem.substring(i + begin.length(), j).replaceAll("\\s", "");
        return Base64.getDecoder().decode(b64);
    }
}
