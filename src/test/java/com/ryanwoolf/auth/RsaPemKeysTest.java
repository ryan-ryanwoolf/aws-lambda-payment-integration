package com.ryanwoolf.auth;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class RsaPemKeysTest {

    @Test
    void parsesEscapedNewlines() {
        KeyPair kp = JwtTestKeys.rsa2048();
        String singleLinePrivate = pkcs8Pem((RSAPrivateKey) kp.getPrivate()).replace("\n", "\\n");
        String singleLinePublic = spkiPublicPem((RSAPublicKey) kp.getPublic()).replace("\n", "\\n");

        assertDoesNotThrow(() -> {
            RSAPrivateKey priv = RsaPemKeys.parsePkcs8PrivateKey(singleLinePrivate);
            RSAPublicKey pub = RsaPemKeys.parsePublicKey(singleLinePublic);
            AlgorithmSmoke.signVerify(priv, pub);
        });
    }

    /** Minimal RS256 sign/verify using parsed keys. */
    private static final class AlgorithmSmoke {
        static void signVerify(RSAPrivateKey priv, RSAPublicKey pub) {
            JwtTokenService jwt = JwtTokenService.forTests(priv, pub, "partner-api", "partner-payments", 60);
            String t = jwt.createAccessToken("p", "P");
            jwt.verify(t);
        }
    }

    private static String pkcs8Pem(RSAPrivateKey privateKey) {
        String b64 = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" + b64 + "\n-----END PRIVATE KEY-----\n";
    }

    private static String spkiPublicPem(RSAPublicKey publicKey) {
        String b64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + b64 + "\n-----END PUBLIC KEY-----\n";
    }
}
