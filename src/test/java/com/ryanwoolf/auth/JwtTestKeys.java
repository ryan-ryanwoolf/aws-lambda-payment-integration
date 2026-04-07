package com.ryanwoolf.auth;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

final class JwtTestKeys {

    private JwtTestKeys() {}

    static KeyPair rsa2048() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static JwtTokenService jwtService(KeyPair keyPair, int ttlSeconds) {
        return JwtTokenService.forTests(
                (RSAPrivateKey) keyPair.getPrivate(),
                (RSAPublicKey) keyPair.getPublic(),
                "partner-api",
                "partner-payments",
                ttlSeconds);
    }
}
