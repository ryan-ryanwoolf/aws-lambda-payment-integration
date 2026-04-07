package com.ryanwoolf.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.ryanwoolf.authorizer.util.Env;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;

/**
 * RS256 JWTs: token issuer signs with an RSA private key; API Gateway authorizer verifies with the matching public key.
 */
public final class JwtTokenService {

    public static final String CLAIM_PARTNER = "partner";
    public static final String CLAIM_PARTNER_ID = "partnerId";

    private final Algorithm signingAlgorithm;
    private final Algorithm verificationAlgorithm;
    private final String issuer;
    private final String audience;
    private final int ttlSeconds;

    /**
     * Token issuer Lambda: PEM from {@code JWT_RSA_PRIVATE_KEY_SECRET_ID} (Secrets Manager) or
     * {@code JWT_RSA_PRIVATE_KEY_PEM} (env). See {@link JwtSecretPemLoader}.
     */
    public static JwtTokenService forTokenIssuer() {
        RSAPrivateKey privateKey = RsaPemKeys.parsePkcs8PrivateKey(JwtSecretPemLoader.loadPrivateKeyPem());
        Algorithm sign = Algorithm.RSA256(null, privateKey);
        return new JwtTokenService(
                sign,
                null,
                Env.optional("JWT_ISSUER", "partner-api"),
                Env.optional("JWT_AUDIENCE", "partner-payments"),
                parseTtl(Env.optional("JWT_TTL_SECONDS", "3600")));
    }

    /**
     * JWT authorizer Lambda: PEM from {@code JWT_RSA_PUBLIC_KEY_SECRET_ID} (Secrets Manager) or
     * {@code JWT_RSA_PUBLIC_KEY_PEM} (env).
     */
    public static JwtTokenService forAuthorizer() {
        RSAPublicKey publicKey = RsaPemKeys.parsePublicKey(JwtSecretPemLoader.loadPublicKeyPem());
        Algorithm algorithm = Algorithm.RSA256(publicKey, null);
        return new JwtTokenService(
                null,
                algorithm,
                Env.optional("JWT_ISSUER", "partner-api"),
                Env.optional("JWT_AUDIENCE", "partner-payments"),
                parseTtl(Env.optional("JWT_TTL_SECONDS", "3600")));
    }

    /**
     * Tests: supply both keys so the same instance can sign and verify.
     */
    static JwtTokenService forTests(RSAPrivateKey privateKey, RSAPublicKey publicKey, String issuer, String audience, int ttlSeconds) {
        Algorithm sign = Algorithm.RSA256(publicKey, privateKey);
        Algorithm verify = Algorithm.RSA256(publicKey, null);
        return new JwtTokenService(sign, verify, issuer, audience, ttlSeconds);
    }

    private JwtTokenService(
            Algorithm signingAlgorithm,
            Algorithm verificationAlgorithm,
            String issuer,
            String audience,
            int ttlSeconds) {
        this.signingAlgorithm = signingAlgorithm;
        this.verificationAlgorithm = verificationAlgorithm;
        this.issuer = issuer;
        this.audience = audience;
        this.ttlSeconds = ttlSeconds;
    }

    private static int parseTtl(String raw) {
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            throw new IllegalStateException("JWT_TTL_SECONDS must be a positive integer");
        }
    }

    public String createAccessToken(String partnerId, String partnerDisplayName) {
        if (signingAlgorithm == null) {
            throw new IllegalStateException("Signing is not configured (use forTokenIssuer or forTests with a private key)");
        }
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(ttlSeconds);
        return JWT.create()
                .withIssuer(issuer)
                .withAudience(audience)
                .withSubject(partnerId)
                .withClaim(CLAIM_PARTNER_ID, partnerId)
                .withClaim(CLAIM_PARTNER, partnerDisplayName == null ? "" : partnerDisplayName)
                .withIssuedAt(Date.from(now))
                .withExpiresAt(Date.from(exp))
                .sign(signingAlgorithm);
    }

    public DecodedJWT verify(String token) {
        if (verificationAlgorithm == null) {
            throw new IllegalStateException("Verification is not configured (use forAuthorizer or forTests with a public key)");
        }
        JWTVerifier verifier = JWT.require(verificationAlgorithm).withIssuer(issuer).withAudience(audience).build();
        return verifier.verify(token);
    }

    public int ttlSeconds() {
        return ttlSeconds;
    }
}
