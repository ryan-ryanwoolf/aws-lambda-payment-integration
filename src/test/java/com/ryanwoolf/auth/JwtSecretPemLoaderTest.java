package com.ryanwoolf.auth;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtSecretPemLoaderTest {

    @Test
    void extractPem_rawPemWhenNotJson() {
        String pem = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----";
        assertEquals(pem, JwtSecretPemLoader.extractPem(pem, "JWT_RSA_PRIVATE_KEY_PEM"));
    }

    @Test
    void extractPem_readsJsonKey() {
        String json = "{\"JWT_RSA_PRIVATE_KEY_PEM\":\"-----BEGIN X-----\\nline\\n-----END X-----\"}";
        String out = JwtSecretPemLoader.extractPem(json, "JWT_RSA_PRIVATE_KEY_PEM");
        assertTrue(out.contains("BEGIN X"));
        assertTrue(out.contains("line"));
    }

    @Test
    void extractPem_missingKeyThrows() {
        assertThrows(IllegalStateException.class, () ->
                JwtSecretPemLoader.extractPem("{\"other\":\"v\"}", "JWT_RSA_PRIVATE_KEY_PEM"));
    }
}
