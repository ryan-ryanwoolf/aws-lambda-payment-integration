package com.ryanwoolf.authorizer.service;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

import java.nio.charset.StandardCharsets;

/**
 * Hashes and verifies API keys using Argon2id.
 */
public final class Argon2ApiKeyHashService {

    private static final int ITERATIONS = 3;
    private static final int MEMORY_KIB = 65_536;
    private static final int PARALLELISM = 1;

    public String hashForStorage(String apiKey) {
        Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
        char[] chars = apiKey.toCharArray();
        try {
            return argon2.hash(ITERATIONS, MEMORY_KIB, PARALLELISM, chars, StandardCharsets.UTF_8);
        } finally {
            argon2.wipeArray(chars);
        }
    }

    public boolean matches(String apiKey, String encodedHash) {
        Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
        char[] chars = apiKey.toCharArray();
        try {
            return argon2.verify(encodedHash, chars, StandardCharsets.UTF_8);
        } finally {
            argon2.wipeArray(chars);
        }
    }
}
