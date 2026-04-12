package com.ryanwoolf.db;

import com.ryanwoolf.authorizer.util.Env;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

import javax.sql.DataSource;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Lazily creates one {@link HikariDataSource} per logical database for the lifetime of the
 * Lambda execution environment. Reusing a pool avoids opening a new TCP connection to RDS on
 * every invocation after the container is warm.
 * <p>
 * Pool sizes stay small: each Lambda instance runs one request at a time, but concurrent
 * operations inside a handler could use more than one connection; total DB load scales with
 * concurrent Lambda instances × pool size.
 */
public final class LambdaJdbcPools {

    private static final Object AUTH_LOCK = new Object();
    private static final Object PAYMENTS_LOCK = new Object();
    private static volatile HikariDataSource auth;
    private static volatile HikariDataSource payments;
    private static final AtomicBoolean SHUTDOWN_HOOK_REGISTERED = new AtomicBoolean(false);

    private LambdaJdbcPools() {}

    public static DataSource auth() {
        HikariDataSource ds = auth;
        if (ds == null) {
            synchronized (AUTH_LOCK) {
                ds = auth;
                if (ds == null) {
                    auth = createPool(
                            "auth-db",
                            requirePostgresJdbcUrl(Env.required("AUTH_DB_JDBC_URL"), "AUTH_DB_JDBC_URL"),
                            Env.required("AUTH_DB_USERNAME"),
                            Env.required("AUTH_DB_PASSWORD"),
                            poolMaxSize("AUTH_DB_POOL_MAX_SIZE"));
                    registerShutdownHookOnce();
                    ds = auth;
                }
            }
        }
        return ds;
    }

    public static DataSource payments() {
        HikariDataSource ds = payments;
        if (ds == null) {
            synchronized (PAYMENTS_LOCK) {
                ds = payments;
                if (ds == null) {
                    payments = createPool(
                            "payments-db",
                            requirePostgresJdbcUrl(Env.required("PAYMENTS_DB_JDBC_URL"), "PAYMENTS_DB_JDBC_URL"),
                            Env.required("PAYMENTS_DB_USERNAME"),
                            Env.required("PAYMENTS_DB_PASSWORD"),
                            poolMaxSize("PAYMENTS_DB_POOL_MAX_SIZE"));
                    registerShutdownHookOnce();
                    ds = payments;
                }
            }
        }
        return ds;
    }

    private static int poolMaxSize(String envName) {
        String raw = Env.optional(envName, "2").trim();
        try {
            int n = Integer.parseInt(raw);
            if (n < 1 || n > 32) {
                throw new IllegalArgumentException("out of range");
            }
            return n;
        } catch (RuntimeException e) {
            throw new IllegalStateException(
                    envName + " must be an integer between 1 and 32 (default 2), got: " + raw);
        }
    }

    private static HikariDataSource createPool(
            String poolName, String jdbcUrl, String username, String password, int maximumPoolSize) {
        HikariConfig config = new HikariConfig();
        config.setPoolName(poolName);
        config.setJdbcUrl(jdbcUrl);
        config.setUsername(username);
        config.setPassword(password);
        config.setMaximumPoolSize(maximumPoolSize);
        config.setMinimumIdle(0);
        config.setConnectionTimeout(10_000);
        config.setMaxLifetime(25 * 60_000);
        config.setIdleTimeout(10 * 60_000);
        config.setAutoCommit(true);
        return new HikariDataSource(config);
    }

    private static void registerShutdownHookOnce() {
        if (SHUTDOWN_HOOK_REGISTERED.compareAndSet(false, true)) {
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                closeQuietly(auth);
                closeQuietly(payments);
            }, "lambda-jdbc-pools-shutdown"));
        }
    }

    private static void closeQuietly(HikariDataSource ds) {
        if (ds != null && !ds.isClosed()) {
            ds.close();
        }
    }

    private static String requirePostgresJdbcUrl(String raw, String envVarName) {
        String trimmed = raw.trim();
        if (trimmed.regionMatches(true, 0, "jdbc:postgresql://", 0, "jdbc:postgresql://".length())) {
            return trimmed;
        }
        throw new IllegalStateException(
                envVarName + " must be a full PostgreSQL JDBC URL, for example: "
                        + "jdbc:postgresql://host:5432/dbname");
    }
}
