package com.ryanwoolf.transactions;

import com.ryanwoolf.authorizer.util.Env;

import java.math.BigDecimal;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.UUID;

/**
 * Inserts a {@code PENDING} row into {@code payments.payment_transaction} when
 * {@code (partner_id, idempotency_key)} does not already exist.
 */
public final class PostgresPendingTransactionRepository implements PendingTransactionRepository {

    public static final String STATUS_PENDING = "PENDING";

    private static final String INSERT_PENDING = """
            INSERT INTO payments.payment_transaction (
                id, partner_id, idempotency_key, status, amount, currency
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (partner_id, idempotency_key) DO NOTHING
            """;

    private final String jdbcUrl;
    private final String dbUsername;
    private final String dbPassword;

    public PostgresPendingTransactionRepository() {
        this(
                requiredPostgresJdbcUrl(Env.required("PAYMENTS_DB_JDBC_URL")),
                Env.required("PAYMENTS_DB_USERNAME"),
                Env.required("PAYMENTS_DB_PASSWORD"));
    }

    PostgresPendingTransactionRepository(String jdbcUrl, String dbUsername, String dbPassword) {
        this.jdbcUrl = jdbcUrl;
        this.dbUsername = dbUsername;
        this.dbPassword = dbPassword;
    }

    @Override
    public void createIfAbsent(String partnerId, String clientIdempotencyKey, BigDecimal amount, String currency)
            throws DuplicateTransactionException {
        try (Connection connection = DriverManager.getConnection(jdbcUrl, dbUsername, dbPassword);
                PreparedStatement statement = connection.prepareStatement(INSERT_PENDING)) {
            statement.setObject(1, UUID.randomUUID());
            statement.setString(2, partnerId);
            statement.setString(3, clientIdempotencyKey);
            statement.setString(4, STATUS_PENDING);
            statement.setBigDecimal(5, amount);
            statement.setString(6, currency);

            int inserted = statement.executeUpdate();
            if (inserted == 0) {
                throw new DuplicateTransactionException();
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Postgres pending transaction insert failed: " + e.getMessage(), e);
        }
    }

    private static String requiredPostgresJdbcUrl(String raw) {
        String trimmed = raw.trim();
        if (trimmed.regionMatches(true, 0, "jdbc:postgresql://", 0, "jdbc:postgresql://".length())) {
            return trimmed;
        }
        throw new IllegalStateException(
                "PAYMENTS_DB_JDBC_URL must be a full PostgreSQL JDBC URL, for example: "
                        + "jdbc:postgresql://host:5432/payments_db");
    }
}
