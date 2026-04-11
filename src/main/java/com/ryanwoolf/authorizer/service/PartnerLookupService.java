package com.ryanwoolf.authorizer.service;

import com.ryanwoolf.authorizer.model.PartnerRecord;
import com.ryanwoolf.authorizer.util.Env;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Locale;
import java.util.logging.Logger;

public class PartnerLookupService implements PartnerLookup {
    private static final Logger LOGGER = Logger.getLogger(PartnerLookupService.class.getName());

    private static final String DEFAULT_ALLOWED_ROLES = "SUPER,PAYMENT";
    private static final String FIND_PARTNER_SQL = """
            SELECT p.display_name, p.enabled, ps.partner_secret_hash
            FROM auth.partner p
            JOIN auth.partner_secret ps ON ps.partner_fk = p.id
            WHERE p.partner_id = ?
              AND ps.active = TRUE
              AND (ps.expires_at IS NULL OR ps.expires_at > CURRENT_TIMESTAMP)
              AND EXISTS (
                  SELECT 1
                  FROM auth.partner_role pr
                  JOIN auth.role r ON r.id = pr.role_fk
                  WHERE pr.partner_fk = p.id
                    AND r.role_code = ANY (?)
              )
            ORDER BY ps.created_at DESC
            LIMIT 1
            """;

    private final Argon2ApiKeyHashService argon2ApiKeyHashService;
    private final String jdbcUrl;
    private final String dbUsername;
    private final String dbPassword;
    private final String[] allowedRoleCodes;

    public PartnerLookupService() {
        this(
                new Argon2ApiKeyHashService(),
                requiredPostgresJdbcUrl(),
                Env.required("AUTH_DB_USERNAME"),
                Env.required("AUTH_DB_PASSWORD"),
                parseAllowedRoles(Env.optional("AUTH_ALLOWED_ROLE_CODES", DEFAULT_ALLOWED_ROLES)));
    }

    PartnerLookupService(
            Argon2ApiKeyHashService argon2ApiKeyHashService,
            String jdbcUrl,
            String dbUsername,
            String dbPassword,
            String[] allowedRoleCodes) {
        this.argon2ApiKeyHashService = argon2ApiKeyHashService;
        this.jdbcUrl = jdbcUrl;
        this.dbUsername = dbUsername;
        this.dbPassword = dbPassword;
        this.allowedRoleCodes = allowedRoleCodes;
    }

    @Override
    public PartnerRecord findByPartnerIdAndApiKey(String partnerId, String apiKey) {
        LOGGER.info(() -> "Partner lookup started: partnerId=" + partnerId + ", database=postgres");
        try (Connection connection = DriverManager.getConnection(jdbcUrl, dbUsername, dbPassword);
                PreparedStatement statement = connection.prepareStatement(FIND_PARTNER_SQL)) {
            statement.setString(1, partnerId);
            statement.setArray(2, connection.createArrayOf("text", allowedRoleCodes));

            try (ResultSet rs = statement.executeQuery()) {
                if (!rs.next()) {
                    LOGGER.info(() -> "Partner lookup result: no eligible row found for partnerId=" + partnerId);
                    return null;
                }

                String partnerSecretHash = rs.getString("partner_secret_hash");
                if (partnerSecretHash == null || partnerSecretHash.isBlank()) {
                    LOGGER.warning(() -> "Partner row missing partner_secret_hash for partnerId=" + partnerId);
                    return null;
                }

                if (!argon2ApiKeyHashService.matches(apiKey, partnerSecretHash)) {
                    LOGGER.info(() -> "API key hash verification failed for partnerId=" + partnerId);
                    return null;
                }

                String partner = rs.getString("display_name");
                boolean enabled = rs.getBoolean("enabled");
                LOGGER.info(() -> "Partner lookup result: partnerId=" + partnerId + ", enabled=" + enabled);
                return new PartnerRecord(partner, enabled);
            }
        } catch (SQLException e) {
            String details = "Postgres partner lookup failed: sqlState=" + e.getSQLState()
                    + ", errorCode=" + e.getErrorCode()
                    + ", message=" + e.getMessage();
            LOGGER.severe(details);
            throw new IllegalStateException(details, e);
        } catch (Exception e) {
            String details = "Postgres partner lookup failed: " + e.getMessage();
            LOGGER.severe(details);
            throw new IllegalStateException(details, e);
        }
    }

    private static String[] parseAllowedRoles(String csvRoleCodes) {
        return csvRoleCodes
                .trim()
                .toUpperCase(Locale.ROOT)
                .replace(" ", "")
                .split(",");
    }

    private static String requiredPostgresJdbcUrl() {
        String raw = Env.required("AUTH_DB_JDBC_URL").trim();
        if (raw.regionMatches(true, 0, "jdbc:postgresql://", 0, "jdbc:postgresql://".length())) {
            return raw;
        }
        throw new IllegalStateException(
                "AUTH_DB_JDBC_URL must be a full PostgreSQL JDBC URL, for example: "
                        + "jdbc:postgresql://payments-postgres.cpmgyowgui8a.eu-west-1.rds.amazonaws.com:5432/payments_db");
    }
}
