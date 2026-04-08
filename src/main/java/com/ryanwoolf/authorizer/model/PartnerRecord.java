package com.ryanwoolf.authorizer.model;

/**
 * A record representing a partner record in the database.
 */
public record PartnerRecord(String partner, boolean enabled) {
    // Used to create a new PartnerRecord with a partner name and enabled status
    public PartnerRecord(String partner, boolean enabled) {
        this.partner = partner;
        this.enabled = enabled;
    }
}