package com.ryanwoolf.authorizer.service;

import com.ryanwoolf.authorizer.model.PartnerRecord;

public interface PartnerLookup {
    // Used by the partner token issuer to validate the x-api-key for a given x-partner-id and check enabled status
    PartnerRecord findByPartnerIdAndApiKey(String partnerId, String apiKey);
}
