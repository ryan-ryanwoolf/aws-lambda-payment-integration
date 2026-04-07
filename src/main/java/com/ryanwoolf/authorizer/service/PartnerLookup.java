package com.ryanwoolf.authorizer.service;

import com.ryanwoolf.authorizer.model.PartnerRecord;

public interface PartnerLookup {

    PartnerRecord findByPartnerIdAndApiKey(String partnerId, String apiKey);
}
