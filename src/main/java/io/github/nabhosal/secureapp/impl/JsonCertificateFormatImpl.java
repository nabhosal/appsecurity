package io.github.nabhosal.secureapp.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.nabhosal.secureapp.CertificateFormat;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

public class JsonCertificateFormatImpl implements CertificateFormat {

    private static final ObjectMapper objectMapper = new ObjectMapper();
    private Map<String, Object> mJson;
    private Map<String, Object> options;

    public JsonCertificateFormatImpl(){
        options = new HashMap<>();
        options.put("secure-field", "secure-field");
    }

    @Override
    public Object getFieldData(String field) {
        validateCertificate();
        return mJson.getOrDefault(field, "field not found");
    }

    @Override
    public LocalDateTime getExpiryDate() {
        validateCertificate();
        return LocalDateTime.parse(String.valueOf(getFieldData(String.valueOf(options.get("secure-field")))));
    }

    @Override
    public CertificateFormat set(String name, Object value) {
        options.put(name, value);
        return this;
    }

    @Override
    public CertificateFormat fromData(Object certificateContent) {
        try {
            mJson = objectMapper.readValue(String.valueOf(certificateContent), Map.class);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return this;
    }

    private void validateCertificate(){
        if(mJson == null || mJson.size() == 0)
            throw new AssertionError("Certificate is absent, kindly use `fromData` method to push certificate");
    }
}

