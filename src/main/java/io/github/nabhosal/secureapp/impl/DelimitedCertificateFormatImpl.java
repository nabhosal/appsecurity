package io.github.nabhosal.secureapp.impl;

import io.github.nabhosal.secureapp.CertificateFormat;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;


public class DelimitedCertificateFormatImpl implements CertificateFormat {

    private Map<String, Object> options;
    private String certificateContent;

    public DelimitedCertificateFormatImpl(){
        options = new HashMap<>();
        options.put("delimiter", "\\|\\|");
        options.put("secure-field", 2);
    }

//    public static CertificateFormat from(String certificateContent){
//        return new DelimitedCertificateFormatImpl(certificateContent);
//    }

    /**
     *  Extract specific data from encrypted certificate using delimiter and fieldindex for handling certificate
     *  internal shuffling
     *  String rawdata = "2019-06-01T18:30:27.298||2019-06-07T18:30:27.298||2019-06-05T12:59:27.298||2019-06-04T18:30:27.298";
     *  give delimiter = || & fieldIndex = 3
     *  getDataField method return 2019-06-05T12:59:27.298
     *
     * @param field field index to extract
     * @return
     */

    @Override
    public Object getFieldData(String field) {
        validateCertificate();
        return getDataField(certificateContent, String.valueOf(options.get("delimiter")), Integer.valueOf(field));
    }

    @Override
    public LocalDateTime getExpiryDate() {
        validateCertificate();
        return LocalDateTime.parse(String.valueOf(getFieldData(String.valueOf(options.get("secure-field")))));
    }

    @Override
    public CertificateFormat set(String name, Object value) {
        options.put(name,value);
        return this;
    }

    @Override
    public CertificateFormat fromData(Object certificateContent) {
        this.certificateContent = String.valueOf(certificateContent);
        return this;
    }

    private void validateCertificate(){

        if ("".equalsIgnoreCase(this.certificateContent) || certificateContent == null)
            throw new AssertionError("Certificate is absent, kindly use `fromData` method to push certificate");
    }

    private static String getDataField(String certificate, String delimiter, int fieldIndex){

        String fieldValue = certificate.split(delimiter)[fieldIndex];
        return fieldValue;
    }
}
