package io.github.nabhosal.secureapp;

import java.io.Serializable;
import java.time.LocalDateTime;

public interface CertificateFormat extends Serializable, Cloneable {

    public Object getFieldData(String field);
    public LocalDateTime getExpiryDate();
    public CertificateFormat set(String name, Object value);
    public CertificateFormat fromData(Object certificateContent);
}
