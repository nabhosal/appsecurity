package com.cv.secureapp.core;

import java.io.Serializable;
import java.time.LocalDateTime;

public interface CertificateFormat extends Serializable, Cloneable {

    public String encode();
    public Object getFieldData(String field);
    public LocalDateTime getExpiryDate();
    public CertificateFormat setOption(String name, Object value);
    public Object getOption(String name);
}
