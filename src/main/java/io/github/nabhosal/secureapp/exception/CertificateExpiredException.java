package io.github.nabhosal.secureapp.exception;

public class CertificateExpiredException extends RuntimeException {

    public CertificateExpiredException(String message){
        super(message);
    }
}
