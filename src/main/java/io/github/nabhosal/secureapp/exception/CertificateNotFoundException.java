package io.github.nabhosal.secureapp.exception;

public class CertificateNotFoundException extends RuntimeException{

    public CertificateNotFoundException(String message, Throwable exception){
        super(message, exception);
    }
    public CertificateNotFoundException(String message){
        super(message);
    }

}
