package io.github.nabhosal.secureapp.exception;

public class SecurityContextException extends RuntimeException {

    public SecurityContextException(String message, Throwable exception){
        super(message, exception);
    }

    public SecurityContextException(String message){
        super(message);
    }

}
