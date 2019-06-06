package com.cv.secureapp.obfuscateInterface;

import com.cv.secureapp.core.SecurityContext;

public class ProxyAccessibleClass {

    /* decorator based validation */
    public static void Method1(){
        /*
            Dynamic Proxies based invocation
            example https://www.baeldung.com/java-dynamic-proxies
                    https://docs.oracle.com/javase/8/docs/technotes/guides/reflection/proxy.html
                    https://jrebel.com/rebellabs/recognize-and-conquer-java-proxies-default-methods-and-method-handles/
         */
        /*
          Below statement, validate the authenticity and expiration of certificate
         */
        SecurityContext.isCertificateValid();
    }
}
