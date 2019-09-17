package io.github.nabhosal.secureapp.test;

import io.github.nabhosal.secureapp.CertificateUtil;
import io.github.nabhosal.secureapp.SecurityContext;
import io.github.nabhosal.secureapp.SecurityContextBuilder;
import io.github.nabhosal.secureapp.impl.DelimitedCertificateFormatImpl;
import org.junit.Test;

import java.time.LocalDateTime;

import static io.github.nabhosal.secureapp.test.TestSecurityContext.createTempCertificate;
import static junit.framework.TestCase.assertFalse;

public class TestSecurityContextBuilder {

    private static final String PRIVATE_KEY = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKTi9bphbRTp1qxkVLZWpAZWVSarGJXHAvvJPBOpFl2go9gdRtPC34h+RN2dLfD5SO1UHYfXFb0AKbPSRLFtgOPKFlntkyUWDp06ibwsTsvDhraCtWUjZB34P3Wf4dYnT/k4g8KzrsKuSahBT915K/f0qpynjqbeqz14Pjfz3M2JAgMBAAECgYBZ5Y/ZvRJu64rqVI1HGHe3KMymF3SA/I7o3e9OPMr/4vxRcKzT+ZRL46QCO5b3ocIb+tda325vrC4QZ1yia7RwHHjBhpjMr4dRDBf4fev0YokRenCAUGfG8Reff+mXB355cytgbWbr03NBUOpO+8S2/UURGRXIymE0cOLnN9rFDQJBANzhm9gqVa4pcZNIMMB8EZQVfKFyzsOBJnOnRVased9HsG4LC4ITijrV3yPxAXvv2f5nKjTsP7Wlqyx9mSvxPdsCQQC/Gju8FAk6twTW6kZnqERzzAQy4UHnbxOC20nYeNoT4JXe6AdIIvtVeY4IqQV1JtUl1ENwgArOiEUuogFElclrAkEA1uwrsU2YKywmWDJBRbozfIzfxVSp/a+4U4aqQGj4+RqPgLP8kagjs5YRVq6WTBsZWaLWfcJ3R2+ZPGRF220USwJAJA2C73yoMReOJi2UksHACEiZEjBFCrB98dYFHH3QRqe8Ho2PsiBHYlzIWwHoMa3d0IE3J+ZAI665vo55xsKreQJAV8wUQxS0RNIZ0xojHL7wgcZa7j6OsYsQSsy2JUvFAqJav8D5I6HfXbUYNbhVhtnPuF9OhhbD7t/FWLrORzfMyw==";

    @Test
    public void basicTest(){

        String rawdata = "2019-06-01T18:30:27.298||2019-06-07T18:30:27.298||"+ LocalDateTime.now().plusMinutes(3)+"||2019-06-05T12:59:27.298";
        try {
            String certificateContent = CertificateUtil.encrypt(rawdata, PRIVATE_KEY);
            String certificatePath = createTempCertificate(certificateContent);
            System.setProperty("cv.secureapp.certificate", certificatePath);
            assertFalse("It should give runtime expection Certificate Expired on ", false);
            SecurityContextBuilder.withDefault().initialize();
            SecurityContext.isCertificateValid();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void basicFlow(){
        String rawdata = "2019-06-01T18:30:27.298||2019-06-07T18:30:27.298||"+ LocalDateTime.now().plusMinutes(3)+"||2019-06-05T12:59:27.298";
        try {
            String certificateContent = CertificateUtil.encrypt(rawdata, PRIVATE_KEY);
            String certificatePath = createTempCertificate(certificateContent);
            System.setProperty("custom_path_test", certificatePath);
            assertFalse("It should give runtime expection Certificate Expired on ", false);
            SecurityContextBuilder.withDefault()
                    .useCertificateVariableName("custom_path_test")
                    .withInterval(SecurityContextBuilder.INTERVAL.MINUTE.getTime() * 1L)
                    .withPublicKey("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCk4vW6YW0U6dasZFS2VqQGVlUmqxiVxwL7yTwTqRZdoKPYHUbTwt+IfkTdnS3w+UjtVB2H1xW9ACmz0kSxbYDjyhZZ7ZMlFg6dOom8LE7Lw4a2grVlI2Qd+D91n+HWJ0/5OIPCs67CrkmoQU/deSv39Kqcp46m3qs9eD4389zNiQIDAQAB")
                    .withCertificateFormat(new DelimitedCertificateFormatImpl())
                    .initialize();
            SecurityContext.isCertificateValid();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
