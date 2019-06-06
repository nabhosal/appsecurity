package com.cv.secureapp.test;

import com.cv.secureapp.core.CertificateBuilder;
import com.cv.secureapp.core.SecurityContext;
import org.junit.Test;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;

import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;

public class TestSecurityContext {

    private static final String PRIVATE_KEY = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKTi9bphbRTp1qxkVLZWpAZWVSarGJXHAvvJPBOpFl2go9gdRtPC34h+RN2dLfD5SO1UHYfXFb0AKbPSRLFtgOPKFlntkyUWDp06ibwsTsvDhraCtWUjZB34P3Wf4dYnT/k4g8KzrsKuSahBT915K/f0qpynjqbeqz14Pjfz3M2JAgMBAAECgYBZ5Y/ZvRJu64rqVI1HGHe3KMymF3SA/I7o3e9OPMr/4vxRcKzT+ZRL46QCO5b3ocIb+tda325vrC4QZ1yia7RwHHjBhpjMr4dRDBf4fev0YokRenCAUGfG8Reff+mXB355cytgbWbr03NBUOpO+8S2/UURGRXIymE0cOLnN9rFDQJBANzhm9gqVa4pcZNIMMB8EZQVfKFyzsOBJnOnRVased9HsG4LC4ITijrV3yPxAXvv2f5nKjTsP7Wlqyx9mSvxPdsCQQC/Gju8FAk6twTW6kZnqERzzAQy4UHnbxOC20nYeNoT4JXe6AdIIvtVeY4IqQV1JtUl1ENwgArOiEUuogFElclrAkEA1uwrsU2YKywmWDJBRbozfIzfxVSp/a+4U4aqQGj4+RqPgLP8kagjs5YRVq6WTBsZWaLWfcJ3R2+ZPGRF220USwJAJA2C73yoMReOJi2UksHACEiZEjBFCrB98dYFHH3QRqe8Ho2PsiBHYlzIWwHoMa3d0IE3J+ZAI665vo55xsKreQJAV8wUQxS0RNIZ0xojHL7wgcZa7j6OsYsQSsy2JUvFAqJav8D5I6HfXbUYNbhVhtnPuF9OhhbD7t/FWLrORzfMyw==";

    @Test
    public void check_initialization(){

        String rawdata = "2019-06-01T18:30:27.298||2019-06-07T18:30:27.298||"+ LocalDateTime.now().plusMinutes(3)+"||2019-06-05T12:59:27.298";
        try {
            String certificateContent = CertificateBuilder.encrypt(rawdata, PRIVATE_KEY);
            String certificatePath = createTempCertificate(certificateContent);
            System.setProperty("cv.secureapp.certificate", certificatePath);
            assertTrue("Failed to initialize", SecurityContext.isCertificateValid());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void check_expire_certificate(){

        String rawdata = "2019-06-01T18:30:27.298||2019-06-07T18:30:27.298||"+ LocalDateTime.now().minusMinutes(3)+"||2019-06-05T12:59:27.298";
        try {
            String certificateContent = CertificateBuilder.encrypt(rawdata, PRIVATE_KEY);
            String certificatePath = createTempCertificate(certificateContent);
            System.setProperty("cv.secureapp.certificate", certificatePath);
            assertFalse("It should give runtime expection Certificate Expired on ", false);
            SecurityContext.isCertificateValid();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void certificate_validity_within_timeframe(){

        String rawdata = "2019-06-01T18:30:27.298||2019-06-07T18:30:27.298||"+ LocalDateTime.now().plusMinutes(3)+"||2019-06-05T12:59:27.298";
        try {
            String certificateContent = CertificateBuilder.encrypt(rawdata, PRIVATE_KEY);
            String certificatePath = createTempCertificate(certificateContent);
            System.setProperty("cv.secureapp.certificate", certificatePath);
            Thread.sleep(2 * 60 * 1000L); // Sleep for 2 minute and the check
            assertTrue( SecurityContext.isCertificateValid());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void certificate_validity_outside_timeframe(){

        String rawdata = "2019-06-01T18:30:27.298||2019-06-07T18:30:27.298||"+ LocalDateTime.now().plusMinutes(1)+"||2019-06-05T12:59:27.298";
        try {
            String certificateContent = CertificateBuilder.encrypt(rawdata, PRIVATE_KEY);
            String certificatePath = createTempCertificate(certificateContent);
            System.setProperty("cv.secureapp.certificate", certificatePath);
            Thread.sleep(2 * 60 * 1000L); // Sleep for 2 minute and the check
            assertTrue( SecurityContext.isCertificateValid());
            assertFalse("It should give runtime expection Certificate Expired on ", false);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void certificate_validity_on_larger_timeframe(){

        String rawdata = "2019-06-01T18:30:27.298||2019-06-07T18:30:27.298||"+ LocalDateTime.now().plusMinutes(4)+"||2019-06-05T12:59:27.298";
        try {
            String certificateContent = CertificateBuilder.encrypt(rawdata, PRIVATE_KEY);
            String certificatePath = createTempCertificate(certificateContent);
            System.setProperty("cv.secureapp.certificate", certificatePath);
            Thread.sleep(2 * 60 * 1000L); // Sleep for 2 minute and the check
            assertTrue( SecurityContext.isCertificateValid());
            assertFalse("It should give runtime expection `Certificate Expired on` ", false);
            Thread.sleep(2 * 60 * 1000L); // Again sleep for 2 minute and the check
            assertTrue( SecurityContext.isCertificateValid());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String createTempCertificate(String certificateContent){

        File tempFile = null;
        try {
            tempFile = File.createTempFile("CERT-",".cipher");
            BufferedWriter bw = new BufferedWriter(new FileWriter(tempFile));
            bw.write(certificateContent);
            bw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return tempFile.getAbsolutePath();
    }
}
