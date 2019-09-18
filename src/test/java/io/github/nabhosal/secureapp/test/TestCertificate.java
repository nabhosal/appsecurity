package io.github.nabhosal.secureapp.test;

import io.github.nabhosal.secureapp.CertificateFormat;
import io.github.nabhosal.secureapp.utils.CertificateUtil;
import io.github.nabhosal.secureapp.utils.Triplet;
import io.github.nabhosal.secureapp.impl.DelimitedCertificateFormatImpl;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static junit.framework.TestCase.assertTrue;


public class TestCertificate {

    @Test
    public void test_build_certificate(){

        String rawdata = "2019-06-01T18:30:27.298||other important stuff||2019-06-05T12:59:27.298||2019-06-04T18:30:27.298";
        CertificateUtil certificateUtil = CertificateUtil.getInstance();
        Triplet<String, String, String> certificate = certificateUtil.buildCertificateForData(rawdata);

        System.out.println("Public Key: "+certificate.$1());
        System.out.println("Private Key: "+certificate.$2());
        System.out.println("Certificate: "+certificate.$3());

        String tCertContent = null;
        try {

            tCertContent = CertificateUtil.getCertificateContent(certificate.$3(), CertificateUtil.getPublicKeyFromText(certificate.$1()));
            assertTrue("Certificate is not same", rawdata.equalsIgnoreCase(tCertContent));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        CertificateFormat cf = new DelimitedCertificateFormatImpl().fromData(tCertContent).set("secure-field", 0);

        assertTrue("Texp is not matching", "2019-06-01T18:30:27.298".equalsIgnoreCase(cf.getExpiryDate().toString()));
        assertTrue("Field value is not matching", "other important stuff".equalsIgnoreCase(String.valueOf(cf.getFieldData("1"))));
    }

}
