package com.cv.secureapp.test;

import com.cv.secureapp.core.CertificateUtil;
import com.cv.secureapp.core.Triplet;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static junit.framework.TestCase.assertEquals;


public class TestCertificate {

    @Test
    public void test_build_certificate(){
        String rawdata = "2019-06-01T18:30:27.298||2019-06-07T18:30:27.298||2019-06-05T12:59:27.298||2019-06-04T18:30:27.298";
        CertificateUtil certificateUtil = CertificateUtil.getInstance();
        Triplet<String, String, String> certificate = certificateUtil.buildCertificateForData(rawdata);

        System.out.println("Public Key: "+certificate.$1());
        System.out.println("Private Key: "+certificate.$2());
        System.out.println("Certificate: "+certificate.$3());

        String TcertDate = null;
        try {
            TcertDate = CertificateUtil.getDataField(certificate.$3(), CertificateUtil.getPublicKeyFromText(certificate.$1()), "\\|\\|", 3);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        assertEquals("2019-06-04T18:30:27.298", TcertDate);
    }

}
