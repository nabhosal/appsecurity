package com.cv.secureapp.test;

import com.cv.secureapp.core.CertificateBuilder;
import com.cv.secureapp.core.Triplet;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDateTime;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;


public class TestCertificate {

    @Test
    public void test_build_certificate(){
        String rawdata = "2019-06-01T18:30:27.298||2019-06-07T18:30:27.298||2019-06-05T12:59:27.298||2019-06-04T18:30:27.298";
        CertificateBuilder certificateBuilder = CertificateBuilder.getInstance();
        Triplet<String, String, String> certificate = certificateBuilder.buildCertificateForData(rawdata);

        System.out.println("Public Key: "+certificate.$1());
        System.out.println("Private Key: "+certificate.$2());
        System.out.println("Certificate: "+certificate.$3());

        String TcertDate = null;
        try {
            TcertDate = CertificateBuilder.getDataField(certificate.$3(), CertificateBuilder.getPublicKeyFromText(certificate.$1()), "\\|\\|", 3);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        assertEquals("2019-06-04T18:30:27.298", TcertDate);
    }

    @Test
    public void test(){
        System.out.println("||"+ LocalDateTime.now().plusMinutes(3) +"||");

        try {
            File tempFile = File.createTempFile("CERT-",".cipher");
            System.out.println(tempFile.getAbsolutePath());
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

}
