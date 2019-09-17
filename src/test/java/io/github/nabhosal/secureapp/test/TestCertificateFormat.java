package io.github.nabhosal.secureapp.test;

import io.github.nabhosal.secureapp.CertificateFormat;
import io.github.nabhosal.secureapp.impl.DelimitedCertificateFormatImpl;
import org.junit.Test;

import java.time.LocalDateTime;

import static junit.framework.TestCase.assertTrue;

public class TestCertificateFormat {

    @Test
    public void testBasic(){

        LocalDateTime TExp = LocalDateTime.now().plusMinutes(3);
        String rawdata = "2019-06-01T18:30:27.298||2019-06-07T18:30:27.298||"+ TExp +"||2019-06-05T12:59:27.298";
        CertificateFormat format = new DelimitedCertificateFormatImpl().set("secure-field", 2);
        format.fromData(rawdata);
        assertTrue("Expiry time mis-match", TExp.isEqual(format.getExpiryDate()));
        assertTrue("Field retrieve is not working", "2019-06-01T18:30:27.298".equalsIgnoreCase(String.valueOf(format.getFieldData("0"))));
    }

    @Test
    public void testWithDifferentDelimiters(){

        LocalDateTime TExp = LocalDateTime.now().plusMinutes(3);
        String delimiter = "\t";
        String rawdata = "2019-06-01T18:30:27.298"+delimiter+"2019-06-07T18:30:27.298"+delimiter+TExp+delimiter+"2019-06-05T12:59:27.298";
        CertificateFormat format = new DelimitedCertificateFormatImpl().set("secure-field", 2).set("delimiter", delimiter);
        format.fromData(rawdata);
        assertTrue("Expiry time mis-match", TExp.isEqual(format.getExpiryDate()));
        assertTrue("Field retrieve is not working", "2019-06-05T12:59:27.298".equalsIgnoreCase(String.valueOf(format.getFieldData("3"))));


        TExp = LocalDateTime.now().plusMinutes(3);
        delimiter = ",";
        rawdata = "2019-06-01T18:30:27.298"+delimiter+"2019-06-07T18:30:27.298"+delimiter+TExp+delimiter+"2019-06-05T12:59:27.298";
        format = new DelimitedCertificateFormatImpl().set("secure-field", 2).set("delimiter", delimiter);
        format.fromData(rawdata);
        assertTrue("Expiry time mis-match", TExp.isEqual(format.getExpiryDate()));
        assertTrue("Field retrieve is not working", "2019-06-05T12:59:27.298".equalsIgnoreCase(String.valueOf(format.getFieldData("3"))));

        TExp = LocalDateTime.now().plusMinutes(3);
        delimiter = "CUSTOM_DELIMITER";
        rawdata = "2019-06-01T18:30:27.298"+delimiter+"2019-06-07T18:30:27.298"+delimiter+TExp+delimiter+"2019-06-05T12:59:27.298";
        format = new DelimitedCertificateFormatImpl().set("secure-field", 2).set("delimiter", delimiter);
        format.fromData(rawdata);
        assertTrue("Expiry time mis-match", TExp.isEqual(format.getExpiryDate()));
        assertTrue("Field retrieve is not working", "2019-06-05T12:59:27.298".equalsIgnoreCase(String.valueOf(format.getFieldData("3"))));

    }
}
