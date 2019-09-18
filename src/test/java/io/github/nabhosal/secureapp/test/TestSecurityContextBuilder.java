package io.github.nabhosal.secureapp.test;

import io.github.nabhosal.secureapp.utils.CertificateUtil;
import io.github.nabhosal.secureapp.SecurityContext;
import io.github.nabhosal.secureapp.SecurityContextBuilder;
import io.github.nabhosal.secureapp.impl.DelimitedCertificateFormatImpl;
import org.junit.Test;

import java.time.LocalDateTime;

import static io.github.nabhosal.secureapp.test.TestSecurityContext.createTempCertificate;
import static junit.framework.TestCase.assertFalse;

public class TestSecurityContextBuilder {

    private static String PRIVATE_KEY = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC3ee2oXPQmii0Kb0Ye8FUs4J7ZKUSLFChBP4gVRWcqgeXcfsDbeNig1ZOPwq0GBBp9wQWx3iTRABYL0BDSsWKdymGh36ajJn5Ne7ebJCLo/nclcUD7RaEQeD5TzwN3hdqeLX595xVJakyQLhpME4/F2ZGqFa8nFUvSHyrdxdN0EFyYo4z5clpGT5qqhXxIuQ+4NT8ghRhZAqP0Fvn+HlbhzRAeKJxQW/nWK1PVsCZw5Nn0uLWTyosdInhOOIoTnFTgyXoMtmDZCKtt/tIpaw5rqwLczUYZMp57h8qSPmM9fIHIgFhuEEWqSTTs0pRP+TSoYkDMTYsWuXCA8Z3dY2d/AgMBAAECggEAcUyT28H66sms4qKwNG7IyjuzG/sF3rSF3zTyPeBrwq4QWcbUJTNM4pTA2Keo3Owvx7QoZhv9tCpPct/7Y4Aym6nb/G/1oQ4mNIbPbLg17pck0DRNolzvBxKZuns9ctNvmvoRAIJwfLNtsCMoDg6OW+jssJFPZd0awxiICgcdeq+LS4pJ+uFPgc//cFJmD0LV60HUiT0Y1P63wxvmva5MHHEhbCo2eJVXVrxYyGGaWmgW4VPUsQSvohF/2oPjhzeHoStSbDqgEiQkJsM+yWCaIdE4nWxU+YBgRcg/uuBxxp1ZaOm1tuak4G3ap7F4mTQfkPapZBodnfNsMZg5x3SSAQKBgQDrVS990nMgovumVKgf2qbjD1zoLfGxDBTlZWX3+sMan0JGEKUcATFdwx+IODd2cyyf7qePj+J6REQRRXmvEwzuTvAIpza+T7ABRp6crxIkRu0T908Kylt/MBNkzgl8vkzOOmEDCCdOBzZp0z2mu9/v7NeasoJ4anxWkn5gQTXp/wKBgQDHluRBHiVArX133pOABTYCHMvXZw8e3vdN0oR2osg3JORmTSb6Vs8dmTC3DVULQgJBEv3+hmi504+I02i5jsRqxzgqigQxnk7r2LaryhR5VC0I2lqaW8yl+t/813k55oPyURxLFVgPaiz5i78oCT7gRiX3mIza+y0vWzyHDZuCgQKBgDOnegojFFQYkiX7NP/w7WqvZ5Qq6X8UCM4lSJF6wDJqvJBGfQc9l8ld1+D9fecI9sWQC8VuLqbprwsfdcsg4li4iOVNVq3FLfvJtWzs3I2L5+PXB8l1i0nKkqcwtlJkLtWhaMPSmVX+LUpjLIgZetjd4qE5B3xI20vhUc3s4lmfAoGAUFOiObLwOz+Xp46kvnlaay87us13gG0sCt4XAcgx3D+0zJdwgIA/iyIEQSfUeltunNIP90gRDfjfY6nyE/wpgO/84uH5Hh8glDr8CdeitdHy7gUzQbyAeKynSRNPbsYfhH6wbGeCsXGB+E0N+gb+jzSsQyHaTqeYX97QVWpclAECgYAr7PuvH7pFfxDl49juGHXJBN1YmnrTGd4r6Uxv91XXIruIY3lCkRWh2auSS3DKgC0CnPMzSfhVEWH+OuTrd3UdyuXZXJKWcNjTkb9k1rshHIxeSfa+8ROU82WQEEH2idkzgr9qYvNjATqInc05KaJqmj2LkNXneYh1PUUxgCupoA==";
    private static String PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt3ntqFz0JootCm9GHvBVLOCe2SlEixQoQT+IFUVnKoHl3H7A23jYoNWTj8KtBgQafcEFsd4k0QAWC9AQ0rFincphod+moyZ+TXu3myQi6P53JXFA+0WhEHg+U88Dd4Xani1+fecVSWpMkC4aTBOPxdmRqhWvJxVL0h8q3cXTdBBcmKOM+XJaRk+aqoV8SLkPuDU/IIUYWQKj9Bb5/h5W4c0QHiicUFv51itT1bAmcOTZ9Li1k8qLHSJ4TjiKE5xU4Ml6DLZg2Qirbf7SKWsOa6sC3M1GGTKee4fKkj5jPXyByIBYbhBFqkk07NKUT/k0qGJAzE2LFrlwgPGd3WNnfwIDAQAB";

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
            SecurityContextBuilder.withDefault()
                    .useCertificateVariableName("custom_path_test")
                    .withInterval(SecurityContextBuilder.INTERVAL.MINUTE.getTime() * 1L)
                    .withPublicKey(PUBLIC_KEY)
                    .withCertificateFormat(new DelimitedCertificateFormatImpl())
                    .initialize();
            SecurityContext.isCertificateValid();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test(expected = AssertionError.class)
    public void check_multi_securityContext(){

        String expiredCertificate = "2019-06-01T18:30:27.298||2019-06-07T18:30:27.298||"+ LocalDateTime.now().plusSeconds(10)+"||2019-06-05T12:59:27.298";
        String validCertificate = "2019-06-01T18:30:27.298||2019-06-07T18:30:27.298||"+ LocalDateTime.now().plusMinutes(3)+"||2019-06-05T12:59:27.298";
        String expiredCertificateContent = null;
        String validCertificateContent = null;
        try {
            expiredCertificateContent = CertificateUtil.encrypt(expiredCertificate, PRIVATE_KEY);
            validCertificateContent = CertificateUtil.encrypt(validCertificate, PRIVATE_KEY);
        } catch (Exception e) {
            e.printStackTrace();
        }
        String expiredCertificatePath = createTempCertificate(expiredCertificateContent);
        System.setProperty("cv.secureapp.certificate", expiredCertificatePath);

        SecurityContextBuilder.withDefault().withPublicKey(PUBLIC_KEY).initialize();

        /* It must throw java.lang.RuntimeException: Certificate Expired on  */
        SecurityContext.isCertificateValid();


        String validCertificateContentPath = createTempCertificate(validCertificateContent);
        System.setProperty("cv.secureapp.certificate", validCertificateContentPath);

        SecurityContextBuilder.withDefault().withPublicKey(PUBLIC_KEY).initialize();
//        SecurityContext.isCertificateValid();
    }
}
