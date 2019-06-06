package com.cv.secureapp.core;

import org.apache.commons.net.ntp.NTPUDPClient;
import org.apache.commons.net.ntp.TimeInfo;

import java.io.IOException;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;

/**
 * SecurityContext is singleton implementation to validate the certificates and make sure
 * context is valid till only TCert time(time mentioned in certificate)
 * the implementation avoid the use of system / machine time, to get time it relies on Network Time Server through
 * NTP Protocol
 * NTPTimerSynJob a internal Class is used to sync internal time reference (i.e TApp) with NTS service.
 * TAppTime class take TCert time and do comparison with TApp time, It also refresh TApp time with NTS service.
 *
 * SecurityContext.isCertificateValid() method will return True, if everything is fine or else Runtime Exception
 * Since we don't want jar service to be used after certificate expire, it will always give runtime exception instead of false
 */
public class SecurityContext implements Cloneable, Serializable {

    /* System property to get certificate path */
    private static final String DEFAULT_CERT_SYS_FUNC_NAME = "cv.secureapp.certificate";

    /* System property to get ntp server hostname */
    private static final String DEFAULT_NTP_FUNC_NAME = "cv.secureapp.ntpserver";

    /* default network server */
    private static final String DEFAULT_NS_SERVER = "time-a.nist.gov";

    /* Conf for extracting data from Cipher / Certificate */
    private static final String CIPHER_DELIMITER = "\\|\\|";
    private static final int CIPHER_SECURE_FIELD = 3;

    /* Max retry for getting time from ns server */
    private static final int MAX_RETRY_ATTEMP = 3;

    /* for adding exponential time delay between each retry */
    private static final int SEED_EXPONENTIAL_FACTOR = 3;

    /* Hardcode Public Key, When certificate is build Change public key with certificate public key */
    private static final String PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCk4vW6YW0U6dasZFS2VqQGVlUmqxiVxwL7yTwTqRZdoKPYHUbTwt+IfkTdnS3w+UjtVB2H1xW9ACmz0kSxbYDjyhZZ7ZMlFg6dOom8LE7Lw4a2grVlI2Qd+D91n+HWJ0/5OIPCs67CrkmoQU/deSv39Kqcp46m3qs9eD4389zNiQIDAQAB";

    /* TApp Context */
    private static final TAppTime context = new TAppTime();

    /**
     * check if certificate is provided, and it is a valid certificate, able to get TCert date
     * TCert datetime is greater then TApp datetime
     * @return
     */
    public static boolean isCertificateValid(){
        return context.isCertificateValid();
    }

    /**
     * Internal Helper class, used to validate certificate and implementation make sure
     * TAppTime is less then TCert while TAppTime getting refreshed regularly
     */
    static class TAppTime{

        private boolean isValid;
        private final LocalDateTime tCertExpire;

        /**
         * Read Certificate, get time from NTP Server.
         * Set isValid to true, if TCert < TAppTime
         * Schedule Job/Thread for Syncing TAppTime
         */
        TAppTime(){
            String certificatePath = System.getProperty(DEFAULT_CERT_SYS_FUNC_NAME, "NONE");
            if("NONE".equals(certificatePath)){
                throw new RuntimeException("Certificate not found");
            }

            this.tCertExpire = readCertificate(certificatePath);

            LocalDateTime ntpTime = getTimeFromNTPOrFail();
            if(ntpTime == null){
                throw new RuntimeException("Not able to get time from NTP server");
            }

            System.out.println("tCertExpire "+tCertExpire+ " ntpTime "+ntpTime);
            if(IsCertificateTimeValid(tCertExpire, ntpTime)){
                this.isValid = true;
            }else{
                throw new RuntimeException("Certificate Expired on "+tCertExpire);
            }

            scheduleNTPTimerSynJob();
        }

        private boolean IsCertificateTimeValid(LocalDateTime TCertTime, LocalDateTime NTPTime){
            return TCertTime.isAfter(NTPTime) ? true : false;
        }

        /**
         *  Schedule TAppTime Refresh by using NTPTimerSynJob Class based on TimerTask Implementation
         *  Configurable for refresh duration using period variable
         */
        private void scheduleNTPTimerSynJob() {
            TimerTask repeatedTask = new NTPTimerSynJob(this);
            Timer timer = new Timer("scheduleNTPTimerSynJob");

            long delay = 1000L;
            // long period = 1000L * 60L * 60L; // Hourly
            long period = 1000L * 60L;         // Every Minute
            timer.scheduleAtFixedRate(repeatedTask, delay, period);
        }

        private boolean isCertificateValid(){
            return this.isValid;
        }

        /**
         * Read Certificate from absFilePath and decrypt the certificate with public key and extract TCert datetime
         * TCert time is extracted from Certificate
         * @param absFilePath
         * @return TCert datetime
         */
        private LocalDateTime readCertificate(String absFilePath){

            byte[] certificateContent;
            try{
                certificateContent = Files.readAllBytes(Paths.get(absFilePath));
            }catch (IOException e){
                throw new RuntimeException("Not able to read certificate file at "+absFilePath);
            }

            PublicKey publicKey = null;
            try {
                publicKey = CertificateBuilder.getPublicKeyFromText(PUBLIC_KEY);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidKeySpecException e) {
                e.printStackTrace();
            }

            String fieldValue = CertificateBuilder.getDataField(new String(certificateContent),
                                                                publicKey,
                                                                CIPHER_DELIMITER,
                                                                CIPHER_SECURE_FIELD - 1
                                                                );
            return LocalDateTime.parse(fieldValue);
        }

        /**
         * The getTimeFromNTPOrFail method try to get TAppTime from NS servers,
         * it retry for MAX_RETRY_ATTEMP with delay of SEED_EXPONENTIAL_FACTOR
         * @return TAppTime or Null
         */
        private LocalDateTime getTimeFromNTPOrFail(){

            int retryCount = 1;
            int factor = SEED_EXPONENTIAL_FACTOR; // exponential increase next attempt time

            while(retryCount <= MAX_RETRY_ATTEMP){
//                System.out.println("retryCount "+retryCount+" "+Instant.now());
                LocalDateTime ntptime = getTimeFromNTP();

                if (ntptime != null){
                    return ntptime;
                }

                try {
                    if(retryCount == SEED_EXPONENTIAL_FACTOR)
                        break;
                    Thread.sleep(1000L * (retryCount+factor));
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                retryCount++;
                factor += factor;
            }
            return null;
        }

//        Mock Implementation to test retry
//        static int mockAttempt = 1;
//        private LocalDateTime getTimeFromNTPMock(){
//
//            System.out.println("getTimeFromNTPMock mockAttempt "+mockAttempt);
//            if(mockAttempt == 2)
//                return LocalDateTime.now();
//            mockAttempt++;
//            return null;
//        }

        /**
         * the getTimeFromNTP method connect to network server using NTPUDP Client to retrieve TnsTime
         * @return
         */
        private LocalDateTime getTimeFromNTP(){
            String nsServer = System.getProperty(DEFAULT_NTP_FUNC_NAME, DEFAULT_NS_SERVER);
            System.out.println(nsServer);
            NTPUDPClient timeClient = new NTPUDPClient();
            InetAddress inetAddress = null;
            try {
                inetAddress = InetAddress.getByName(nsServer);
            } catch (UnknownHostException e) {
                e.printStackTrace();
                return null;
            }
            TimeInfo timeInfo = null;
            try {
                timeInfo = timeClient.getTime(inetAddress);
            } catch (IOException e) {
                e.printStackTrace();
                return null;
            }
            long returnTime = timeInfo.getMessage().getTransmitTimeStamp().getTime();
            Instant instant = Instant.ofEpochMilli(returnTime);

            return instant.atZone(ZoneId.systemDefault()).toLocalDateTime();
        }
    }

    /**
     *  NTPTimerSynJob class is used to create task for updating TAppTime, a executor is schedule
     *  to run task periodically
     */
    static class NTPTimerSynJob extends TimerTask{

        private final TAppTime tAppTime;

        public NTPTimerSynJob(TAppTime tAppTime){
            this.tAppTime = tAppTime;
        }

        @Override
        public void run() {
//            System.out.println("Task performed on " + new Date());
            LocalDateTime ntpTime = tAppTime.getTimeFromNTPOrFail();
            if(ntpTime == null){
                tAppTime.isValid = false;
                throw new RuntimeException("Not able to get time from NTP server");
            }
            tAppTime.isValid = true;
        }
    }

}
