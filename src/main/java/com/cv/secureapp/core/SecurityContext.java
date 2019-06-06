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

public class SecurityContext implements Cloneable, Serializable {

    private static final String DEFAULT_CERT_SYS_FUNC_NAME = "cv.secureapp.certificate";
    private static final String DEFAULT_NTP_FUNC_NAME = "cv.secureapp.ntpserver";
    private static final String DEFAULT_NS_SERVER = "time-a.nist.gov";
    private static final String CIPHER_DELIMITER = "\\|\\|";
    private static final int CIPHER_SECURE_FIELD = 3;
    private static final int MAX_RETRY_ATTEMP = 3;
    private static final int SEED_EXPONENTIAL_FACTOR = 3;
    private static final String PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCk4vW6YW0U6dasZFS2VqQGVlUmqxiVxwL7yTwTqRZdoKPYHUbTwt+IfkTdnS3w+UjtVB2H1xW9ACmz0kSxbYDjyhZZ7ZMlFg6dOom8LE7Lw4a2grVlI2Qd+D91n+HWJ0/5OIPCs67CrkmoQU/deSv39Kqcp46m3qs9eD4389zNiQIDAQAB";

    public static TAppTime context = new TAppTime();

    public static boolean isCertificateValid(){
        return context.isCertificateValid();
    }

    static class TAppTime{

        private boolean isValid;
        private final LocalDateTime tCertExpire;

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

        private void scheduleNTPTimerSynJob() {
            TimerTask repeatedTask = new NTPTimerSynJob(this);
            Timer timer = new Timer("scheduleNTPTimerSynJob");

            long delay = 1000L;
//            long period = 1000L * 60L * 60L;
            long period = 1000L * 60L;
            timer.scheduleAtFixedRate(repeatedTask, delay, period);
        }

        private boolean isCertificateValid(){
            return this.isValid;
        }

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

        private LocalDateTime getTimeFromNTPOrFail(){

            int retryCount = 1;
            int factor = SEED_EXPONENTIAL_FACTOR; // exponential increase next attempt time

            while(retryCount <= MAX_RETRY_ATTEMP){
                System.out.println("retryCount "+retryCount+" "+Instant.now());
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

        static int mockAttempt = 1;
        private LocalDateTime getTimeFromNTPMock(){

            System.out.println("getTimeFromNTPMock mockAttempt "+mockAttempt);
            if(mockAttempt == 2)
                return LocalDateTime.now();
            mockAttempt++;
            return null;
        }

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

    static class NTPTimerSynJob extends TimerTask{

        private final TAppTime tAppTime;

        public NTPTimerSynJob(TAppTime tAppTime){
            this.tAppTime = tAppTime;
        }

        @Override
        public void run() {
            System.out.println("Task performed on " + new Date());
            LocalDateTime ntpTime = tAppTime.getTimeFromNTPOrFail();
            if(ntpTime == null){
                throw new RuntimeException("Not able to get time from NTP server");
            }
            tAppTime.isValid = true;
        }
    }

}
