package io.github.nabhosal.secureapp;

import io.github.nabhosal.secureapp.exception.CertificateExpiredException;
import io.github.nabhosal.secureapp.exception.CertificateNotFoundException;
import io.github.nabhosal.secureapp.exception.SecurityContextException;
import io.github.nabhosal.secureapp.utils.CertificateUtil;
import org.apache.commons.net.ntp.NTPUDPClient;
import org.apache.commons.net.ntp.TimeInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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

    private static Logger logger = LogManager.getLogger(SecurityContext.class);

    private static SecurityContext securityContext;

    /* TApp Context */
    private final TAppTime context;

    private SecurityContext(SecurityContextBuilder contextBuilder){

       this.context = new TAppTime(contextBuilder.getNsServer(),
                contextBuilder.getCertSysFuncName(),
                contextBuilder.getPeriodicInterval(),
                contextBuilder.getSeedExponentialFactor(),
                contextBuilder.getMaxRetryAttempt(),
                contextBuilder.getPublicKey(),
                contextBuilder.getCertificateFormat(),
                contextBuilder.isUseLocalInstanceTime());
    }

    /**
     * check if certificate is provided, and it is a valid certificate, able to get TCert date
     * TCert datetime is greater then TApp datetime
     * @return
     */
    public static boolean isCertificateValid(){

        if(securityContext == null) {
            logger.error("SecurityContext->isCertificateValid: SecurityContext is null");
            throw new SecurityContextException("You have to call SecurityContextBuilder.initialize first or Certificate is already expired");
        }
        return securityContext.context.isCertificateValid();
    }

    public synchronized static void init(SecurityContextBuilder contextBuilder) {
        if (securityContext != null)
        {
            // in my opinion this is optional, but for the purists it ensures
            // that you only ever get the same instance when you call getInstance
            logger.error("SecurityContext->isCertificateValid: SecurityContext is null");
            throw new SecurityContextException("You already initialized Security Context");
        }

        securityContext = new SecurityContext(contextBuilder);
    }

    /**
     * Internal Helper class, used to validate certificate and implementation make sure
     * TAppTime is less then TCert while TAppTime getting refreshed regularly
     */
    static class TAppTime{

        private boolean isValid;
        private final LocalDateTime tCertExpire;
        private final int seed_exponential_factor;
        private final int max_retry_attempt;
        private final String ns_server;
        private final long periodicInterval;
        private final String publicKey;
        private final CertificateFormat certificateFormat;
        private final boolean useLocalInstanceTime;

        /**
         * Read Certificate, get time from NTP Server.
         * Set isValid to true, if TCert < TAppTime
         * Schedule Job/Thread for Syncing TAppTime
         */
        TAppTime(String ns_server,
                 String cert_sys_func_name,
                 long periodicInterval,
                 int seed_exponential_factor,
                 int max_retry_attempt,
                 String publicKey,
                 CertificateFormat certificateFormat,
                 boolean useLocalInstanceTime){

            // String ns_server, int seed_exponential_factor, int max_retry_attempt
            this.ns_server = ns_server;
            this.seed_exponential_factor = seed_exponential_factor;
            this.max_retry_attempt = max_retry_attempt;
            this.periodicInterval = periodicInterval;
            this.publicKey = publicKey;
            this.certificateFormat = certificateFormat;
            this.useLocalInstanceTime = useLocalInstanceTime;

            String certificatePath = System.getProperty(cert_sys_func_name, "NONE");
            if("NONE".equals(certificatePath)){
                throw new CertificateNotFoundException("the certificate path variable "+cert_sys_func_name+" is empty ");
            }

            this.tCertExpire = readCertificate(certificatePath);

            LocalDateTime ntpTime = useLocalInstanceTime ? LocalDateTime.now() : getTimeFromNTPOrFail();
            if(ntpTime == null){
                throw new SecurityContextException("Not able to get time from NTP server");
            }

            if(IsCertificateTimeValid(ntpTime)){
                this.isValid = true;
            }else{
                throw new CertificateExpiredException("Certificate expired on "+tCertExpire);
            }

            scheduleTimerSynJob();
        }

        private boolean IsCertificateTimeValid(LocalDateTime NTPTime){
            if(tCertExpire == null)
                return false;
            return tCertExpire.isAfter(NTPTime) ? true : false;
        }

        /**
         *  Schedule TAppTime Refresh by using NTPTimerSynJob Class based on TimerTask Implementation
         *  Configurable for refresh duration using period variable
         */
        private void scheduleTimerSynJob() {
            TimerTask repeatedTask = useLocalInstanceTime ? new InstanceTimeSynJob(this) : new NTPTimerSynJob(this);
            Timer timer = new Timer("scheduleTimerSynJob");

            long delay = 1000L;
            // long period = 1000L * 60L * 60L; // Hourly
//            long period = 1000L * 60L;         // Every Minute
            timer.scheduleAtFixedRate(repeatedTask, delay, this.periodicInterval);
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
                throw new CertificateNotFoundException("Not able to read certificate file at "+absFilePath, e);
            }

            PublicKey publicKey = null;
            try {
                publicKey = CertificateUtil.getPublicKeyFromText(this.publicKey);
            } catch (NoSuchAlgorithmException e) {
                throw new SecurityContextException("Not able to build public key from text", e);
            } catch (InvalidKeySpecException e) {
                throw new SecurityContextException("Not able to build public key from text", e);
            }

            String decipherCertificate =  CertificateUtil.getCertificateContent(new String(certificateContent), publicKey);

            return this.certificateFormat.fromData(decipherCertificate).getExpiryDate();
        }

        /**
         * The getTimeFromNTPOrFail method try to get TAppTime from NS servers,
         * it retry for MAX_RETRY_ATTEMP with delay of SEED_EXPONENTIAL_FACTOR
         * @return TAppTime or Null
         */
        private LocalDateTime getTimeFromNTPOrFail(){

            int retryCount = 1;
            int factor = this.seed_exponential_factor; // exponential increase next attempt time

            while(retryCount <= this.max_retry_attempt){
//                System.out.println("retryCount "+retryCount+" "+Instant.now());
                LocalDateTime ntptime = getTimeFromNTP();

                if (ntptime != null){
                    return ntptime;
                }

                try {
                    if(retryCount == this.max_retry_attempt)
                        break;
                    Thread.sleep(1000L * (retryCount+factor));
                } catch (InterruptedException e) {
                    e.printStackTrace();
                    throw new SecurityContextException("demon thread to get NTP time is interrupted", e);
                }
                retryCount++;
                factor += factor;
            }
            return null;
        }


        /**
         * the getTimeFromNTP method connect to network server using NTPUDP Client to retrieve TnsTime
         * @return
         */
        private LocalDateTime getTimeFromNTP(){
//            String nsServer = System.getProperty(DEFAULT_NTP_FUNC_NAME, DEFAULT_NS_SERVER);
            String nsServer = this.ns_server;
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
                throw new SecurityContextException("Not able to get time from NTP server");
            }
            if(!tAppTime.IsCertificateTimeValid(ntpTime)){
                tAppTime.isValid = false;
                throw new CertificateExpiredException("Certificate validity "+tAppTime.tCertExpire+" is expired on "+ntpTime);
            }
        }
    }

    /**
     *  InstanceTimeSynJob class is used to create task for updating TAppTime, a executor is schedule
     *  to run task periodically using instance/machine time
     */
    static class InstanceTimeSynJob extends TimerTask{

        private final TAppTime tAppTime;

        public InstanceTimeSynJob(TAppTime tAppTime){
            this.tAppTime = tAppTime;
        }

        @Override
        public void run() {

            LocalDateTime ntpTime = LocalDateTime.now();
            if(!tAppTime.IsCertificateTimeValid(ntpTime)){
                tAppTime.isValid = false;
                throw new CertificateExpiredException("Certificate validity "+tAppTime.tCertExpire+" is expired on "+ntpTime);
            }
        }
    }

    // Enabling SecurityContext, a singleton class safe reflection based attack
    // implement readResolve method
    protected Object readResolve()
    {
        return context;
    }
    @Override
    protected Object clone() throws CloneNotSupportedException
    {
        // throw new CloneNotSupportedException();
        return context;
    }
}
