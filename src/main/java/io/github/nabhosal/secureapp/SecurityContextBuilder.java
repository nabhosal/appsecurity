package io.github.nabhosal.secureapp;

import io.github.nabhosal.secureapp.exception.SecurityContextException;
import io.github.nabhosal.secureapp.impl.DelimitedCertificateFormatImpl;

public class SecurityContextBuilder {

    /* System property to get certificate path */
    private static final String DEFAULT_CERT_SYS_FUNC_NAME = "cv.secureapp.certificate";

    /* System property to get ntp server hostname */
//    private static final String DEFAULT_NTP_FUNC_NAME = "cv.secureapp.ntpserver";

    /* default network server */
    private static final String DEFAULT_NS_SERVER = "time-a.nist.gov";

    /* Max retry for getting time from ns server */
    private static final int DEFAULT_MAX_RETRY_ATTEMPT = 3;

    /* for adding exponential time delay between each retry */
    private static final int DEFAULT_SEED_EXPONENTIAL_FACTOR = 3;

    /**
     * Set Periodic interval to refresh TApp time
     * e.g.  Every Minute = 1000L * 60L
     *       Hourly       = 1000L * 60L * 60L
     *       Daily        = 1000L * 60L * 60L * 24L
     */
    private static final long DEFAULT_PERIODIC_INTERVAL = INTERVAL.SECOND.getTime();

    private static final CertificateFormat DEFAULT_CERTIFICATE_FORMAT = new DelimitedCertificateFormatImpl();

    private String nsServer;
    private String certSysFuncName;
    private int seedExponentialFactor;
    private int maxRetryAttempt;
    private long periodicInterval;
    private String publicKey;
    private boolean useLocalInstanceTime;

    public CertificateFormat getCertificateFormat() {
        return certificateFormat;
    }

    public SecurityContextBuilder withCertificateFormat(CertificateFormat certificateFormat) {
        this.certificateFormat = certificateFormat;
        return this;
    }

    private CertificateFormat certificateFormat;

    private SecurityContextBuilder(String nsServer,
                                   String certSysFuncName,
                                   long periodicInterval,
                                   int seedExponentialFactor,
                                   int maxRetryAttempt,
                                   String publicKey,
                                   CertificateFormat certificateFormat,
                                   boolean useLocalInstanceTime){
        this.nsServer = nsServer;
        this.certSysFuncName = certSysFuncName;
        this.periodicInterval = periodicInterval;
        this.seedExponentialFactor = seedExponentialFactor;
        this.maxRetryAttempt = maxRetryAttempt;
        this.publicKey = publicKey;
        this.certificateFormat = certificateFormat;
        this.useLocalInstanceTime = useLocalInstanceTime;
    }

    public static SecurityContextBuilder withDefault(){

        return new SecurityContextBuilder(DEFAULT_NS_SERVER,
                DEFAULT_CERT_SYS_FUNC_NAME,
                DEFAULT_PERIODIC_INTERVAL,
                DEFAULT_SEED_EXPONENTIAL_FACTOR,
                DEFAULT_MAX_RETRY_ATTEMPT,
                "",
                DEFAULT_CERTIFICATE_FORMAT,
                false);
    }

    public void initialize(){
        if ("".equalsIgnoreCase(publicKey) || publicKey == null)
            throw new SecurityContextException("public key is not defined");
        SecurityContext.init(this);
    }

    public SecurityContextBuilder withNSServer(String ns_server) {
        this.nsServer = ns_server;
        return this;
    }

    public SecurityContextBuilder useCertificateVariableName(String cert_sys_func_name) {
        this.certSysFuncName = cert_sys_func_name;
        return this;
    }

    public SecurityContextBuilder withInterval(long intervalInSec ) {
        this.periodicInterval = intervalInSec;
        return this;
    }

    public SecurityContextBuilder withSeedFactor(int seed_exponential_factor) {
        this.seedExponentialFactor = seed_exponential_factor;
        return this;
    }

    public SecurityContextBuilder withMaxRetry(int max_retry_attempt) {
        this.maxRetryAttempt = max_retry_attempt;
        return this;
    }

    public SecurityContextBuilder withPublicKey(String publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    public SecurityContextBuilder useInstanceTime(){
        this.useLocalInstanceTime = true;
        return this;
    }

    public String getNsServer() {
        return nsServer;
    }

    public String getCertSysFuncName() {
        return certSysFuncName;
    }

    public int getSeedExponentialFactor() {
        return seedExponentialFactor;
    }

    public int getMaxRetryAttempt() {
        return maxRetryAttempt;
    }

    public long getPeriodicInterval() {
        return periodicInterval;
    }

    public String getPublicKey(){
        return publicKey;
    }

    public boolean isUseLocalInstanceTime() {
        return useLocalInstanceTime;
    }

    public enum INTERVAL
    {
        SECOND(1000L), MINUTE(SECOND.getTime() * 60L), HOURLY(MINUTE.getTime() * 60L), DAILY(HOURLY.getTime() * 24L);

        // declaring private variable for getting values
        private long time;

        // getter method
        public long getTime()
        {
            return this.time;
        }

        // enum constructor - cannot be public or protected
        private INTERVAL(long time)
        {
            this.time = time;
        }
    }

}
