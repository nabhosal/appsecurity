# How to secure JAR/APP, and make it active/usable for specific duration 

We come across a requirement of deploying our important jar on the client environment, yup it is a very common scenario.  But we wanted the jar to be usable for a specific duration & reverse engineering of the jar should be very hard to do.
For making reverse engineering very hard, we used code obfuscate & dynamic proxy to hide important class and audit method invocation through a proxy.
But the challenge of sharing a jar & making it usable for the specific duration is a very important business requirement. Since once the jar is shared we don’t have any control, and we wanted it to be non-usable if unfortunately, someone gets access to the jar he should not be able to use it.

The problem can be divided into two parts,
1. Share Jar expiration time ( i.e TCert ) separately and must be temper free
2. The dependency of Jar on system/machine time

We build certificate and shared it separately to our client, the certificate is a cipher containing TCert time. We used asymmetric encryption (RSA) technique to build certificate, a cipher is created using PrivateKey and PublicKey is hardcoded in SecurityContext class for decrypting the certificate/cipher. It’s similar to a signature verification technique without exposing certificate content.

If jar depends on system time then by just tempering system time, a jar can be easily compromised. We completely avoid using system time, it relies on the Network Time Protocol (NTP) server to give the correct time. It periodically refreshes (Tapp time) from NTP servers.

##### How to create a new Certificate
```java
String rawdata = "2019-06-01T18:30:27.298||2019-06-07T18:30:27.298||2019-06-05T12:59:27.298||2019-06-04T18:30:27.298";
CertificateBuilder certificateUtil = CertificateBuilder.getInstance();
Triplet<String, String, String> certificate = certificateUtil.buildCertificateForData(rawdata);

System.out.println("Public Key: "+certificate.$1());
System.out.println("Private Key: "+certificate.$2());
System.out.println("Certificate: "+certificate.$3());

String TcertDate = CertificateBuilder.getDataField(certificate.$3(), CertificateBuilder.getPublicKeyFromText(certificate.$1()), "\\|\\|", 3);
```

##### How to validate the certificate on each call
```java
// Initialize security context with certificate path
System.setProperty("cv.secureapp.certificate", <certificatePath>);
java -jar <parentJar> -Dcv.secureapp.certificate=<certificatePath>

// call below stmt to validate certificate on each request
SecurityContext.isCertificateValid()
```

##### Future enhancement
Code obfuscate make reverse engineering hard, can we use obfuscation with encryption to make sharing jar more secure and nearly impossible to reverse engineer 

