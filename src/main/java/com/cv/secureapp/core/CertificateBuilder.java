package com.cv.secureapp.core;

import javax.crypto.Cipher;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Its is builder class used for handling certificates, it takes care of RSA based encryption/decryption for building
 * certificates.
 * It encrypt data using private key, and use public key for decryption. We cannot use Java native Signature verify
 * since it require both signature and uncipher data to be shared
 *
 * How to build Certificate
 *   Triplet certificate =  CertificateBuilder.getInstance().buildCertificateForData(String rawdata)
 *
 *   $1 is public key, replace SecurityContext.PUBLIC_KEY to $1
 *   $2 is private key, save privateKey for future reference
 *   $3 is cipher certificate
 *
 * Creating new Certificate
 *   String cipherCertificate = CertificateBuilder.encrypt(String rawdata, String privateKey);
 *
 */
public class CertificateBuilder {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public CertificateBuilder() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public void writeToFile(String path, byte[] key) throws IOException {
        File f = new File(path);
        f.getParentFile().mkdirs();

        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key);
        fos.flush();
        fos.close();
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     *  Given Base64 encoded publickey in string, it will convert into X509 encoded public key
     * @param publicKeyContent public key in encoded format
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PublicKey getPublicKeyFromText(String publicKeyContent) throws NoSuchAlgorithmException, InvalidKeySpecException {

        KeyFactory kf = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
        PublicKey pubKey =  kf.generatePublic(keySpecX509);
        return pubKey;
    }

    /**
     *  Given Base64 encoded privatekey in string, it will convert into PKCS8 encoded private key
     * @param privateKeyContent private key in encoded format
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PrivateKey getPrivateKeyFromText(String privateKeyContent) throws NoSuchAlgorithmException, InvalidKeySpecException {

        KeyFactory kf = KeyFactory.getInstance("RSA");

        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
        PrivateKey pubKey =  kf.generatePrivate(keySpecPKCS8);
        return pubKey;
    }

    public static String encrypt(String plainText, PrivateKey privateKey) throws Exception {
       return encrypt(plainText.getBytes(UTF_8), privateKey);
    }

    public static String encrypt(String plainText, String privateKey) throws Exception {

        return encrypt(plainText.getBytes(UTF_8), getPrivateKeyFromText(privateKey));
    }

    public static String encrypt(byte[] plainText, PrivateKey privateKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, privateKey);

        byte[] cipherText = encryptCipher.doFinal(plainText);

        return Base64.getEncoder().encodeToString(cipherText);
    }
    public static String decrypt(byte[] cipherText, PublicKey publicKey) throws Exception {

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, publicKey);

        return new String(decriptCipher.doFinal(cipherText), UTF_8);
    }

    public static String decrypt(String cipherText, PublicKey publicKey) throws Exception {
        return decrypt(Base64.getDecoder().decode(cipherText), publicKey);
    }

    public static String getDataField(String certificate, PublicKey publicKey, String delimiter, int fieldIndex){
        return getDataField(Base64.getDecoder().decode(certificate), publicKey, delimiter, fieldIndex);
    }

    /**
     *  Extract specific data from encrypted certificate using delimiter and fieldindex for handling certificate
     *  internal shuffling
     *  String rawdata = "2019-06-01T18:30:27.298||2019-06-07T18:30:27.298||2019-06-05T12:59:27.298||2019-06-04T18:30:27.298";
     *  give delimiter = || & fieldIndex = 3
     *  getDataField method return 2019-06-05T12:59:27.298
     *
     * @param certificate encrypted certficate content
     * @param publicKey key to decrypt the certificate
     * @param delimiter internal to certificate content shuffling
     * @param fieldIndex internal to certificate content shuffling
     * @return
     */
    public static String getDataField(byte []certificate, PublicKey publicKey, String delimiter, int fieldIndex){
        String unCipherData = "";
        try {
            unCipherData = decrypt(certificate, publicKey);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Not able to decrypt certificate using public key");
        }

        String fieldValue = unCipherData.split(delimiter)[fieldIndex];
        return fieldValue;
    }

    public static CertificateBuilder getInstance(){
        CertificateBuilder certificateBuilder = null;
        try {
            certificateBuilder = new CertificateBuilder();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.out.println("CertificateBuilder: No Such Algo found");
            throw new RuntimeException("CertificateBuilder: No Such Algo found");
        }
        return certificateBuilder;
    }

    /**
     * It build certificate with public, private & cipher certificate content
     * @param content certificate content
     * @return
     */
    public Triplet buildCertificateForData(String content){

        Triplet<String, String, String> certificate = null;
        try {
            CertificateBuilder keyPairGenerator = new CertificateBuilder();

            String cipher = CertificateBuilder.encrypt(content, keyPairGenerator.getPrivateKey());
            String publicKey = Base64.getEncoder().encodeToString(keyPairGenerator.getPublicKey().getEncoded());
            String privateKey = Base64.getEncoder().encodeToString(keyPairGenerator.getPrivateKey().getEncoded());

            certificate = Triplet.with(publicKey, privateKey, cipher);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return certificate;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {

        String rawdata = "2019-06-01T18:30:27.298||2019-06-07T18:30:27.298||2019-06-05T12:59:27.298||2019-06-04T18:30:27.298";
        CertificateBuilder keyPairGenerator = new CertificateBuilder();
//        keyPairGenerator.writeToFile("Certificate/publicKey", keyPairGenerator.getPublicKey().getEncoded());
//        keyPairGenerator.writeToFile("Certificate/privateKey", keyPairGenerator.getPrivateKey().getEncoded());
//        System.out.println("Private Key "+Base64.getEncoder().encodeToString(keyPairGenerator.getPublicKey().getEncoded()));
//        System.out.println("Public Key "+Base64.getEncoder().encodeToString(keyPairGenerator.getPrivateKey().getEncoded()));

        try {
            String cipher = CertificateBuilder.encrypt(rawdata, keyPairGenerator.getPrivateKey());
            String publicKey = Base64.getEncoder().encodeToString(keyPairGenerator.getPublicKey().getEncoded());
            System.out.println("public "+publicKey);
            String decipher = CertificateBuilder.decrypt(cipher, CertificateBuilder.getPublicKeyFromText(publicKey));
            System.out.println("Certificate "+cipher);
//            System.out.println("#rd Field "+CertificateBuilder.getDataField(cipher, keyPairGenerator.getPublicKey(), "\\|\\|", 3));
            System.out.println("Extracted Field "+CertificateBuilder.getDataField(cipher, CertificateBuilder.getPublicKeyFromText(publicKey), "\\|\\|", 3));
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
