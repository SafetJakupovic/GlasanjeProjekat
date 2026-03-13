package org.kripto.voting;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.cert.X509Certificate;

public class VotingCrypto {
    static {
        if (Security.getProvider("BC") == null)
            Security.addProvider(new BouncyCastleProvider());
    }

    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_IV_BYTES = 12;

    public static class EncryptedVoteData {
        public final byte[] encryptedChoice;
        public final byte[] encryptedAesKey;
        public final byte[] iv;

        public EncryptedVoteData(byte[] encryptedChoice, byte[] encryptedAesKey, byte[] iv) {
            this.encryptedChoice = encryptedChoice;
            this.encryptedAesKey = encryptedAesKey;
            this.iv = iv;
        }
    }

    public static EncryptedVoteData encrypt(String choice, PublicKey organizerPublicKey) throws Exception {
        // generise se nasumicni aes256 kljuc
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
        keyGen.init(256, new SecureRandom());
        SecretKey aesKey = keyGen.generateKey();

        // generise se nasumicni iv za gcm
        byte[] iv = new byte[GCM_IV_BYTES];
        new SecureRandom().nextBytes(iv);

        // enkriptuje se glas sa aes256gcm
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] encryptedChoice = aesCipher.doFinal(choice.getBytes("UTF-8"));

        // enkriptuje se aes kljuc sa rsa oaep
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
        rsaCipher.init(Cipher.ENCRYPT_MODE, organizerPublicKey);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

        return new EncryptedVoteData(encryptedChoice, encryptedAesKey, iv);
    }

    public static String decrypt(byte[] encryptedChoice, byte[] encryptedAesKey, byte[] iv, PrivateKey organizerPrivKey) throws Exception {
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
        rsaCipher.init(Cipher.DECRYPT_MODE, organizerPrivKey);
        byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);

        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] plaintext = aesCipher.doFinal(encryptedChoice);

        return new String(plaintext, "UTF-8");
    }

    public static byte[] sign(byte[] encryptedChoice, byte[] encryptedAesKey, byte[] iv, PrivateKey voterPrivKey) throws Exception {
        Signature signer = Signature.getInstance("SHA256WithRSA", "BC");
        signer.initSign(voterPrivKey);

        signer.update(encryptedChoice);
        signer.update(encryptedAesKey);
        signer.update(iv);

        return signer.sign();
    }

    public static boolean verify(byte[] encryptedChoice, byte[] encryptedAesKey, byte[] iv, byte[] signature, X509Certificate voterCert) throws Exception {
        Signature verifier = Signature.getInstance("SHA256WithRSA", "BC");
        verifier.initVerify(voterCert.getPublicKey());

        verifier.update(encryptedChoice);
        verifier.update(encryptedAesKey);
        verifier.update(iv);

        return verifier.verify(signature);
    }
}
