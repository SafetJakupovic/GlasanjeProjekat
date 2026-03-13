package org.kripto.model;

import java.awt.*;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.time.Instant;

// jedan enkriptovani glas
// sami podaci enkriptovani su simetricnim aes kljucem
// aes kljuc enkriptovan je asimetricnim rsa javnim kljucem organizatora
// (samim tim samo organizator moze dekriptovani taj aes kljuc, tj. sadrzaj glasa)
public class Vote implements Serializable {
    private static final long serialVersionUID = 1L;
    public final String pollId;

    // aes enkriptovani izbor glasaca
    // sadrzaj utf8 string naziva opcije enkriptovan aes 256 gmc
    public final byte[] encryptedChoice;

    // aes kljuc enkriptovan rsa javnim kljucem organizatora
    public final byte[] encryptedAesKey;
    public final byte[] iv;

    // digitalni potpis glasaca potpisan privatnim kljucem glasaca, verifikuje se javnim kljucem iz sertifikata
    public final byte[] signature;
    public final BigInteger voterCertSerial;
    public final Instant timestamp;
    public final String voteId;

    public Vote(String pollId, byte[] encryptedChoice, byte[] encryptedAesKey, byte[] iv, byte[] signature, BigInteger voterCertSerial) {
        this.pollId = pollId;
        this.encryptedChoice = encryptedChoice;
        this.encryptedAesKey = encryptedAesKey;
        this.iv = iv;
        this.signature = signature;
        this.voterCertSerial = voterCertSerial;
        this.timestamp = Instant.now();
        this.voteId = computeVoteId(voterCertSerial, this.timestamp);
    }

    private static String computeVoteId(BigInteger serial, Instant ts) {
        try{
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(serial.toByteArray());
            md.update(ts.toString().getBytes());
            byte[] hash = md.digest();
            StringBuilder sb = new StringBuilder();
            for(int i = 0; i < 16; i++)
                sb.append(String.format("%02x", hash[i]));
            return sb.toString();
        } catch (Exception e) {
            return serial.toString() + "-" + ts.toEpochMilli();
        }
    }
}
