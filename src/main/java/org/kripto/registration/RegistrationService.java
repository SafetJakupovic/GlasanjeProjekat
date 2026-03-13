package org.kripto.registration;

import org.bouncycastle.asn1.x500.X500Name;
import org.kripto.ca.OrgCA;
import org.kripto.ca.RootCA;
import org.kripto.ca.VoterCA;
import org.kripto.util.CryptoUtil;
import org.kripto.util.KeyStoreUtil;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

public class RegistrationService {
    private final RootCA rootCA;
    private final OrgCA orgCA;
    private final VoterCA voterCA;

    private final Map<String, UserRecord> users = new HashMap<>();

    public RegistrationService(RootCA rootCA, OrgCA orgCA, VoterCA voterCA) {
        this.rootCA = rootCA;
        this.orgCA = orgCA;
        this.voterCA = voterCA;
    }

    // registracija organizatora
    public void registerOrganizer(String orgName, String orgId, String username, String password, String keystoreDir) throws Exception {
        if(users.containsKey(username))
            throw new IllegalArgumentException("Korisnik vec postoji: " + username);

        KeyPair kp = CryptoUtil.generateRSAKeyPair();
        X500Name dn = new X500Name("CN=" + orgName + ", SERIALNUMBER=" + orgId + ", O=EVoting, C=BA");
        //izdaj sertifikat od orgca
        X509Certificate cert = orgCA.issueOrgCert(dn, kp.getPublic());
        // hashiranje lozinke
        byte[] salt = CryptoUtil.generateSalt();
        byte[] pwHash = CryptoUtil.hashPassword(password, salt);
        // cuvanje keypair + cert u pkcs12 fajlu zasticenom lozinkom
        String ksPath = keystoreDir + "/" + username + "_org.p12";
        KeyStoreUtil.saveUserKeyStore(username, kp.getPrivate(), cert, orgCA.getCertificate(), password.toCharArray(), ksPath);

        System.out.println("[Organizator registrovan]");
        System.out.println("  DN: " + dn);
        System.out.println("  Serial: " + cert.getSerialNumber());
        System.out.println("  KeyStore: " + ksPath);

        users.put(username, new UserRecord(salt, pwHash, "ORGANIZER", cert.getSerialNumber(), ksPath, cert.getEncoded()));
    }

    // registracija glasaca
    public void registerVoter(String firstName, String lastName, String username, String password, String keystoreDir) throws Exception {
        if(users.containsKey(username))
            throw new IllegalArgumentException("Korisnik vec postoji: " + username);

        KeyPair kp = CryptoUtil.generateRSAKeyPair();
        X500Name dn = new X500Name("CN=" + firstName + " " + lastName + ", UID=" + username + ", O=EVoting, C=BA");

        X509Certificate cert = voterCA.issueVoterCert(dn, kp.getPublic());

        byte[] salt = CryptoUtil.generateSalt();
        byte[] pwHash = CryptoUtil.hashPassword(password, salt);

        String ksPath = keystoreDir + "/" + username + "_voter.p12";
        KeyStoreUtil.saveUserKeyStore(username, kp.getPrivate(), cert, voterCA.getCertificate(), password.toCharArray(), ksPath);

        System.out.println("[Glasač registrovan]");
        System.out.println("  DN: " + dn);
        System.out.println("  Serial: " + cert.getSerialNumber());
        System.out.println("  KeyStore: " + ksPath);

        users.put(username, new UserRecord(salt, pwHash, "VOTER", cert.getSerialNumber(), ksPath, cert.getEncoded()));
    }

    public Map<String, UserRecord> getUsers() {
        return users;
    }

    public OrgCA getOrgCA() {
        return orgCA;
    }

    public VoterCA getVoterCA() {
        return voterCA;
    }

    public static class UserRecord implements Serializable {
        private static final long serialVersionUID = 1L;
        public final byte[] salt;
        public final byte[] passwordHash;
        public final String role;
        public final BigInteger certSerial;
        public final String keystorePath;
        public int failedAttempts = 0;
        //public final X509Certificate certificate;
        public final byte[] encodedCertificate;

        public UserRecord(byte[] salt, byte[] passwordHash, String role, BigInteger certSerial, String keystorePath, byte[] encodedCertificate) {
            this.salt = salt;
            this.passwordHash = passwordHash;
            this.role = role;
            this.certSerial = certSerial;
            this.keystorePath = keystorePath;
            this.encodedCertificate = encodedCertificate;
        }
    }
}
