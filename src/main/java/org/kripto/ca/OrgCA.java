package org.kripto.ca;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.kripto.util.CryptoUtil;
import org.kripto.util.KeyStoreUtil;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

public class OrgCA {
    public static final X500Name DN = new X500Name("CN=Org CA, O=EVoting, C=BA");
    private final KeyPair keyPair;
    private final X509Certificate certificate;

    private final List<BigInteger> revokedSerials = new ArrayList<>();
    private BigInteger serialCounter = BigInteger.TWO;

    private final X509Certificate rootCACert;

    public OrgCA(RootCA rootCA) throws Exception {
        this.keyPair = CryptoUtil.generateRSAKeyPair();
        this.certificate = rootCA.signSubCA(DN, keyPair.getPublic(), 0);
        this.rootCACert = rootCA.getCertificate();
    }

    public OrgCA(PrivateKey privateKey, X509Certificate certificate, RootCA rootCA) {
        this.keyPair = new KeyPair(certificate.getPublicKey(), privateKey);
        this.certificate = certificate;
        this.rootCACert = rootCA.getCertificate();
    }

    public X509Certificate issueOrgCert(X500Name subjectDN, PublicKey subjectPub) throws Exception {
        long now = System.currentTimeMillis();
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(keyPair.getPrivate());

        BigInteger serial = serialCounter;
        serialCounter = serial.add(BigInteger.ONE);

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(DN, serial, new Date(now), new Date(now + 2L * 365 * 24 * 24 * 60 * 60 * 1000), subjectDN, subjectPub);

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false)); // nije ca
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment)); // digitalni potpis + sifrovanje kljuca
        builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_emailProtection));

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    public void revoke(BigInteger serial) {
        revokedSerials.add(serial);
    }

    public boolean isRevoked(BigInteger serial) {
        return revokedSerials.contains(serial);
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public void saveToDisk(String path, char[] password) throws Exception {
        KeyStoreUtil.saveUserKeyStore("org-ca", keyPair.getPrivate(),
                certificate, rootCACert, // chain: OrgCA cert → Root CA cert
                password, path);
    }

    public static OrgCA loadFromDisk(String path, char[] password, RootCA rootCA) throws Exception {
        KeyStore ks = KeyStoreUtil.loadKeyStore(path, password);
        PrivateKey privKey = KeyStoreUtil.getPrivateKey(ks, "org-ca", password);
        X509Certificate cert = KeyStoreUtil.getCertificate(ks, "org-ca");
        return new OrgCA(privKey, cert, rootCA); // novi konstruktor
    }

    public void loadRevokedSerials(List<BigInteger> serials) {
        revokedSerials.addAll(serials);
    }

    public List<BigInteger> getRevokedSerials() {
        return Collections.unmodifiableList(revokedSerials);
    }
}