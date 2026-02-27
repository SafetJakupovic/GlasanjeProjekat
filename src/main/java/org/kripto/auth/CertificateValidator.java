package org.kripto.auth;

import org.kripto.ca.OrgCA;
import org.kripto.ca.RootCA;
import org.kripto.ca.VoterCA;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertificateValidator {
    private final RootCA rootCA;
    private final OrgCA orgCA;
    private final VoterCA voterCA;

    public CertificateValidator(RootCA rootCA, OrgCA orgCA, VoterCA voterCA) {
        this.rootCA = rootCA;
        this.orgCA = orgCA;
        this.voterCA = voterCA;
    }

    public static class ValidationResult {
        public final boolean valid;
        public final String reason;
        public final String certType;

        public ValidationResult(boolean valid, String reason, String certType) {
            this.valid = valid;
            this.reason = reason;
            this.certType = certType;
        }
    }

    public ValidationResult validate(X509Certificate cert) {
        // provjera vremenske validnost
        try {
            cert.checkValidity(new Date());
        } catch (CertificateExpiredException e) {
            return new ValidationResult(false, "Sertifikat je istekao.", null);
        } catch (CertificateNotYetValidException e) {
            return new ValidationResult(false, "Sertifikat nije jos aktivan.", null);
        }

        // odredjivanje tipa i provjera izdavaca
        String issuerDN = cert.getIssuerX500Principal().getName();
        String certType = null;

        //odredjujemo tip po tome koji CA je izdao sertifikat
        String orgCADN = orgCA.getCertificate().getSubjectX500Principal().getName();
        String voterCADN = voterCA.getCertificate().getSubjectX500Principal().getName();

        if(issuerDN.equals(orgCADN)) {
            certType = "ORGANIZER";
        } else if(issuerDN.equals(voterCADN)) {
            certType = "VOTER";
        } else {
            return new ValidationResult(false, "Sertifikat nije izdat od poznatog CA.", null);
        }

        //verifikacija potpisa
        try {
            if (certType.equals("ORGANIZER")) {
                //orgCA javni kljuc mora odgovarati potpisu na sertifikatu
                cert.verify(orgCA.getCertificate().getPublicKey());
            } else {
                cert.verify(voterCA.getCertificate().getPublicKey());
            }
        } catch (Exception e) {
            return new ValidationResult(false, "Potpis sertifikata nije validan: " + e.getMessage(), null);
        }

        // provjera crl liste
        boolean revoked;
        if(certType.equals("ORGANIZER")) {
            revoked = orgCA.isRevoked(cert.getSerialNumber());
        } else {
            revoked = voterCA.isRevoked(cert.getSerialNumber());
        }

        if(revoked) {
            return new ValidationResult(false, "Sertifikat je povucen.", null);
        }

        return new ValidationResult(true, "OK", certType);
    }


}
