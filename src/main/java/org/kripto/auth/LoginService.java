package org.kripto.auth;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.kripto.registration.RegistrationService;
import org.kripto.util.CryptoUtil;
import org.kripto.util.KeyStoreUtil;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;

// korisnik predaje putanju do svoj p12 fajla i lozinku za otvaranje
// ucitava se sertifikat i validira
// zatim unosi korisnicko ime i lozinku
// provjerava se da li hash odgovarava sacuvanom hashu
// i da li korisnicko ime odgovara podatku u sertifikatu
public class LoginService {
    private final RegistrationService registrationService;
    private final CertificateValidator certValidator;

    private static final int MAX_FAILED_ATTEMPTS = 3;

    public LoginService(RegistrationService registrationService, CertificateValidator certValidator) {
        this.registrationService = registrationService;
        this.certValidator = certValidator;
    }

    // ucitavanje p12 fajla i validacija
    public StepOneResult stepOne(String p12Path, String p12Password, String usernameAlias)  {
        KeyStore ks;
        try {
            ks = KeyStoreUtil.loadKeyStore(p12Path, p12Password.toCharArray());
        } catch (Exception e) {
            return new StepOneResult(false, null, "Nije moguce otvoriti .p12 fajl: " + e.getMessage());
        }

        X509Certificate cert;
        try {
            cert = KeyStoreUtil.getCertificate(ks, usernameAlias);
            if(cert == null)
                return new StepOneResult(false, null, "Sertifikat nije pronadjen u fajlu (alias: " + usernameAlias + ")");
        } catch (Exception e) {
            return new StepOneResult(false, null, "Greska pri citanju sertifikata: " + e.getMessage());
        }

        CertificateValidator.ValidationResult vr = certValidator.validate(cert);
        if(!vr.valid) {
            return new StepOneResult(false, null, "Validacija sertifikata neuspjesna: " + vr.reason);
        }

        System.out.println("1. Sertifikat validan. Tip: " + vr.certType);
        return new StepOneResult(true, cert, "OK");
    }

    // provjera korisnickom imena i lozinke
    // takodje se radi binding sertifikata (username koji korisnik unosi odgovara UID/CN atributu u subject DNu u sertifikatu) pa se ne moze uzeti tudji p12 fajl
    public LoginResult stepTwo(X509Certificate cert, String username, String password) {
        //provjera da username postoji u sistemu
        RegistrationService.UserRecord record = registrationService.getUsers().get(username);
        if(record == null)
            return new LoginResult(false, null, null, "Korisnik ne postoji");

        // provjera da li je povucen sertifikat (duplira se provjera za svaki slucaj)
        CertificateValidator.ValidationResult vr = certValidator.validate(cert);
        if(!vr.valid)
            return new LoginResult(false, null, null, "Sertifikat vise nije validan: " + vr.reason);

        // da li sertifikat pripada ovom korisniku
        // citamo subject dn iz sertifikata i trazimo UID atribud (za glasace) ili poredimo sa SERIALNUMBER (za organizatore)
        // X500Name iz bouncycastle dozvoljava pristup pojedinim atributima DNa
        // BCStyle.UID = OID za userid
        // BCStyle.CN = OID za commonName
        boolean certBelongsToUser = false;
        try {
            X500Name subjectDN = new X500Name(cert.getSubjectX500Principal().getName());

            if(vr.certType.equals("VOTER")) {
                // glasaci imaju uid=username u sertifikatu
                RDN[] uidRDNs = subjectDN.getRDNs(BCStyle.UID);
                if(uidRDNs.length > 0) {
                    String certUID = uidRDNs[0].getFirst().getValue().toString();
                    certBelongsToUser = certUID.equals(username);
                }
            } else {
                // organizatori imaju serialnumber=orgid i cn=orgname
                RDN[] cnRDNs = subjectDN.getRDNs(BCStyle.CN);
                if(cnRDNs.length > 0) {
                    String certCN = cnRDNs[0].getFirst().getValue().toString();
                    certBelongsToUser = cert.getSerialNumber().equals(record.certSerial);
                }
            }
        } catch (Exception e) {
            return new LoginResult(false, null, null, "Greska pri provjeri sertifikata: " + e.getMessage());
        }

        if(!certBelongsToUser)
            return new LoginResult(false, null, null, "Sertifikat ne pripada ovom korisniku.");

        // provjera lozinke
        // hashiramo unesenu lozinku sa istim saltom koji je sacuvan pri registraciji pa poredimo sa sacuvanim hashom
        byte[] enteredHash;
        try {
            enteredHash = CryptoUtil.hashPassword(password, record.salt);
        } catch (Exception e) {
            return new LoginResult(false, null, null, "Greska pri provjeri lozinke");
        }

        if(!Arrays.equals(enteredHash, record.passwordHash)) {
            record.failedAttempts++;
            System.out.println("Progresna lozinka. Neuspjesnih pokusaja: " + record.failedAttempts + "/" + MAX_FAILED_ATTEMPTS);

            if(record.failedAttempts >= MAX_FAILED_ATTEMPTS) {
                revokeCertificate(record, vr.certType);
                return new LoginResult(false, null, null, "Previse neuspjelih pokusaja. Sertifikat je povucen.");
            }

            return new LoginResult(false, null, null, "Pogresna lozinka. Preostalo pokusaja: " + (MAX_FAILED_ATTEMPTS - record.failedAttempts));
        }

        record.failedAttempts = 0;

        return new LoginResult(true, username, record.role, "Uspjesna prijava kao " + record.role);
    }

    private void revokeCertificate(RegistrationService.UserRecord record, String certType) {
        if(certType.equals("ORGANIZER"))
            registrationService.getOrgCA().revoke(record.certSerial);
        else
            registrationService.getVoterCA().revoke(record.certSerial);

        System.out.println("Sertifikat povucen. Serijski broj: " + record.certSerial);
    }

    public static class LoginResult {
        public final boolean success;
        public final String username;
        public final String role; // ORGANIZER ili VOTER
        public final String message;

        public LoginResult(boolean success, String username, String role, String message) {
            this.success = success;
            this.username = username;
            this.role = role;
            this.message = message;
        }
    }

    public static class StepOneResult {
        public final boolean success;
        public final X509Certificate certificate;
        public final String message;

        public StepOneResult(boolean success, X509Certificate certificate, String message) {
            this.success = success;
            this.certificate = certificate;
            this.message = message;
        }
    }
}
