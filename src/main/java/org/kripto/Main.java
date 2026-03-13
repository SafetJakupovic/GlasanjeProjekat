package org.kripto;

import org.kripto.auth.CertificateValidator;
import org.kripto.auth.LoginService;
import org.kripto.ca.CAStore;
import org.kripto.ca.OrgCA;
import org.kripto.ca.RootCA;
import org.kripto.ca.VoterCA;
import org.kripto.model.Poll;
import org.kripto.registration.RegistrationService;
import org.kripto.registration.UserStore;
import org.kripto.util.KeyStoreUtil;
import org.kripto.voting.PollService;
import org.kripto.voting.PollStore;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.*;
import java.util.*;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {

    private static RootCA rootCA;
    private static OrgCA orgCA;
    private static VoterCA voterCA;
    private static RegistrationService regService;
    private static LoginService loginService;
    private static PollService pollService;
    private static Scanner sc = new Scanner(System.in);
    private static String ksDir = "keystores";

    public static void main(String[] args) throws Exception {
        System.out.println("=== Inicijalizacija CA hijerarhije ===");

        // ucitava sa diska ako postoji, kreira novo ako ne postoji
        rootCA  = CAStore.loadOrCreateRootCA();
        orgCA   = CAStore.loadOrCreateOrgCA(rootCA);
        voterCA = CAStore.loadOrCreateVoterCA(rootCA);
        System.out.println("CA hijerarhija spremna\n");

        regService  = new RegistrationService(rootCA, orgCA, voterCA);
        pollService = new PollService(regService);
        pollService.loadPolls(PollStore.load());
        System.out.println("Ucitano " + pollService.getAllPolls().size() + " glasanja");


        // ucitaj korisnike sa diska
        regService.getUsers().putAll(UserStore.load());
        System.out.println("Ucitano " + regService.getUsers().size() + " korisnika\n");

        CertificateValidator validator = new CertificateValidator(rootCA, orgCA, voterCA);
        loginService = new LoginService(regService, validator);

        Files.createDirectories(Paths.get(ksDir));

        // cuva korisnike pri gasenju
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                UserStore.save(regService.getUsers());
                PollStore.save(new LinkedHashMap<>(pollService.getAllPolls()));
                System.out.println("Podaci sacuvani");
            } catch (Exception e) {
                System.out.println("Greska pri cuvanju: " + e.getMessage());
            }
        }));


        while (true) {
            System.out.println("\n=============================");
            System.out.println(" E-VOTING SISTEM");
            System.out.println("=============================");
            System.out.println("1. Registracija");
            System.out.println("2. Prijava");
            System.out.println("0. Izlaz");
            System.out.print("Odabir: ");
            switch (sc.nextLine().trim()) {
                case "1" -> registrationMenu();
                case "2" -> loginMenu();
                case "0" -> { System.out.println("KRAJ"); return; }
                default  -> System.out.println("Nepoznata opcija");
            }
        }
    }

    private static void registrationMenu() throws Exception {
        System.out.println("\n-- REGISTRACIJA --");
        System.out.println("1. Organizator");
        System.out.println("2. Glasac");
        System.out.print("Odabir: ");

        switch (sc.nextLine().trim()) {
            case "1" -> {
                System.out.print("Naziv organizacije: ");
                String orgName = sc.nextLine().trim();
                System.out.print("Identifikacioni broj: ");
                String orgId = sc.nextLine().trim();
                System.out.print("Korisnicko ime: ");
                String username = sc.nextLine().trim();
                System.out.print("Lozinka: ");
                String password = sc.nextLine().trim();
                regService.registerOrganizer(orgName, orgId, username, password, ksDir);
            }
            case "2" -> {
                System.out.print("Ime: ");
                String ime = sc.nextLine().trim();
                System.out.print("Prezime: ");
                String prez = sc.nextLine().trim();
                System.out.print("Korisnicko ime: ");
                String username = sc.nextLine().trim();
                System.out.print("Lozinka: ");
                String password = sc.nextLine().trim();
                regService.registerVoter(ime, prez, username, password, ksDir);
            }
        }
    }

    private static void loginMenu() {
        System.out.println("\n-- PRIJAVA --");
        System.out.println("Digitalni sertifikat");
        System.out.print("Putanja do .p12 fajla: ");
        String p12Path = sc.nextLine().trim();
        System.out.print("Korisnicko ime: ");
        String alias = sc.nextLine().trim();
        System.out.print("Lozinka za .p12: ");
        String p12Password = sc.nextLine().trim();

        LoginService.StepOneResult s1 = loginService.stepOne(p12Path, p12Password, alias);
        if (!s1.success) {
            System.out.println(s1.message);
            return;
        }
        System.out.println("Sertifikat prihvacen");

        System.out.println("Kredencijali");
        System.out.print("Korisnicko ime: ");
        String username = sc.nextLine().trim();
        System.out.print("Lozinka: ");
        String password = sc.nextLine().trim();

        LoginService.LoginResult lr = loginService.stepTwo(s1.certificate, username, password);
        if (!lr.success) {
            System.out.println(lr.message);
            return;
        }

        System.out.println(lr.message);

        if (lr.role.equals("ORGANIZER"))
            organizerInterface(lr.username);
        else
            voterInterface(lr.username, s1.certificate);
    }

    private static void organizerInterface(String username) {
        while (true) {
            System.out.println("\n╔══════════════════════════════╗");
            System.out.println("║  ORGANIZATOR: " + username);
            System.out.println("╠═══════════════════════════════╣");
            System.out.println("║  1. Kreiraj glasanje          ║");
            System.out.println("║  2. Moja glasanja             ║");
            System.out.println("║  3. Pokreni brojanje          ║");
            System.out.println("║  0. Odjava                    ║");
            System.out.println("╚═══════════════════════════════╝");
            System.out.print("Odabir: ");

            switch (sc.nextLine().trim()) {
                case "1" -> createPoll(username);
                case "2" -> showOrganizerPolls(username);
                case "3" -> startCounting(username);
                case "0" -> { System.out.println("Odjava"); return; }
                default  -> System.out.println("Nepoznata opcija");
            }
        }
    }

    private static void createPoll(String username) {
        try {
            System.out.print("Naslov: ");
            String title = sc.nextLine().trim();
            System.out.print("Opis: ");
            String desc = sc.nextLine().trim();

            // format 2025-06-01T10:00:00Z
            System.out.print("Početak (npr. 2026-12-31T12:00:00Z, ili ENTER za odmah): ");
            String startStr = sc.nextLine().trim();
            Instant start = startStr.isEmpty() ? Instant.now() : Instant.parse(startStr);

            System.out.print("Kraj (npr. 11:30 za danas, ili 2027-12-31T12:00:00Z): ");
            String endStr = sc.nextLine().trim();
            Instant end;

            // ako korisnik unese samo vrijeme (HH:mm), uzmi danasnji datum u lokalnoj zoni
            if (endStr.matches("\\d{2}:\\d{2}")) {
                LocalDate today = LocalDate.now();
                LocalTime time = LocalTime.parse(endStr);
                end = LocalDateTime.of(today, time)
                        .atZone(ZoneId.systemDefault())
                        .toInstant();
            } else {
                // pokusaj parsirati kao ISO, podrzava i Z i +01:00
                end = Instant.parse(endStr);
            }
            System.out.println("Unesite opcije (2-5), prazan unos za kraj:");
            List<String> options = new ArrayList<>();
            for (int i = 1; i <= 5; i++) {
                System.out.print("  Opcija " + i + ": ");
                String opt = sc.nextLine().trim();
                if (opt.isEmpty()) break;
                options.add(opt);
            }

            RegistrationService.UserRecord rec = regService.getUsers().get(username);
            Poll poll = pollService.createPoll(
                    username, title, desc, start, end, options,
                    rec.keystorePath, getPassword("Lozinka za potvrdu: "));

            System.out.println("Glasanje kreirano, ID: " + poll.id);

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void showOrganizerPolls(String username) {
        List<Poll> polls = pollService.getPollsByOrganizer(username);
        if (polls.isEmpty()) {
            System.out.println("Nemas kreirana glasanja");
            return;
        }
        System.out.println("\n-- TVOJA GLASANJA --");
        polls.forEach(p -> System.out.println("  " + p));
    }

    private static void startCounting(String username) {
        showOrganizerPolls(username);
        System.out.print("Unesi Poll ID za prebrojavanje: ");
        String pollId = sc.nextLine().trim();

        try {
            RegistrationService.UserRecord rec = regService.getUsers().get(username);
            char[] password = getPassword("Lozinka: ");

            Map<String, Integer> results = pollService.countVotes(
                    pollId, username, rec.keystorePath, password);

            pollService.printResults(pollId);

            System.out.print("Prikazi potpisani izvjestaj? (d/n): ");
            if (sc.nextLine().trim().equalsIgnoreCase("d")) {
                KeyStore ks = KeyStoreUtil.loadKeyStore(rec.keystorePath, password);
                X509Certificate orgCert = KeyStoreUtil.getCertificate(ks, username);
                pollService.printSignedReport(pollId, orgCert);
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void voterInterface(String username, X509Certificate voterCert) {
        while (true) {
            System.out.println("\n╔══════════════════════════════╗");
            System.out.println("║  GLASAČ: " + username);
            System.out.println("╠═══════════════════════════════╣");
            System.out.println("║  1. Aktivna glasanja          ║");
            System.out.println("║  2. Glasaj                    ║");
            System.out.println("║  3. Verifikuj moj glas        ║");
            System.out.println("║  0. Odjava                    ║");
            System.out.println("╚═══════════════════════════════╝");
            System.out.print("Odabir: ");

            switch (sc.nextLine().trim()) {
                case "1" -> showActivePolls(username);
                case "2" -> vote(username);
                case "3" -> verifyVote(voterCert);
                case "0" -> { System.out.println("Odjava"); return; }
                default  -> System.out.println("Nepoznata opcija");
            }
        }
    }

    private static void showActivePolls(String username) {
        List<Poll> active = pollService.getActivePollsForVoter(username);
        if (active.isEmpty()) {
            System.out.println("Nema aktivnih glasanja (ili si vec glasao u svima)");
            return;
        }
        System.out.println("\n-- AKTIVNA GLASANJA --");
        active.forEach(p -> {
            System.out.println("  ID: " + p.id + " | " + p.title);
            System.out.println("     " + p.description);
            System.out.println("     Opcije: " + p.options);
            System.out.println("     Ističe: " + p.endTime);
        });
    }

    private static void vote(String username) {
        showActivePolls(username);

        System.out.print("Poll ID: ");
        String pollId = sc.nextLine().trim();

        Poll poll = pollService.getAllPolls().get(pollId);
        if (poll == null) { System.out.println("Glasanje nije pronadjeno"); return; }

        System.out.println("Opcije:");
        for (int i = 0; i < poll.options.size(); i++)
            System.out.println("  " + (i+1) + ". " + poll.options.get(i));

        System.out.print("Tvoj izbor (broj): ");
        int izbor;
        try {
            izbor = Integer.parseInt(sc.nextLine().trim()) - 1;
            if (izbor < 0 || izbor >= poll.options.size()) throw new NumberFormatException();
        } catch (NumberFormatException e) {
            System.out.println("Nevazeci izbor");
            return;
        }
        String odabranOpcija = poll.options.get(izbor);

        System.out.println("Potvrdjujes glas za: \"" + odabranOpcija + "\"");
        System.out.print("(d/n): ");
        if (!sc.nextLine().trim().equalsIgnoreCase("d")) {
            System.out.println("Glasanje otkazano");
            return;
        }

        try {
            RegistrationService.UserRecord rec = regService.getUsers().get(username);
            char[] password = getPassword("Lozinka: ");

            String voteId = pollService.castVote(
                    pollId, odabranOpcija, username, rec.keystorePath, password);

            System.out.println("\n╔═══════════════════════════════════════╗");
            System.out.println("║          POTVRDA GLASANJA              ║");
            System.out.println("╠════════════════════════════════════════╣");
            System.out.printf ("║  VoteID: %-29s║%n", voteId);
            System.out.println("║  Sacuvaj ovaj ID za verifikaciju!      ║");
            System.out.println("╚════════════════════════════════════════╝");

        } catch (Exception e) {
            System.out.println("Greska pri glasanju: " + e.getMessage());
        }
    }

    private static void verifyVote(X509Certificate voterCert) {
        System.out.print("Poll ID: ");
        String pollId = sc.nextLine().trim();
        System.out.print("Vote ID: ");
        String voteId = sc.nextLine().trim();

        try {
            String result = pollService.verifyVote(pollId, voteId, voterCert);
            System.out.println(result);
        } catch (Exception e) {
            System.out.println("[!] Greška: " + e.getMessage());
        }
    }

    private static char[] getPassword(String prompt) {
        System.out.print(prompt);
        return sc.nextLine().toCharArray();    }
}