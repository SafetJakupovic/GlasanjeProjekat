package org.kripto;

import org.kripto.auth.CertificateValidator;
import org.kripto.auth.LoginService;
import org.kripto.ca.OrgCA;
import org.kripto.ca.RootCA;
import org.kripto.ca.VoterCA;
import org.kripto.registration.RegistrationService;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Scanner;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {
    private static RootCA rootCA;
    private static OrgCA orgCA;
    private static VoterCA voterCA;
    private static RegistrationService regService;
    private static LoginService loginService;
    private static Scanner sc = new Scanner(System.in);

    public static void main(String[] args) throws Exception{
        System.out.println("----- Inicijalizacija CA hijerarhije -----");
        rootCA = new RootCA();
        orgCA = new OrgCA(rootCA);
        voterCA = new VoterCA(rootCA);
        System.out.println("Root CA, Org CA i Voter CA su inicijalizovani.");
        System.out.println();

        regService = new RegistrationService(rootCA, orgCA, voterCA);
        CertificateValidator validator = new CertificateValidator(rootCA, orgCA, voterCA);
        loginService = new LoginService(regService, validator);

        String ksDir = "keystores";
        Files.createDirectories(Paths.get(ksDir));

        while (true) {
            System.out.println("\n=============================");
            System.out.println(" E-VOTING SISTEM");
            System.out.println("=============================");
            System.out.println("1. Registracija");
            System.out.println("2. Prijava");
            System.out.println("0. Izlaz");
            System.out.print("Odabir: ");
            String choice = sc.nextLine().trim();

            switch (choice) {
                case "1" -> registrationMenu(ksDir);
                case "2" -> loginMenu();
                case "0" -> { System.out.println("KRAJ"); return; }
                default  -> System.out.println("Nepoznata opcija.");
            }
        }
    }

    private static void registrationMenu(String ksDir) throws Exception {
        System.out.println("\n-- REGISTRACIJA --");
        System.out.println("1. Organizator");
        System.out.println("2. Glasač");
        System.out.print("Odabir: ");
        String tip = sc.nextLine().trim();

        if (tip.equals("1")) {
            System.out.print("Naziv organizacije: ");
            String orgName = sc.nextLine().trim();
            System.out.print("Identifikacioni broj: ");
            String orgId = sc.nextLine().trim();
            System.out.print("Korisničko ime: ");
            String username = sc.nextLine().trim();
            System.out.print("Lozinka: ");
            String password = sc.nextLine().trim();
            regService.registerOrganizer(orgName, orgId, username, password, ksDir);

        } else if (tip.equals("2")) {
            System.out.print("Ime: ");
            String ime = sc.nextLine().trim();
            System.out.print("Prezime: ");
            String prez = sc.nextLine().trim();
            System.out.print("Korisničko ime: ");
            String username = sc.nextLine().trim();
            System.out.print("Lozinka: ");
            String password = sc.nextLine().trim();
            regService.registerVoter(ime, prez, username, password, ksDir);
        }
    }

    private static void loginMenu() throws Exception {
        System.out.println("\n-- PRIJAVA --");

        System.out.println("Unos digitalnog sertifikata");
        System.out.print("Putanja do .p12 fajla: ");
        String p12Path = sc.nextLine().trim();
        System.out.print("Lozinka za .p12 fajl: ");
        String p12Password = sc.nextLine().trim();
        System.out.print("Korisničko ime (alias): ");
        String alias = sc.nextLine().trim();

        LoginService.StepOneResult s1 = loginService.stepOne(p12Path, p12Password, alias);
        if (!s1.success) {
            System.out.println("Korak 1 neuspješan: " + s1.message);
            return;
        }
        System.out.println("Sertifikat prihvaćen.");

        System.out.println("Unos kredencijala");
        System.out.print("Korisničko ime: ");
        String username = sc.nextLine().trim();
        System.out.print("Lozinka: ");
        String password = sc.nextLine().trim();

        LoginService.LoginResult result = loginService.stepTwo(s1.certificate, username, password);

        if (!result.success) {
            System.out.println("Prijava neuspješna: " + result.message);
            return;
        }

        System.out.println("\n" + result.message);

        if (result.role.equals("ORGANIZER")) {
            orgInterface(result.username);
        } else {
            voterInterface(result.username);
        }
    }

    private static void orgInterface(String username) {
        System.out.println("\n╔══════════════════════════════╗");
        System.out.println("║  ORGANIZATOR: " + username);
        System.out.println("╠═══════════════════════════════╣");
        System.out.println("║  1. Kreiraj glasanje          ║");
        System.out.println("║  2. Pregled glasanja          ║");
        System.out.println("║  3. Pokreni brojanje glasova  ║");
        System.out.println("║  0. Odjava                    ║");
        System.out.println("╚═══════════════════════════════╝");
    }

    private static void voterInterface(String username) {
        System.out.println("\n╔══════════════════════════════╗");
        System.out.println("║  GLASAČ: " + username);
        System.out.println("╠═══════════════════════════════╣");
        System.out.println("║  1. Aktivna glasanja          ║");
        System.out.println("║  2. Verifikuj moj glas        ║");
        System.out.println("║  0. Odjava                    ║");
        System.out.println("╚═══════════════════════════════╝");
    }
}