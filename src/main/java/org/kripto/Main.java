package org.kripto;

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
    public static void main(String[] args) throws Exception{
        System.out.println("----- Inicijalizacija CA hijerarhije -----");
        RootCA rootCA = new RootCA();
        OrgCA orgCA = new OrgCA(rootCA);
        VoterCA voterCA = new VoterCA(rootCA);
        System.out.println("Root CA, Org CA i Voter CA su inicijalizovani.");
        System.out.println();

        RegistrationService regService = new RegistrationService(rootCA, orgCA, voterCA);

        String ksDir = "keystores";
        Files.createDirectories(Paths.get(ksDir));

        Scanner sc = new Scanner(System.in);

        while (true) {
            System.out.println("\n=== REGISTRACIJA ===");
            System.out.println("1. Registruj organizatora");
            System.out.println("2. Registruj glasača");
            System.out.println("0. Izlaz");
            System.out.print("Odabir: ");
            String choice = sc.nextLine().trim();

            if(choice.equals("1")) {
                System.out.print("Naziv organizacije: ");
                String orgName = sc.nextLine().trim();
                System.out.print("Identifikacioni broj: ");
                String orgId = sc.nextLine().trim();
                System.out.print("Korisničko ime: ");
                String username = sc.nextLine().trim();
                System.out.print("Lozinka: ");
                String password = sc.nextLine().trim();

                try {
                    regService.registerOrganizer(orgName, orgId, username, password, ksDir);
                } catch (Exception e) {
                    System.out.println("Greska: " + e.getMessage());
                }
            } else if(choice.equals("2")) {
                System.out.print("Ime: ");
                String first = sc.nextLine().trim();
                System.out.print("Prezime: ");
                String last = sc.nextLine().trim();
                System.out.print("Korisničko ime: ");
                String username = sc.nextLine().trim();
                System.out.print("Lozinka: ");
                String password = sc.nextLine().trim();

                try {
                    regService.registerVoter(first, last, username, password, ksDir);
                } catch (Exception e) {
                    System.out.println("Greska: " + e.getMessage());
                }
            } else if(choice.equals("0")) {
                break;
            }
        }
        sc.close();
    }
}