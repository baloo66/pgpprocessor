package de.ellersoftware.maven.pgptest;

import java.io.FileInputStream;
import java.io.FileOutputStream;

public class Tester {
 
    private static final String PASSPHRASE = "mtfbwy#MTFBWY#m1t2f3b4w5";
 
    // private static final String DE_INPUT = "C:/temp/gpg/replace-briefauswahl-db.xml.pgp";
    private static final String DE_INPUT = "/media/aeller/HAMA-STICK/replace-briefauswahl-db.xml.pgp";
    // private static final String DE_OUTPUT = "C:/temp/gpg/replace-briefauswahl-db.xml";
    private static final String DE_OUTPUT = "/media/aeller/HAMA-STICK/replace-briefauswahl-db.xml";
    // private static final String DE_KEY_FILE = "Z:/Users/ServiceHarvestBuild/AppData/Roaming/gnupg/secring.gpg";
    private static final String DE_KEY_FILE = "/media/aeller/HAMA-STICK/Harvest_gnupg/secring.gpg";
    
 
    // private static final String E_INPUT = "src/test/x.txt";
    private static final String E_INPUT = "/media/aeller/HAMA-STICK/x.txt";
    // private static final String E_OUTPUT = "src/test/x.pgp";
    private static final String E_OUTPUT = "/media/aeller/HAMA-STICK/x.pgp";
    // private static final String E_KEY_FILE = "src/test/pubring.pkr";
    private static final String E_KEY_FILE = "/media/aeller/HAMA-STICK/Harvest_gnupg/pubring.gpg";
 
 
    public static void main(String[] args) throws Exception {
		// testDecrypt();
    	testEncrypt();
	}
    
    public static void testDecrypt() throws Exception {
        PGPFileProcessor p = new PGPFileProcessor();
        p.setInputStream(new FileInputStream(DE_INPUT));
        p.setOutputStream(new FileOutputStream(DE_OUTPUT));
        p.setPassphrase(PASSPHRASE);
        p.setSecretKeyInputStream(new FileInputStream(DE_KEY_FILE));
        System.out.println(p.decrypt());
    }
 
    public static void testEncrypt() throws Exception {
        PGPFileProcessor p = new PGPFileProcessor();
        p.setInputFileName(E_INPUT);
        p.setOutputStream(new FileOutputStream(E_OUTPUT));
        p.setPassphrase(PASSPHRASE);
        p.setPublicKeyInputStream(new FileInputStream(E_KEY_FILE));
        System.out.println(p.encrypt());
    }
}