package de.ellersoftware.maven.pgptest;

import java.io.Closeable;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
 
public class PGPFileProcessor {
 
    private String passphrase;
    private String inputFileName;
    private InputStream publicKeyInputStream;
    private InputStream secretKeyInputStream;
    private InputStream inputStream;
    private OutputStream outputStream;
    private boolean asciiArmored = false;
    private boolean integrityCheck = true;

    
    
    public boolean encrypt() throws Exception {
        PGPUtils.encryptFile(outputStream, inputFileName, 
        		               PGPUtils.readPublicKey(publicKeyInputStream), 
        		               asciiArmored, integrityCheck);
        if (outputStream instanceof Closeable) {
        	outputStream.close();
        }
        if (publicKeyInputStream instanceof Closeable) {
        	publicKeyInputStream.close();
        }
        
        return true;
    }
 
    
    
    public boolean signEncrypt() throws Exception {
        PGPPublicKey publicKey = PGPUtils.readPublicKey(publicKeyInputStream);
        PGPSecretKey secretKey = PGPUtils.readSecretKey(secretKeyInputStream);
 
        PGPUtils.signEncryptFile(outputStream, inputFileName, 
        		                   publicKey, secretKey, this.getPassphrase(), 
        		                   this.isAsciiArmored(), this.isIntegrityCheck() );

        if (outputStream instanceof Closeable) {
        	outputStream.close();
        }
        if (publicKeyInputStream instanceof Closeable) {
        	publicKeyInputStream.close();
        }
        if (secretKeyInputStream instanceof Closeable) {
        	secretKeyInputStream.close();
        }
 
        return true;
    }
 
    
    
    public boolean decrypt() throws Exception {
        PGPUtils.decryptFile(inputStream, outputStream, secretKeyInputStream, passphrase.toCharArray());
        if (outputStream instanceof Closeable) {
        	outputStream.close();
        }
        if (publicKeyInputStream instanceof Closeable) {
        	publicKeyInputStream.close();
        }
        if (secretKeyInputStream instanceof Closeable) {
        	secretKeyInputStream.close();
        }
        return true;
    }
 
    
    
    public boolean isAsciiArmored() {
            return asciiArmored;
    }
 
    public void setAsciiArmored(boolean asciiArmored) {
            this.asciiArmored = asciiArmored;
    }
 
    
    
    public boolean isIntegrityCheck() {
            return integrityCheck;
    }
 
    public void setIntegrityCheck(boolean integrityCheck) {
            this.integrityCheck = integrityCheck;
    }
 
    
    
    public String getPassphrase() {
            return passphrase;
    }
 
    public void setPassphrase(String passphrase) {
            this.passphrase = passphrase;
    }
 
    
    
    public InputStream getPublicKeyInputStream() {
            return publicKeyInputStream;
    }
 
    public void setPublicKeyInputStream(InputStream publicKeyInputStream) {
            this.publicKeyInputStream = publicKeyInputStream;
    }

    
    
    public InputStream getSecretKeyInputStream() {
            return secretKeyInputStream;
    }
    
    public void setSecretKeyInputStream(InputStream secretKeyInputStream) {
            this.secretKeyInputStream = secretKeyInputStream;
    }

    
    
    public String getInputFileName() {
            return inputFileName;
    }
 
    public void setInputFileName(String inputFileName) {
            this.inputFileName = inputFileName;
    }
 
    
    
    public InputStream getInputStream() {
            return inputStream;
    }
 
    public void setInputStream(InputStream inputStream) {
            this.inputStream = inputStream;
    }
 
    
    
    public OutputStream getOutputStream() {
            return outputStream;
    }
 
    public void setOutputStream(OutputStream outputStream) {
            this.outputStream = outputStream;
    }
 
}