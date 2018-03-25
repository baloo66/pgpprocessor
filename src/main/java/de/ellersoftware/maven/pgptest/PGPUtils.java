package de.ellersoftware.maven.pgptest;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
 
public class PGPUtils {
 
    private static final int   BUFFER_SIZE = 1 << 16; // should always be power of 2
    private static final int   KEY_FLAGS = KeyFlags.SPLIT | KeyFlags.ENCRYPT_STORAGE | KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER; 
    private static final int[] MASTER_KEY_CERTIFICATION_TYPES = new int[]{ PGPSignature.POSITIVE_CERTIFICATION,
    		                                                               PGPSignature.CASUAL_CERTIFICATION,
    		                                                               PGPSignature.NO_CERTIFICATION,
    		                                                               PGPSignature.DEFAULT_CERTIFICATION };
 

    
    /**
     * 
     * @param keyInputStream
     * @return
     * @throws IOException
     * @throws PGPException
     */
    public static PGPPublicKey readPublicKey(InputStream keyInputStream)
           throws IOException, PGPException {
 
        PGPPublicKeyRingCollection publicKeyRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyInputStream), new BcKeyFingerprintCalculator());
 
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        PGPPublicKey publicKey = null;
 
        // iterate through the key rings.
        Iterator<PGPPublicKeyRing> publicKeyRingIterator = publicKeyRingCollection.getKeyRings();
        while ((publicKey == null) && (publicKeyRingIterator.hasNext())) {
            PGPPublicKeyRing publicKeyRing = publicKeyRingIterator.next();
            Iterator<PGPPublicKey> publicKeyIterator = publicKeyRing.getPublicKeys();
            while ((publicKey == null) && (publicKeyIterator.hasNext())) {
                PGPPublicKey publicKeyCandidate = publicKeyIterator.next();
                if (publicKeyCandidate.isEncryptionKey()) {
                    publicKey = publicKeyCandidate;
                }
            }
        }

        // Validate public key
        if (publicKey == null) {
            throw new IllegalArgumentException("Can't find public key in the key ring.");
        }
        
        if (!isForEncryption(publicKey)) {
            throw new IllegalArgumentException("KeyID " + publicKey.getKeyID() + " not flagged for encryption.");
        }
 
        return publicKey;
    }
 
    
    
    /**
     * 
     * @param keyInputStream
     * @return
     * @throws IOException
     * @throws PGPException
     */
    public static PGPSecretKey readSecretKey(InputStream keyInputStream)
                  throws IOException, PGPException {
 
        PGPSecretKeyRingCollection secretKeyRingCollection = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyInputStream), new BcKeyFingerprintCalculator());
 
        // We just loop through the collection till we find a key suitable for signing. 
        PGPSecretKey secretKey = null;
        
        // iterate through the key rings
        Iterator<PGPSecretKeyRing> secretKeyRingIterator = secretKeyRingCollection.getKeyRings();
        while ((secretKey == null) && (secretKeyRingIterator.hasNext())) {
            PGPSecretKeyRing secretKeyRing = secretKeyRingIterator.next();
            Iterator<PGPSecretKey> secretKeyIterator = secretKeyRing.getSecretKeys();
            while ((secretKey == null) && (secretKeyIterator.hasNext())) {
                PGPSecretKey secretKeyCandidate = secretKeyIterator.next();
                if (secretKeyCandidate.isSigningKey()) {
                    secretKey = secretKeyCandidate;
                }
            }
        }
 
        // Validate secret key
        if (secretKey == null) {
            throw new IllegalArgumentException("Can't find private key in the key ring.");
        }
        if (!secretKey.isSigningKey()) {
            throw new IllegalArgumentException("Private key does not allow signing.");
        }
        if (secretKey.getPublicKey().hasRevocation()) {
            throw new IllegalArgumentException("Private key has been revoked.");
        }
        if (!hasKeyFlags(secretKey.getPublicKey(), KeyFlags.SIGN_DATA)) {
            throw new IllegalArgumentException("Key cannot be used for signing.");
        }
 
        return secretKey;
    }
 


    /**
     * Load a secret key ring collection from keyIn and find the private key corresponding to
     * keyID if it exists.
     *
     * @param keyInputStream input stream representing a key ring collection.
     * @param keyID keyID we want.
     * @param passphrase passphrase to decrypt secret key with.
     * @return
     * @throws IOException
     * @throws PGPException
     * @throws NoSuchProviderException
     */
    public static PGPPrivateKey findPrivateKey(InputStream keyInputStream, long keyID, char[] passphrase)
                  throws IOException, PGPException, NoSuchProviderException {
        PGPSecretKeyRingCollection pgpSecretKeyCollection = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyInputStream), new BcKeyFingerprintCalculator());
        return findPrivateKey(pgpSecretKeyCollection.getSecretKey(keyID), passphrase);
 
    }
 


    /**
     * decode the private key from a secret key
     * @param pgpSecretKey The secret key
     * @param passphrase passphrase to decrypt secret key with
     * @return the extracted private key
     * @throws PGPException
     */
    public static PGPPrivateKey findPrivateKey(PGPSecretKey pgpSecretKey, char[] passphrase)
                  throws PGPException {
        if (pgpSecretKey == null) {
        	return null;
        }
        PBESecretKeyDecryptor secretKeyDecryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(passphrase);
        return pgpSecretKey.extractPrivateKey(secretKeyDecryptor);
    }

   
   
    /**
     * decrypt the passed in message stream
     */
    @SuppressWarnings("unchecked")
    public static void decryptFile(InputStream inputStreamToDecrypt, OutputStream decryptedOutputStream, InputStream keyInputStream, char[] password)
                  throws Exception {
    	
        Security.addProvider(new BouncyCastleProvider()); // make BouncyCastle a known and valid security provider
        
        inputStreamToDecrypt = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(inputStreamToDecrypt);
 
        PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(inputStreamToDecrypt, new BcKeyFingerprintCalculator());

        // get encrypted data; the first object might be a PGP marker packet - skip it
        PGPEncryptedDataList encryptedData;
        Object objectFromInputStream = pgpObjectFactory.nextObject();
        if (objectFromInputStream instanceof  PGPEncryptedDataList) {
            encryptedData = (PGPEncryptedDataList)objectFromInputStream;
        } else { 
            encryptedData = (PGPEncryptedDataList)pgpObjectFactory.nextObject();
        }
 
        // find the secret key
        Iterator<PGPPublicKeyEncryptedData> encryptedDataIterator = encryptedData.getEncryptedDataObjects();
        PGPPrivateKey secretKey = null;
        PGPPublicKeyEncryptedData publicKeyEncryptedData = null;
        while ((secretKey == null) && (encryptedDataIterator.hasNext())) {
            publicKeyEncryptedData = encryptedDataIterator.next();
            secretKey = findPrivateKey(keyInputStream, publicKeyEncryptedData.getKeyID(), password);
        }
        if (secretKey == null) {
            throw new IllegalArgumentException("Secret key for message not found.");
        }
 
        InputStream decryptedData = publicKeyEncryptedData.getDataStream(new BcPublicKeyDataDecryptorFactory(secretKey));
        pgpObjectFactory = new PGPObjectFactory(decryptedData, new BcKeyFingerprintCalculator());
 
        Object message = pgpObjectFactory.nextObject();
 
        if (message instanceof PGPCompressedData) {
            PGPCompressedData compressedData = (PGPCompressedData)message;
            pgpObjectFactory = new PGPObjectFactory(compressedData.getDataStream(), new BcKeyFingerprintCalculator());
            message = pgpObjectFactory.nextObject();
        }
        if (message instanceof PGPLiteralData) {
            PGPLiteralData literalData = (PGPLiteralData) message;
            InputStream rawLiteralData = literalData.getInputStream();
            int readChar;
            while ((readChar = rawLiteralData.read()) >= 0) {
                decryptedOutputStream.write(readChar);
            }
        } else if (message instanceof PGPOnePassSignatureList) {
            throw new PGPException("Encrypted message contains a signed message - not literal data.");
        } else {
            throw new PGPException("Message is not a simple encrypted file - type unknown.");
        }
 
        if (publicKeyEncryptedData.isIntegrityProtected()) {
            if (!publicKeyEncryptedData.verify()) {
                throw new PGPException("Message failed integrity check");
            }
        }
    }
 


    /**
     * 
     * @param encryptedOutputStream
     * @param fileName
     * @param publicEncrptionKey
     * @param asciiArmored
     * @param withIntegrityCheck
     * @throws IOException
     * @throws NoSuchProviderException
     * @throws PGPException
     */
    public static void encryptFile(OutputStream encryptedOutputStream, String fileName, PGPPublicKey publicEncrptionKey, boolean asciiArmored, boolean withIntegrityCheck)
    		           throws IOException, NoSuchProviderException, PGPException {

    	Security.addProvider(new BouncyCastleProvider()); // make BouncyCastle a known and valid security provider
 
        if (asciiArmored) { // make an ASCII armored output stream on request
            encryptedOutputStream = new ArmoredOutputStream(encryptedOutputStream);
        }
 
        // convert file content to a compressed output stream
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();       
        PGPCompressedDataGenerator commpressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
        PGPUtil.writeFileToLiteralData(commpressedDataGenerator.open(byteArrayOutputStream), PGPLiteralData.BINARY, new File(fileName) ); 
        commpressedDataGenerator.close();
 
        // 
        BcPGPDataEncryptorBuilder dataEncryptorBuilder = new BcPGPDataEncryptorBuilder(PGPEncryptedData.TRIPLE_DES);
        dataEncryptorBuilder.setWithIntegrityPacket(withIntegrityCheck);
        dataEncryptorBuilder.setSecureRandom(new SecureRandom());
        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(dataEncryptorBuilder);
        encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(publicEncrptionKey));
        
        // get the (compressed) content of file and encrypt it 
        byte[] bytes = byteArrayOutputStream.toByteArray();
        OutputStream encryptedOutput = encryptedDataGenerator.open(encryptedOutputStream, bytes.length);
        encryptedOutput.write(bytes);
        encryptedOutput.close();
        encryptedOutputStream.close();
    }
 


    /**
     * 
     * @param encryptedOutputStream
     * @param fileName
     * @param publicEncryptionKey
     * @param secretKey
     * @param password
     * @param asciiArmored
     * @param withIntegrityCheck
     * @throws Exception
     */
    public static void signEncryptFile(OutputStream encryptedOutputStream, String fileName, PGPPublicKey publicEncryptionKey, PGPSecretKey secretKey,  String password, boolean asciiArmored, boolean withIntegrityCheck )
                  throws Exception {
 
        Provider provider = new BouncyCastleProvider(); // make BouncyCasle a known and valid security provider
        Security.addProvider(provider);
 
        if (asciiArmored) { // make an ASCII armored output stream on request
            encryptedOutputStream = new ArmoredOutputStream(encryptedOutputStream);
        }
 
        // 
        BcPGPDataEncryptorBuilder dataEncryptorBuilder = new BcPGPDataEncryptorBuilder(PGPEncryptedData.TRIPLE_DES);
        dataEncryptorBuilder.setWithIntegrityPacket(withIntegrityCheck);
        dataEncryptorBuilder.setSecureRandom(new SecureRandom());
        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(dataEncryptorBuilder);
        encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(publicEncryptionKey));
 
        OutputStream encryptedOut = encryptedDataGenerator.open(encryptedOutputStream, new byte[PGPUtils.BUFFER_SIZE]);
 
        // Initialize compressed data generator
        PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
        OutputStream compressedOut = compressedDataGenerator.open(encryptedOut, new byte [PGPUtils.BUFFER_SIZE]);
 
        // Initialize signature generator
        PGPPrivateKey privateKey = findPrivateKey(secretKey, password.toCharArray());
 
        PGPContentSignerBuilder signerBuilder = new BcPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1);
 
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(signerBuilder);
        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
 
        boolean firstTime = true;
        Iterator<String> it = secretKey.getPublicKey().getUserIDs();
        while (it.hasNext() && firstTime) {
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
            spGen.setSignerUserID(false, it.next());
            signatureGenerator.setHashedSubpackets(spGen.generate());
            // Exit the loop after the first iteration
            firstTime = false;
        }
        signatureGenerator.generateOnePassVersion(false).encode(compressedOut);
 
        // Initialize literal data generator
        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        OutputStream literalOut = literalDataGenerator.open(compressedOut, PGPLiteralData.BINARY, fileName, new Date(), new byte [PGPUtils.BUFFER_SIZE] );
 
        // Main loop - read the "in" stream, compress, encrypt and write to the "out" stream
        FileInputStream in = new FileInputStream(fileName);
        byte[] buf = new byte[PGPUtils.BUFFER_SIZE];
        int len;
        while ((len = in.read(buf)) > 0) {
            literalOut.write(buf, 0, len);
            signatureGenerator.update(buf, 0, len);
        }
 
        in.close();
        literalDataGenerator.close();
        // Generate the signature, compress, encrypt and write to the "out" stream
        signatureGenerator.generate().encode(compressedOut);
        compressedDataGenerator.close();
        encryptedDataGenerator.close();
        if (asciiArmored) {
            encryptedOutputStream.close();
        }
    }
 
    
    
    /**
     * 
     * @param inDataStream
     * @param inKeyStream
     * @param extractContentFile
     * @return
     * @throws Exception
     */
    public static boolean verifyFile(InputStream inDataStream, InputStream inKeyStream, String extractContentFile)
           throws Exception {
    	
        inDataStream = PGPUtil.getDecoderStream(inDataStream);
 
        PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(inDataStream, new BcKeyFingerprintCalculator());
        PGPCompressedData compressedData = (PGPCompressedData)pgpObjectFactory.nextObject(); // get data from file
 
        // get first 
        pgpObjectFactory = new PGPObjectFactory(compressedData.getDataStream(), new BcKeyFingerprintCalculator());
        PGPOnePassSignatureList onePassSignatureList = (PGPOnePassSignatureList)pgpObjectFactory.nextObject(); // 
        PGPOnePassSignature onePassSignature = onePassSignatureList.get(0); 
 
        PGPLiteralData literalData = (PGPLiteralData)pgpObjectFactory.nextObject();
        InputStream dataInputStream = literalData.getInputStream();
        
        IOUtils.copy(dataInputStream, new FileOutputStream(extractContentFile));
 
        // get correct public key from in key stream 
        PGPPublicKeyRingCollection publicKeyRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(inKeyStream), new BcKeyFingerprintCalculator());
        PGPPublicKey publicKey = publicKeyRingCollection.getPublicKey(onePassSignature.getKeyID());
 
        // iterate over data input, calculate signature and copy to original file name
        onePassSignature.init(new BcPGPContentVerifierBuilderProvider(), publicKey); // initialize for verification
        FileOutputStream outFileStream = new FileOutputStream(literalData.getFileName());
        for (int readCharacter = dataInputStream.read(); readCharacter >= 0; readCharacter = dataInputStream.read()) {
            onePassSignature.update((byte)readCharacter);
            outFileStream.write(readCharacter);
        }
        outFileStream.close();
 
        // get "correct" PGP signatures and compare with calculated signature 
        PGPSignatureList pgpSignatures = (PGPSignatureList)pgpObjectFactory.nextObject();
        
        return onePassSignature.verify(pgpSignatures.get(0));
    }
 
    
    
    /**
     * From LockBox Lobs PGP Encryption tools (http://www.lockboxlabs.org/content/downloads).
     *
     * I didn't think it was worth having to import a 4meg lib for three methods
     * 
     * @param key
     * @return
     */
    public static boolean isForEncryption(PGPPublicKey key)
    {
        if ( (key.getAlgorithm() == PublicKeyAlgorithmTags.RSA_SIGN)
          || (key.getAlgorithm() == PublicKeyAlgorithmTags.DSA)
          || (key.getAlgorithm() == PublicKeyAlgorithmTags.ECDH)
          || (key.getAlgorithm() == PublicKeyAlgorithmTags.ECDSA) ) {
            return false;
        }
 
        return hasKeyFlags(key, (KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE));
    }
 
    
    
    /**
     * From LockBox Lobs PGP Encryption tools (http://www.lockboxlabs.org/content/downloads).
     *
     * I didn't think it was worth having to import a 4meg lib for three methods
     * 
     * @param key
     * @return
     */
    @SuppressWarnings("unchecked")
    private static boolean hasKeyFlags(PGPPublicKey encryptionKey, int keyUsage) {
        if (encryptionKey.isMasterKey()) {
            for (int i = 0; i != PGPUtils.MASTER_KEY_CERTIFICATION_TYPES.length; i++) {
                for (Iterator<PGPSignature> signatureIterator = encryptionKey.getSignaturesOfType(PGPUtils.MASTER_KEY_CERTIFICATION_TYPES[i]); signatureIterator.hasNext();) {
                    PGPSignature signature = signatureIterator.next();
                    if (!isMatchingUsage(signature, keyUsage)) {
                        return false;
                    }
                }
            }
        } else {
            for (Iterator<PGPSignature> subkeySignatureIterator = encryptionKey.getSignaturesOfType(PGPSignature.SUBKEY_BINDING); subkeySignatureIterator.hasNext();) {
                PGPSignature subkeySignature = subkeySignatureIterator.next();
                if (!isMatchingUsage(subkeySignature, keyUsage)) {
                    return false;
                }
            }
        }
        return true;
    }
 
    
    
    /**
     * From LockBox Lobs PGP Encryption tools (http://www.lockboxlabs.org/content/downloads).
     *
     * I didn't think it was worth having to import a 4meg lib for three methods
     * 
     * @param key
     * @return
     */
    private static boolean isMatchingUsage(PGPSignature signature, int keyUsage) {
        if (signature.hasSubpackets()) {
            PGPSignatureSubpacketVector subpacketVector = signature.getHashedSubPackets();
            if (subpacketVector.hasSubpacket(PGPUtils.KEY_FLAGS)) {
                if ((subpacketVector.getKeyFlags() & keyUsage) == 0) {
                    return false;
                }
            }
        }
        return true;
    }
 
}