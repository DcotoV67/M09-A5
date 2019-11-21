package com.ejercicios3;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.*;

public class Main {

    public static void main(String[] args) throws Exception {
	// write your code here
        Scanner scanner = new Scanner(System.in);
        crypt crypt = new crypt();

        // EJERCICIO 1.1

        System.out.println("Ejercicio 1.1");
        String texto;
        KeyPair pair = crypt.randomGenerate(1024);

        System.out.println("Dime el texto a cifrar: ");

        texto = scanner.nextLine();

        byte[] data = texto.getBytes();

        byte[] cifrado = crypt.encryptData(data, pair.getPublic());
        byte[] descifrado = crypt.decryptData(cifrado, pair.getPrivate());

        System.out.println("Private Key:");
        System.out.println(pair.getPrivate());
        System.out.println("");
        System.out.println("Public Key:");
        System.out.println(pair.getPublic());
        System.out.println("");
        System.out.println("Texto cifrado:");
        System.out.println(cifrado);
        System.out.println("");
        System.out.println("Texto descifrado:");
        System.out.println(new String(descifrado));


        //EJERCICIO 1.2

        // 1.2.1

        System.out.println("Ejercicio 1.2");

        KeyStore ks = crypt.loadKeyStore("/home/dam2a/keystore_Dani_jks","password");

        System.out.println("Tipo del keystore: " + ks.getType());
        System.out.println("Tamaño del keystore: " + ks.size());

        Enumeration<String> enumeration = ks.aliases();
        while (enumeration.hasMoreElements()){
            System.out.println("Alias del keystore: " + ks.aliases());
        }

        System.out.println("Certificado de una clave del keystore: " + ks.getCertificate("lamevaclaum9"));
        System.out.println("Algoritmo de una clave del keystore : " + ks.getKey("lamevaclaum9", "password".toCharArray()).getAlgorithm());

        // 1.2.2

        String pswd = "password";

        SecretKey secretKey = crypt.keygenKeyGeneration(256);

        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secretKey);
        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(pswd.toCharArray());

        ks.setEntry("secretKeyAlias", skEntry, protectionParameter);

        try (FileOutputStream fileOutputStream = new FileOutputStream("/home/dam2a/keystore_Dani.jks")){
            ks.store(fileOutputStream, "password".toCharArray());
        }

        System.out.println(ks.getEntry("secretKeyAlias", protectionParameter));

        // 1.2.3

        FileInputStream fileInputStream = new FileInputStream("/home/dam2a/jordi.cer");
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Collection c = certificateFactory.generateCertificates(fileInputStream);
        Iterator i = c.iterator();
        while (i.hasNext()) {
            Certificate cert = (Certificate)i.next();
            System.out.println(cert);
        }

        // 1.2.4

        FileInputStream is = new FileInputStream("/home/dam2a/keystore_DaniNewKs.jks");
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, "password".toCharArray());

        String alias = "mykey";

        Key key = keystore.getKey(alias, "password".toCharArray());
        if (key instanceof PrivateKey) {

            Certificate cert = keystore.getCertificate(alias);

            PublicKey publicKey = cert.getPublicKey();
            System.out.println(publicKey.toString());
        }



        // 1.2.5


        byte[] dataBy = "data".getBytes();

        PrivateKey privKey = pair.getPrivate();

        byte[] firma = crypt.signData(dataBy,privKey);

        System.out.println(new String(firma));


        // 1.2.6


        PublicKey publicKey = pair.getPublic();

        boolean verificado = crypt.validateSignature(dataBy,firma,publicKey);

        System.out.println(verificado);


        // Ejercicio 2.2

        System.out.println("Ejercicio 2.2");

        KeyPair claves = crypt.randomGenerate(1024);

        PublicKey pubKey = claves.getPublic();
        PrivateKey privateKey = claves.getPrivate();

        byte[][] wrappedKeyEncrypt = crypt.encryptWrappedData(dataBy,pubKey);


        byte[]  wrappedKeyDecrypt = crypt.decryptWrappedData(cla9uEmbEnc,privateKey);

        System.out.println(new String(wrappedKeyDecrypt));

    }
}
