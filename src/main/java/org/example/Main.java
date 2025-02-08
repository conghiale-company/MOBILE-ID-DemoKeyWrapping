package org.example;

import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.*;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;

import java.util.Base64;
import java.util.List;
import java.util.Random;
import java.util.Scanner;

public class Main {
    private static final Logger LOG = Logger.getLogger(Main.class);
    private static final Scanner sc = new Scanner(System.in);
    public static HSMManagerImp hsmManager;

    private static KeyPair keyPairRSA, keyPairECDSA;
    private static AESSecretKey keyAES;
    private static byte[] rawKeyWrapped;

    private static String AES_KEY_LABEL = "CONGHIALE_IT_AES_01";
    private static String RSA_KEY_LABEL = "CONGHIALE_IT_RSA_01";
    private static String ECDSA_KEY_LABEL = "CONGHIALE_IT_ECDSA_01";

    public static void main(String[] args) throws Exception {
        System.out.println("HELLO. I'M CONGHIALE!!!");

        run();
    }

    private static void action() {
        System.out.println();
        System.out.println("---------------------START--------------------");
        System.out.println("CHOOSE...");
        System.out.println("1. Instance");
        System.out.println("2. Login");
        System.out.println("3. Generate key AES");
        System.out.println("4. Generate key RSA");
        System.out.println("5. Wrap primary key RSA");
        System.out.println("6. Sign with primary key RSA");
        System.out.println("7. Sign with UNWRAP primary key RSA");
        System.out.println("8. Generate key ECDSA");
        System.out.println("9. Wrap public key ECDSA");
        System.out.println("10. UnWrap public key ECDSA");
        System.out.println("11. Delete key");
        System.out.println("12. Check label key exists");
        System.out.println("13. Get keys");
        System.out.println("0. Exit");
        System.out.println("---------------------END----------------------");
    }

    private static void handleAction(int number) throws Exception {
        String keyLabel, keyType;
        boolean isExists;
        boolean isGen = false;

//        long mode = PKCS11Constants.CKM_AES_CBC_PAD;
//        long mode = PKCS11Constants.CKM_AES_KEY_WRAP;
        long mode = PKCS11Constants.CKM_AES_KEY_WRAP_PAD;
//        long mode = PKCS11Constants.CKM_RSA_PKCS;
//        long mode = PKCS11Constants.CKM_RSA_PKCS_OAEP;
        byte[] iv = genRandomArray(16);

        System.out.println();
        switch (number) {
            case 0:
                System.exit(0);

            case 1:
                hsmManager = (hsmManager == null ? getInstance() : hsmManager);
                break;

            case 2:
                boolean isLogin = hsmManager.loginHSM();
                if (isLogin)
                    System.out.println("LOGIN SUCCESSFULLY");
                else
                    System.out.println("LOGIN FAILED");

                break;

            case 3:
                boolean isAESKeyLabel = enterKeyLabel("AES");
                if (!isAESKeyLabel) {
                    isGen = false;
//                    isExists = hsmManager.labelExists(AES_KEY_LABEL);
//                    if (isExists) {
//                    System.out.println("Key AES with name " + AES_KEY_LABEL + " already exists");
                    System.out.println();
                    while (true) {
                        System.out.println();
                        System.out.println("Generate key AES By...");
                        System.out.println("1. Delete existing ASE key");
                        System.out.println("2. With new ASE keyLabel");
                        System.out.println("0. exit");
                        System.out.print("Choose: ");
                        int choose = sc.nextInt();
                        sc.nextLine();
                        System.out.println();

                        if (choose == 1) {
                            Key keyAes = hsmManager.findAESSecretKey(AES_KEY_LABEL);
                            if (keyAes != null) {
                                boolean isDeleted = hsmManager.deleteKey(keyAes);
                                isGen = isDeleted;
                                System.out.println("Delete AES Key " + (isDeleted ? "successfully" : "failed"));
                            } else {
                                System.out.println("AES Key not found");
                            }
                            break;
                        } else if (choose == 2) {
                            while (true) {
                                isAESKeyLabel = enterKeyLabel("AES");
                                if (isAESKeyLabel) {
                                    if (AES_KEY_LABEL != null && !AES_KEY_LABEL.isEmpty()) {
                                        isGen = true;
                                        break;
                                    }
                                } else {
                                    System.out.println("AES KeyLabel invalid!!!");
                                }

                            }

                            break;
                        } else if (choose == 0)
                            break;
                        else {
                            System.out.println("Please enter the correct function.");
                        }
                    }
//                    }
                }

                if (isAESKeyLabel || isGen){
                    System.out.println();
                    System.out.println("Generating...");
                    keyAES = hsmManager.genAESSecretKey(
                            AES_KEY_LABEL,
                            256,
                            true);

                    if (keyAES != null)
                        System.out.println("Generate aes key successfully with name = " + AES_KEY_LABEL);
                    else
                        System.out.println("Generating aes key failed");
                }

                break;

            case 4:
                boolean isRSAKeyLabel = enterKeyLabel("RSA");
                if (!isRSAKeyLabel) {
                    isGen = false;
//                    isExists = hsmManager.labelExists(RSA_KEY_LABEL);
//                    if (isExists) {
//                        System.out.println("Key RSA with name " + RSA_KEY_LABEL + " already exists");
                    System.out.println();
                    while (true) {
                        System.out.println();
                        System.out.println("Generate key RSA By...");
                        System.out.println("1. Delete existing RSA key");
                        System.out.println("2. With new RSA keyLabel");
                        System.out.println("0. exit");
                        System.out.print("Choose: ");
                        int choose = sc.nextInt();
                        sc.nextLine();
                        System.out.println();

                        if (choose == 1) {
                            Key privateKey = hsmManager.findPrivateKey(RSA_KEY_LABEL, "RSA");
                            if (privateKey != null) {
                                boolean isDeleted = hsmManager.deleteKey(privateKey);
                                isGen = isDeleted;
                                System.out.println("Delete private key " + (isDeleted ? "successfully" : "failed"));
                            } else
                                System.out.println("Private key not found with name: " + RSA_KEY_LABEL);

                            Key publicKey = hsmManager.findPublicKey(RSA_KEY_LABEL, "RSA");
                            if (publicKey != null) {
                                boolean isDeleted = hsmManager.deleteKey(publicKey);
                                isGen = isDeleted;
                                System.out.println("Delete public key " + (isDeleted ? "successfully" : "failed"));
                            }
                            else
                                System.out.println("Public key not found with name: " + RSA_KEY_LABEL);

                            break;

                        } else if (choose == 2) {
                            while (true) {
                                isRSAKeyLabel = enterKeyLabel("RSA");
                                if (isRSAKeyLabel) {
                                    if (RSA_KEY_LABEL != null && !RSA_KEY_LABEL.isEmpty()) {
                                        isGen = true;
                                        break;
                                    }
                                } else {
                                    System.out.println("RSA KeyLabel invalid!!!");
                                }
                            }

                            break;
                        } else if (choose == 0)
                            break;
                        else {
                            System.out.println("Please enter the correct function.");
                        }
                    }
//                    }
                }

                if (isRSAKeyLabel || isGen){
                    System.out.println();
                    System.out.println("Generating...");
                    keyPairRSA = hsmManager.genKeyPair(HSMFunction.KeyType.RSA, 2048, RSA_KEY_LABEL);
                    if (keyPairRSA != null) {
                        if (keyPairRSA.getPublicKey() != null)
                            System.out.println("RSA public key generated successfully with name = " + keyPairRSA.getPublicKey().getLabel());
                        else
                            System.out.println("RSA public key generation failed with name = " + keyPairRSA.getPublicKey().getLabel());

                        if (keyPairRSA.getPublicKey() != null)
                            System.out.println("RSA private key generated successfully with name = " + keyPairRSA.getPublicKey().getLabel());
                        else
                            System.out.println("RSA private key generation failed with name = " + keyPairRSA.getPublicKey().getLabel());
                    } else
                        System.out.println("RSA key generation failed");
                }

                break;

            case 5:
                System.out.println("wrapping...");

                if (keyPairRSA == null) {
                    System.out.println("RSA key not found with name: " + RSA_KEY_LABEL);
                    System.exit(0);
                } else
                    System.out.println("PrivateKey: " + keyPairRSA.getPrivateKey().getLabel());

                rawKeyWrapped = hsmManager.wrapKey(keyPairRSA.getPrivateKey(), keyAES, mode, iv);
                if (rawKeyWrapped != null)
                    System.out.println("key wrapped: " + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(rawKeyWrapped));
                else
                    System.out.println("key wrapping failed");

                break;

            case 6:
                System.out.println("test signing...");
                byte[] data2sign = new byte[32];
                data2sign = paddingSHA256OID(data2sign);
                byte[] signature = hsmManager.signWithPrivateKey(
                        PKCS11Constants.CKM_RSA_PKCS,
                        data2sign,
                        keyPairRSA.getPrivateKey());
                System.out.println("signature=" + Base64.getEncoder().encodeToString(signature));

                System.out.println("deleting...");
                Key hsmPubKey = keyPairRSA.getPublicKey();
                Key hsmPriKey = keyPairRSA.getPrivateKey();
                if (hsmPubKey != null) {
                    hsmManager.deleteKey(hsmPubKey);
                    System.out.println("\tdelete publicKey " + RSA_KEY_LABEL + " successfully");
                }
                if (hsmPriKey != null) {
                    hsmManager.deleteKey(hsmPriKey);
                    System.out.println("\tdelete signing key " + RSA_KEY_LABEL + " successfully");
                }

                break;

            case 7:
                System.out.println("unwrapping...");
                Key signingKey = hsmManager.unWrapKey(
                        rawKeyWrapped,
                        keyAES,
                        mode,
                        iv,
                        Key.KeyType.RSA,
                        RSA_KEY_LABEL,
                        true);
                System.out.println("unwrapping successfully");
                System.out.println("test signing...");
                data2sign = new byte[32];
                data2sign = paddingSHA256OID(data2sign);
                signature = hsmManager.signWithPrivateKey(
                        PKCS11Constants.CKM_RSA_PKCS,
                        data2sign,
                        signingKey);
                System.out.println("signature=" + Base64.getEncoder().encodeToString(signature));
                System.out.println("deleting...");
                hsmManager.deleteKey(signingKey);
                System.out.println("\tdelete signing key " + RSA_KEY_LABEL + " successfully");
                hsmManager.deleteKey(keyAES);
                System.out.println("\tdelete aes key " + AES_KEY_LABEL + " successfully");
                break;

            case 8:
                hsmManager = (hsmManager == null ? getInstance() : hsmManager);
                keyPairRSA = hsmManager.genKeyPair(HSMFunction.KeyType.ECDSA, 2048, ECDSA_KEY_LABEL);
                if (keyPairRSA != null)
                    System.out.println("ECDSA key generated successfully");
                else
                    System.out.println("ECDSA key generation failed");

                break;

            case 9:
                break;

            case 10:
                break;

            case 11:
                System.out.println();
                System.out.print("Enter KeyID: ");
                keyLabel = sc.nextLine();
                System.out.print("Enter KeyType: ");
                keyType = sc.nextLine();

                switch (keyType) {
                    case "RSA":                    case "ECDSA":
                        Key privateKey = hsmManager.findPrivateKey(keyLabel, keyType);
                        if (privateKey != null)
                            System.out.println("Delete private key " + (hsmManager.deleteKey(privateKey) ? "successfully" : "failed"));
                        else
                            System.out.println("Private key not found with name: " + keyLabel);

                        Key publicKey = hsmManager.findPublicKey(keyLabel, keyType);
                        if (publicKey != null)
                            System.out.println("Delete public key " + (hsmManager.deleteKey(publicKey) ? "successfully" : "failed"));
                        else
                            System.out.println("Public key not found with name: " + keyLabel);

                        break;

                    case "AES":
                        Key keyAes = hsmManager.findAESSecretKey(keyLabel);
                        if (keyAes != null)
                            System.out.println("Delete Key " + (hsmManager.deleteKey(keyAes) ? "successfully" : "failed"));
                        else
                            System.out.println("Key not found");

                        break;
                    default:
                        System.out.println("Invalid KeyType: " + keyType);
                        break;
                }
                break;

            case 12:
                System.out.println();
                System.out.print("Enter KeyLabel: ");
                String keyLabelCheck = sc.nextLine();

                if (isLabelExists(keyLabelCheck))
                    System.out.println("Key " + keyLabelCheck + " exists");
                else
                    System.out.println("Key " + keyLabelCheck + " not found");

                break;

            case 13:
                System.out.println();
                System.out.print("Enter KeyLabel: ");
                keyLabel = sc.nextLine();
                System.out.print("Enter KeyType: ");
                keyType = sc.nextLine();

                switch (keyType) {
                    case "RSA":
                        List<RSAPrivateKey> rsaPrivateKeys = hsmManager.getPrivateRSAKeyByLabel(keyLabel);
                        List<RSAPublicKey> rsaPublicKeys = hsmManager.getPublicRSAKeyByLabel(keyLabel);

                        if (rsaPublicKeys.isEmpty() || rsaPrivateKeys.isEmpty())
                            System.out.println("Key RSA with name " + keyLabel + " not found");
                        else
                            System.out.println("Key RSA with name " + keyLabel + " found with quantity is " + rsaPublicKeys.size());

//                        PrivateKey privateKey = hsmManager.findPrivateKey(keyLabel, keyType);
//                        PublicKey publicKey = hsmManager.findPublicKey(keyLabel, keyType);
//
//                        System.out.println("privateKey: " + (privateKey == null ? null : privateKey.getLabel()));
//                        System.out.println("publicKey: " + (publicKey == null ? null : publicKey.getLabel()));
//
//                        if (privateKey == null || publicKey == null)
//                            System.out.println("Key RSA with name " + keyLabel + " not found");
//
//                        else
//                            System.out.println("Key RSA with name " + keyLabel + " exist");

                        break;

                    case "ECDSA":
                        List<ECDSAPrivateKey> ecdsaPrivateKeys = hsmManager.getPrivateECKeyByLabel(keyLabel);
                        List<ECDSAPublicKey> ecdsaPublicKeys = hsmManager.getPublicECKeyByLabel(keyLabel);

                        if (ecdsaPublicKeys.isEmpty() || ecdsaPrivateKeys.isEmpty())
                            System.out.println("Key ECDSA with name " + keyLabel + " not found");
                        else
                            System.out.println("Key ECDSA with name " + keyLabel + " found with quantity is " + ecdsaPublicKeys.size());

                        break;

                    case "AES":
                        List<AESSecretKey> aesSecretKeys = hsmManager.getAESKeyByLabel(keyLabel);
                        Key keyAes = hsmManager.findAESSecretKey(keyLabel);
                        System.out.println("Key AES with name " + keyLabel + " with algorithm findAESSecretKey: " + (keyAes != null));

                        if (aesSecretKeys.isEmpty())
                            System.out.println("Key AES with name " + keyLabel + " not found");
                        else
                            System.out.println("Key AES with name " + keyLabel + " found with quantity is " + aesSecretKeys.size());

                        break;

                    default:
                        System.out.println("Your keyType is not valid");
                        break;
                }

                break;

            default:
                System.out.println("Your choice is not valid. Please re-enter");
                break;
        }
    }

    static HSMManagerImp getInstance() {
        String sofile = "/usr/lib/libcs_pkcs11_R3.so";
        String wrapper = "/root/TestIAIK/libpkcs11wrapper.so";
        String slotstr = "0";
        String pin = "12345678";

        return HSMManagerImp.getInstance(sofile, wrapper, Integer.parseInt(slotstr), pin);
    }

    public static byte[] genRandomArray(int size) {
        // TODO Auto-generated method stub
        byte[] random = new byte[size];
        new Random().nextBytes(random);
        return random;
    }

    public static byte[] paddingSHA256OID(byte[] hashedData) throws Exception {
        DigestAlgorithmIdentifierFinder hashAlgorithmFinder = new DefaultDigestAlgorithmIdentifierFinder();
        AlgorithmIdentifier hashingAlgorithmIdentifier = hashAlgorithmFinder.find("SHA-256");
        DigestInfo digestInfo = new DigestInfo(hashingAlgorithmIdentifier, hashedData);
        return digestInfo.getEncoded();
    }

    private static boolean enterKeyLabel(String type) throws TokenException {
        switch (type) {
            case "RSA":
                System.out.print("Enter RSA keyLabel: ");
                RSA_KEY_LABEL = sc.nextLine();

                if (RSA_KEY_LABEL == null || RSA_KEY_LABEL.isEmpty()) {
                    System.out.println("RSA keyLabel invalid");
                } else if (isLabelExists(RSA_KEY_LABEL)) {
                    System.out.println("Key RSA with name " + RSA_KEY_LABEL + " already exists");
                } else
                    return true;

                break;

            case "ECDSA":
                System.out.print("Enter ECDSA keyLabel: ");
                ECDSA_KEY_LABEL = sc.nextLine();

                if (ECDSA_KEY_LABEL == null || ECDSA_KEY_LABEL.isEmpty()) {
                    System.out.println("ECDSA keyLabel invalid");
                } else if (isLabelExists(ECDSA_KEY_LABEL)) {
                    System.out.println("Key ECDSA with name " + ECDSA_KEY_LABEL + " already exists");
                } else
                    return true;

                break;

            case "AES":
                System.out.print("Enter AES keyLabel: ");
                AES_KEY_LABEL = sc.nextLine();

                if (AES_KEY_LABEL == null || AES_KEY_LABEL.isEmpty()) {
                    System.out.println("AES keyLabel invalid");
                } else if (isLabelExists(AES_KEY_LABEL))
                    System.out.println("Key AES with name " + AES_KEY_LABEL + " already exists");
                else
                    return true;

                break;

            default:
                System.out.println("Invalid KeyType: " + type);
        }
        return false;
    }

    private static boolean isLabelExists(String keyLabelCheck) throws TokenException {
        return hsmManager.labelExists(keyLabelCheck);
    }

    public static void run() throws Exception {
        int number;
        while (true){
            action();
            System.out.println();
            System.out.print("Enter your choice: ");
            number = sc.nextInt();
            sc.nextLine();

            handleAction(number);
        }
    }
}