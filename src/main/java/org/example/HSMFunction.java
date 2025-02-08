package org.example;

import iaik.pkcs.pkcs11.*;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.objects.*;
import iaik.pkcs.pkcs11.objects.Object;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

public class HSMFunction {
    private static final Logger logger = Logger.getLogger(Main.class);

    private Module module;

    private Slot slotToken = null;

    private static HSMFunction instance = null;

    public enum KeyType {
        RSA, ECDSA, AES;
    }

//    Gen AES key
    public AESSecretKey genAESKey(String keyID, int size, Session session, boolean isToken, boolean isSensitive) throws TokenException {

//        Mechanism keyGenerationMechanism = Mechanism.get(PKCS11Constants.CKM_AES_KEY_GEN);
//        AESSecretKey secretKeyTemplate = new AESSecretKey();
//
//        secretKeyTemplate.getId().setByteArrayValue(keyID.getBytes());
//        secretKeyTemplate.getLabel().setCharArrayValue(keyID.toCharArray());
//
//        secretKeyTemplate.getValueLen().setLongValue((long) (size / 8));
//        secretKeyTemplate.getSensitive().setBooleanValue(isSensitive);
//        secretKeyTemplate.getToken().setBooleanValue(isToken);              // not store in hsm
//        secretKeyTemplate.getExtractable().setBooleanValue(Boolean.FALSE);
////        secretKeyTemplate.getModifiable().setBooleanValue(Boolean.FALSE);
//
//        //add for trident
//        secretKeyTemplate.getWrap().setBooleanValue(Boolean.TRUE); // acb
//        secretKeyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE); // acb
//        secretKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
//        secretKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
////        secretKeyTemplate.getTrusted().setBooleanValue(Boolean.TRUE);
////        secretKeyTemplate.getDerive().setBooleanValue(Boolean.TRUE);
//
//        secretKeyTemplate.getKeyType().setLongValue(PKCS11Constants.CKK_AES);
//        secretKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_SECRET_KEY);
//
//        AESSecretKey secretKey = (AESSecretKey) session.generateKey(keyGenerationMechanism, secretKeyTemplate);
//        // return secretKey.getValue().getByteArrayValue();
//        return secretKey;

        Mechanism keyGenerationMechanism = Mechanism.get(4224L);
        AESSecretKey secretKeyTemplate = new AESSecretKey();
        secretKeyTemplate.getId().setByteArrayValue(keyID.getBytes());
        secretKeyTemplate.getLabel().setCharArrayValue(keyID.toCharArray());
        secretKeyTemplate.getValueLen().setLongValue((long) (size / 8));
        secretKeyTemplate.getSensitive().setBooleanValue(Boolean.FALSE);
        secretKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getModifiable().setBooleanValue(Boolean.TRUE);
        return (AESSecretKey) session.generateKey(keyGenerationMechanism, (Object) secretKeyTemplate);
    }

//    Gen RSA Key pair
    public KeyPair genRSAKeyPair(String keyLabel, int size, BigInteger publicExponent, Session session, MechanismInfo signatureMechanismInfo, Module module) throws TokenException {
//        byte[] id = DatatypeConverter.parseHexBinary(keyLabel);  // keyLabel phải có số lượng chẵns
        byte[] id = keyLabel.getBytes();

//        Mechanism keyPairGenerationMechanism = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN);

        byte[] publicExponentBytes = {0x01, 0x00, 0x01}; // 2^16 + 1
        if (publicExponent != null) {
            publicExponentBytes = bigToByteArray(publicExponent);
        }

////        PUBLIC KEY
//        RSAPublicKey rsaPublicKeyTemplate = new RSAPublicKey();
//
//        rsaPublicKeyTemplate.getLabel().setCharArrayValue(keyLabel.toCharArray());
//        rsaPublicKeyTemplate.getId().setByteArrayValue(id);
//
////        set the general attributes for the public key
//        rsaPublicKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
//        rsaPublicKeyTemplate.getModulusBits().setLongValue((long) size);
//        rsaPublicKeyTemplate.getPublicExponent().setByteArrayValue(publicExponentBytes);
//
//        //add for trident
//        rsaPublicKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
//        rsaPublicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);
//        rsaPublicKeyTemplate.getWrap().setBooleanValue(Boolean.TRUE);
//
////        rsaPublicKeyTemplate.getKeyType().setPresent(false);
////        rsaPublicKeyTemplate.getObjectClass().setPresent(false);
//
////        PRIVATE KEY
//        RSAPrivateKey rsaPrivateKeyTemplate = new RSAPrivateKey();
//
//        rsaPrivateKeyTemplate.getId().setByteArrayValue(id);
//        rsaPrivateKeyTemplate.getLabel().setCharArrayValue(keyLabel.toCharArray());
//
////        rsaPrivateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
////        rsaPrivateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
//
//        rsaPrivateKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE); //-> allow wrap
//        rsaPrivateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
//
//        //add for trident
//        rsaPrivateKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
//        rsaPrivateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
//        rsaPrivateKeyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
////        rsaPrivateKeyTemplate.getDerive().setBooleanValue(Boolean.FALSE);
//
////        rsaPrivateKeyTemplate.getKeyType().setPresent(false);
////        rsaPrivateKeyTemplate.getObjectClass().setPresent(false);

//        first check out what attributes of the keys we may set
        Mechanism keyPairGenerationMechanism = Mechanism.RSA_PKCS_KEY_PAIR_GEN;
        RSAPublicKey rsaPublicKeyTemplate = new RSAPublicKey();
        RSAPrivateKey rsaPrivateKeyTemplate = new RSAPrivateKey();

//        Set the general attributes for the public key
//        rsaPublicKeyTemplate.getModulusBits().setLongValue(1024L);
        rsaPublicKeyTemplate.getModulusBits().setLongValue((long) size);
        rsaPublicKeyTemplate.getPublicExponent().setByteArrayValue(publicExponentBytes);
        rsaPublicKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
        rsaPublicKeyTemplate.getId().setByteArrayValue(id);
        rsaPublicKeyTemplate.getLabel().setCharArrayValue(keyLabel.toCharArray());

        // set the general attributes for the private key
        rsaPrivateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getId().setByteArrayValue(id);
        rsaPrivateKeyTemplate.getLabel().setCharArrayValue(keyLabel.toCharArray());

        // set the attributes in a way netscape does, this should work with most tokens
        if (signatureMechanismInfo != null) {
            rsaPublicKeyTemplate.getVerify().setBooleanValue(signatureMechanismInfo.isVerify());
            rsaPublicKeyTemplate.getVerifyRecover().setBooleanValue(signatureMechanismInfo.isVerifyRecover());
            rsaPublicKeyTemplate.getEncrypt().setBooleanValue(signatureMechanismInfo.isEncrypt());
            rsaPublicKeyTemplate.getDerive().setBooleanValue(signatureMechanismInfo.isDerive());
            rsaPublicKeyTemplate.getWrap().setBooleanValue(signatureMechanismInfo.isWrap());

            rsaPrivateKeyTemplate.getSign().setBooleanValue(signatureMechanismInfo.isSign());
            rsaPrivateKeyTemplate.getSignRecover().setBooleanValue(signatureMechanismInfo.isSignRecover());
            rsaPrivateKeyTemplate.getDecrypt().setBooleanValue(signatureMechanismInfo.isDecrypt());
            rsaPrivateKeyTemplate.getDerive().setBooleanValue(signatureMechanismInfo.isDerive());
            rsaPrivateKeyTemplate.getUnwrap().setBooleanValue(signatureMechanismInfo.isUnwrap());
        } else {
            // if we have no information we assume these attributes
            rsaPrivateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
            rsaPrivateKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);

            rsaPublicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);
            rsaPublicKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
        }

        // netscape does not set these attribute, so we do no either
        rsaPublicKeyTemplate.getKeyType().setPresent(false);
        rsaPublicKeyTemplate.getObjectClass().setPresent(false);

        rsaPrivateKeyTemplate.getKeyType().setPresent(false);
        rsaPrivateKeyTemplate.getObjectClass().setPresent(false);
        return session.generateKeyPair(keyPairGenerationMechanism, rsaPublicKeyTemplate, rsaPrivateKeyTemplate);

//        Mechanism keyGenerationMechanism = Mechanism.get(0L);
//        RSAPrivateKey privateKeyTemplate = new RSAPrivateKey();
//        privateKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
//        privateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
//        privateKeyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
//        privateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
//        privateKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);
//        privateKeyTemplate.getLabel().setCharArrayValue(keyLabel.toCharArray());
//        privateKeyTemplate.getId().setByteArrayValue(id);
//        privateKeyTemplate.getModifiable().setBooleanValue(Boolean.TRUE);
//
//        RSAPublicKey publicKeyTemplate = new RSAPublicKey();
//        publicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);
//        publicKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
//        publicKeyTemplate.getWrap().setBooleanValue(Boolean.TRUE);
//        publicKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
//        publicKeyTemplate.getLabel().setCharArrayValue(keyLabel.toCharArray());
//        publicKeyTemplate.getId().setByteArrayValue(id);
//        publicKeyTemplate.getModifiable().setBooleanValue(Boolean.TRUE);
//        publicKeyTemplate.getPublicExponent().setByteArrayValue(publicExponent.toByteArray());
//        publicKeyTemplate.getModulusBits().setLongValue(Long.valueOf(size));
//
//        return session.generateKeyPair(keyGenerationMechanism, (Object) publicKeyTemplate, (Object) privateKeyTemplate);
    }

//    generate key pair ECDSA
    public KeyPair genECDSAKeyPair(String keyLabel, int Length, Session session) throws TokenException {
        ASN1ObjectIdentifier curveId;
        byte[] encodedCurveId;
        switch (Length) {
            case 384:
                curveId = new ASN1ObjectIdentifier("1.3.132.0.34");
                break;
            case 512:
                curveId = new ASN1ObjectIdentifier("1.3.36.3.3.2.8.1.1.13");
                break;
            case 521:
                curveId = new ASN1ObjectIdentifier("1.3.132.0.35");
                break;
            default:
                curveId = new ASN1ObjectIdentifier("1.2.840.10045.3.1.7");
                break;
        }
        Mechanism keyPairGenerationMechanism = Mechanism.get(4160L);
        ECDSAPublicKey ecdsaPublicKeyTemplate = new ECDSAPublicKey();
        ECDSAPrivateKey ecdsaPrivateKeyTemplate = new ECDSAPrivateKey();

        setKeyAttributes(keyLabel, keyLabel, 3L, ecdsaPublicKeyTemplate, ecdsaPrivateKeyTemplate);
        try {
            encodedCurveId = curveId.getEncoded();
        } catch (IOException ex) {
            throw new TokenException(ex.getMessage(), ex);
        }
        try {
            ecdsaPublicKeyTemplate.getEcdsaParams().setByteArrayValue(encodedCurveId);
            return session.generateKeyPair(keyPairGenerationMechanism, ecdsaPublicKeyTemplate, ecdsaPrivateKeyTemplate);
        } catch (TokenException ex) {
            X9ECParameters ecParams = ECNamedCurveTable.getByOID(curveId);
            if (ecParams == null) {
                throw new IllegalArgumentException("Could not get X9ECParameters for curve " + curveId
                        .getId());
            }
            try {
                ecdsaPublicKeyTemplate.getEcdsaParams().setByteArrayValue(ecParams.getEncoded());
            } catch (IOException ex2) {
                throw new TokenException(ex.getMessage(), ex);
            }
            return session.generateKeyPair(keyPairGenerationMechanism, (Object) ecdsaPublicKeyTemplate, (Object) ecdsaPrivateKeyTemplate);
        }
    }

//    Set Key Attributes
    private void setKeyAttributes(final String id, final String label, final long keyType,
                                  final PublicKey publicKey, final PrivateKey privateKey) {
        if (privateKey != null) {
            privateKey.getToken().setBooleanValue(Boolean.TRUE);
            privateKey.getId().setByteArrayValue(id.getBytes());
            privateKey.getLabel().setCharArrayValue(label.toCharArray());
            privateKey.getKeyType().setLongValue(keyType);
            privateKey.getSign().setBooleanValue(Boolean.TRUE);
            privateKey.getPrivate().setBooleanValue(Boolean.TRUE);
            privateKey.getSensitive().setBooleanValue(Boolean.TRUE);

            privateKey.getExtractable().setBooleanValue(Boolean.TRUE);
//            privateKey.getWrapWithTrusted().setBooleanValue(true);
            privateKey.getUnwrap().setBooleanValue(Boolean.TRUE);
            privateKey.getDerive().setBooleanValue(Boolean.FALSE);
//            privateKey.getAlwaysAuthenticate().setBooleanValue(true);
        }

        if (publicKey != null) {
            publicKey.getToken().setBooleanValue(Boolean.TRUE);
            publicKey.getId().setByteArrayValue(id.getBytes());
            publicKey.getLabel().setCharArrayValue(label.toCharArray());
            publicKey.getKeyType().setLongValue(keyType);
            publicKey.getVerify().setBooleanValue(Boolean.TRUE);
            publicKey.getModifiable().setBooleanValue(Boolean.TRUE);
        }
    }
//    Wrap Key
    public byte[] wrapKey(Key wrappingKey, Key key, Session session, Mechanism mechanism) throws TokenException {
        if ((wrappingKey == null) || (key == null)) {
            return null;
        }
        return session.wrapKey(mechanism, wrappingKey, key);
    }

//    UnWrap Key
    public Key unwrapKey(Key unwrappingKey, byte[] wrappedKey, Session session, Mechanism mechanism, Long keyType, String keyID, boolean isToken) throws TokenException {
        if ((wrappedKey == null) || (unwrappingKey == null)) {
            return null;
        }
            /*
            RSAPrivateKey rsaPrivateKeyTemplate = new RSAPrivateKey();
            rsaPrivateKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_PRIVATE_KEY);
            rsaPrivateKeyTemplate.getId().setByteArrayValue(keyID.getBytes());
            rsaPrivateKeyTemplate.getLabel().setCharArrayValue(keyID.toCharArray());
            rsaPrivateKeyTemplate.getKeyType().setLongValue(PKCS11Constants.CKK_RSA);

            rsaPrivateKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);
            rsaPrivateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
            rsaPrivateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
            rsaPrivateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);

            rsaPrivateKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
            rsaPrivateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
            rsaPrivateKeyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
            rsaPrivateKeyTemplate.getDerive().setBooleanValue(Boolean.FALSE);
            */
        RSAPrivateKey rsaPrivateKeyTemplate = new RSAPrivateKey();

        rsaPrivateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE); //diff
        rsaPrivateKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);

        rsaPrivateKeyTemplate.getId().setByteArrayValue(keyID.getBytes());
        rsaPrivateKeyTemplate.getLabel().setCharArrayValue(keyID.toCharArray());

        return session.unwrapKey(mechanism, unwrappingKey, wrappedKey, rsaPrivateKeyTemplate);
    }

//    Delete key
    public void deleteKey(Key key, Session session) throws TokenException {
        session.destroyObject(key);
    }

//    Create Signature
    public byte[] sign(long pkcs11MechanismCode, byte[] data, Key privateKey, Session session) throws TokenException {
        if (data == null || data.length == 0) {
            return null;
        }
        // be sure that your token can process the specified mechanism
        Mechanism encryptionMechanism = Mechanism.get(pkcs11MechanismCode);
        //encryptionMechanism.setParameters(PKCS11Constants.CKM_MD5_RSA_PKCS);
        // initialize for encryption
        session.signInit(encryptionMechanism, privateKey);
        return session.sign(data);
    }

//    Load DLL
    public void loadDll(String pkcs11Name, String wrapperName) throws TokenException, IOException {
        if (module != null) {
            return;
        }

//        logger.debug("Load PKCS11 library with params...");
//        logger.debug("PKCS11 lib path: " + pkcs11Name);
//        logger.debug("Wrapper lib path: " + wrapperName);

        System.out.println("Load PKCS11 library with params...");
        System.out.println("PKCS11 lib path: " + pkcs11Name);
        System.out.println("Wrapper lib path: " + wrapperName);

        module = Module.getInstance(pkcs11Name, wrapperName);
//        logger.debug("Pre initialize...");
        System.out.println("Pre initialize...");
        long start = System.currentTimeMillis();

        InitializeArgs agrs = new DefaultInitializeArgs();
        module.initialize(agrs);

//        logger.debug("Load PKCS11 Library finish, take: " + (System.currentTimeMillis() - start) + " ms");
        System.out.println("Load PKCS11 Library finish, take: " + (System.currentTimeMillis() - start) + " ms");
    }

//    Open Session
    public Session openSession(int slot) throws TokenException {
        if (slotToken == null) {
            connectToken(slot);
        }

        Token token = slotToken.getToken();

        if (token != null) {
            return token.openSession(Token.SessionType.SERIAL_SESSION, Token.SessionReadWriteBehavior.RW_SESSION, null, null);
        } else {
            throw new TokenException("Token is not present in the slot.");
        }
    }

//    Get Module
    public Module getModule(int slot) throws TokenException {
        if (slotToken == null) {
            connectToken(slot);
        }

        if (module != null) {
            return module;
        } else {
            throw new TokenException("Module is not present in the slot.");
        }
    }

//    Get Token
    public Token getToken(int slot) throws TokenException {
        if (slotToken == null) {
            connectToken(slot);
        }

        Token token = slotToken.getToken();

        if (token != null) {
            return token;
        } else {
            throw new TokenException("Token is not present in the slot.");
        }
    }

//    Connect Token -> get slot
    public void connectToken(int slot) throws TokenException {
        Slot[] slots = module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
        if (slots == null || slots.length == 0) {
            throw new TokenException("No token found!");
        }

        for (Slot slot2 : slots) {
            logger.debug("HSM slot id: " + slot2.getSlotID() + ".\n Info: " + slot2);
            if (slot2.getSlotID() == slot) {
                this.slotToken = slot2;
                return;
            }
        }
        throw new TokenException("Slot id not found...");
    }

//    Login
    public boolean login(Session session, String password) {
        long start = System.currentTimeMillis();
        try {
            session.login(Session.UserType.USER, password.toCharArray());
            logger.debug("Login HSM successful, take: " + (System.currentTimeMillis() - start) + " ms");

            return true;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return false;
    }

//    LogOUt
    public boolean logout(Session sess) {
        try {
            if (sess != null) {
                sess.logout();
                return true;
            }
        } catch (Exception var1) {
            var1.printStackTrace();

        }
        return false;
    }

//    Check label exist
    public boolean labelExists(final Session session,
                               final String keyLabel) throws TokenException {

        Key key = new Key();
        key.getLabel().setCharArrayValue(keyLabel.toCharArray());

        Object[] objects;
        try {
            session.findObjectsInit(key);
            objects = session.findObjects(1);
            session.findObjectsFinal();
            if (objects.length > 0) {
                return true;
            }

            X509PublicKeyCertificate cert = new X509PublicKeyCertificate();
            cert.getLabel().setCharArrayValue(keyLabel.toCharArray());

            session.findObjectsInit(cert);
            objects = session.findObjects(1);
            session.findObjectsFinal();
        } catch (TokenException ex) {
            throw new TokenException(ex.getMessage(), ex);
        }

        return objects.length > 0;
    }

//    Get ECDSA key by label
    public List<ECDSAPrivateKey> getPrivateECKeyByLabel(Session session, String keyLabel) throws TokenException {
        List<ECDSAPrivateKey> keys = new ArrayList<>();

        ECDSAPrivateKey e = new ECDSAPrivateKey();
        e.getLabel().setCharArrayValue(keyLabel.toCharArray());

        session.findObjectsInit(e);
        Object[] tempEccPrivateKey = session.findObjects(10);
        session.findObjectsFinal();

        if (tempEccPrivateKey != null) {
            for (Object object : tempEccPrivateKey) {
                keys.add((ECDSAPrivateKey) object);
            }
        }
        return keys;
    }

//    Get public ECDSA key by label
    public List<ECDSAPublicKey> getPublicECKeyByLabel(Session session, String keyLabel) throws TokenException {
        List<ECDSAPublicKey> keys = new ArrayList<>();

        ECDSAPublicKey e = new ECDSAPublicKey();
        e.getLabel().setCharArrayValue(keyLabel.toCharArray());

        session.findObjectsInit(e);
        Object[] tempEccPublicKey = session.findObjects(10);
        session.findObjectsFinal();

        if (tempEccPublicKey != null) {
            for (int i = 0; i < tempEccPublicKey.length; i++) {
                keys.add((ECDSAPublicKey) tempEccPublicKey[i]);
            }
        }
        return keys;
    }

//    Get RSA key by label
    public List<RSAPrivateKey> getPrivateRSAKeyByLabel(Session session, String keyLabel) throws TokenException {
        List<RSAPrivateKey> keys = new ArrayList<>();

        RSAPrivateKey rsaPrivateKey = new RSAPrivateKey();
        rsaPrivateKey.getLabel().setCharArrayValue(keyLabel.toCharArray());
        rsaPrivateKey.getToken().setBooleanValue(true);

        session.findObjectsInit(rsaPrivateKey);
        Object[] tempRSAPrivateKey = session.findObjects(10);

        if (tempRSAPrivateKey != null) {
            for (Object object : tempRSAPrivateKey) {
                keys.add((RSAPrivateKey) object);
            }
        }

        session.findObjectsFinal();
        return keys;
    }

//    Get public RSA key by label
    public List<RSAPublicKey> getPublicRSAKeyByLabel(Session session, String keyLabel) throws TokenException {
        List<RSAPublicKey> keys = new ArrayList<>();

        RSAPublicKey rsaPublicKey = new RSAPublicKey();
        rsaPublicKey.getLabel().setCharArrayValue(keyLabel.toCharArray());
        rsaPublicKey.getToken().setBooleanValue(true);

        session.findObjectsInit(rsaPublicKey);
        Object[] tempRSAPublicKey = session.findObjects(10);
        session.findObjectsFinal();

        if (tempRSAPublicKey != null) {
            for (Object object : tempRSAPublicKey) {
                keys.add((RSAPublicKey) object);
            }
        }
        return keys;
    }

//    Get AES key by label
    public List<AESSecretKey> getAESKeyByLabel(Session session, String keyLabel) throws TokenException {
        List<AESSecretKey> keys = new ArrayList<>();

        AESSecretKey e = new AESSecretKey();
        e.getLabel().setCharArrayValue(keyLabel.toCharArray());

        session.findObjectsInit(e);
        Object[] temp_rsaPrivateKey = session.findObjects(10);
        session.findObjectsFinal();

        if (temp_rsaPrivateKey != null) {
            for (Object object : temp_rsaPrivateKey) {
                keys.add((AESSecretKey) object);
            }
        }
        return keys;
    }

//    Find Primary Key Template
    public PrivateKey findPrivateKeyTemplate(String keyLabel, String keyType, Session session) throws TokenException {
        RSAPrivateKey rSAPrivateKey;
        ECDSAPrivateKey eCDSAPrivateKey;

        PrivateKey foundPrivateKey = null;
        if (keyLabel != null) {
            switch (keyType) {
                case "RSA":
                    rSAPrivateKey = new RSAPrivateKey();
                    rSAPrivateKey.getLabel().setCharArrayValue(keyLabel.toCharArray());
                    rSAPrivateKey.getToken().setBooleanValue(true);

                    try {
                        session.findObjectsInit(rSAPrivateKey);
                        Object[] arrayOfObject = session.findObjects(10);
                        if (arrayOfObject.length > 0) {
                            foundPrivateKey = (PrivateKey) arrayOfObject[0];
                        }
                    } finally {
                        session.findObjectsFinal();
                    }
                    break;
                case "ECDSA":
                    eCDSAPrivateKey = new ECDSAPrivateKey();

                    eCDSAPrivateKey.getLabel().setCharArrayValue(keyLabel.toCharArray());
                    eCDSAPrivateKey.getToken().setBooleanValue(true);

                    try {
                        session.findObjectsInit(eCDSAPrivateKey);
                        Object[] arrayOfObject = session.findObjects(10);
                        if (arrayOfObject.length > 0) {
                            foundPrivateKey = (PrivateKey) arrayOfObject[0];
                        }
                    } finally {
                        session.findObjectsFinal();
                    }
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported key type");
            }
        } else {
            System.out.println("Invalid input parameters - keyType is null");
        }

        session.closeSession();
        return foundPrivateKey;
    }

//    Find Public Key Template
    public PublicKey findPublicKeyTemplate(String keyLabel, String keyType, Session session) throws TokenException {
        ECDSAPublicKey eCDSAPublicKey;
        RSAPublicKey rSAPublicKey;

        PublicKey foundPublicKey = null;

        if (keyLabel != null) {
            switch (keyType) {
                case "RSA":
                    rSAPublicKey = new RSAPublicKey();
                    rSAPublicKey.getLabel().setCharArrayValue(keyLabel.toCharArray());
                    rSAPublicKey.getToken().setBooleanValue(true);

                    try {
                        session.findObjectsInit(rSAPublicKey);
                        Object[] arrayOfObject = session.findObjects(10);
                        if (arrayOfObject.length > 0) {
                            foundPublicKey = (PublicKey) arrayOfObject[0];
                        }
                    } finally {
                        session.findObjectsFinal();
                        session.closeSession();
                    }
                    break;

                case "ECDSA":
                    eCDSAPublicKey = new ECDSAPublicKey();

                    eCDSAPublicKey.getLabel().setCharArrayValue(keyLabel.toCharArray());
                    eCDSAPublicKey.getToken().setBooleanValue(true);

                    try {
                        session.findObjectsInit(eCDSAPublicKey);
                        Object[] arrayOfObject = session.findObjects(1);
                        if (arrayOfObject.length > 0) {
                            foundPublicKey = (PublicKey) arrayOfObject[0];
                        }
                    } finally {
                        session.findObjectsFinal();
                        session.closeSession();
                    }
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported key type");
            }
        } else {
            throw new IllegalArgumentException("Invalid input parameters");
        }

        return foundPublicKey;
    }

//    Find AES Key Template
    public AESSecretKey findAESKeyTemplate(String keyLabel, Session session) throws TokenException {
        AESSecretKey foundSecretKey = null;

        AESSecretKey secretKeyTemplate = new AESSecretKey();
        secretKeyTemplate.getLabel().setCharArrayValue(keyLabel.toCharArray());
        secretKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
//        secretKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
//        secretKeyTemplate.getModifiable().setBooleanValue(Boolean.FALSE);

        try {
            session.findObjectsInit(secretKeyTemplate);
            Object[] arrayOfObject = session.findObjects(1);

            if (arrayOfObject.length > 0) {
                foundSecretKey = (AESSecretKey) arrayOfObject[0];
            }
        } finally {
            if (session != null) {
                try {
                    session.findObjectsFinal();
                } finally {
                    session.closeSession();
                }
            }
        }

        return foundSecretKey;
    }

    private byte[] bigToByteArray(BigInteger x) {
        String hex = x.toString(16);
        if (hex.length() % 2 != 0) {
            hex = '0' + hex;
        }
        return DatatypeConverter.parseHexBinary(hex);
    }
}
