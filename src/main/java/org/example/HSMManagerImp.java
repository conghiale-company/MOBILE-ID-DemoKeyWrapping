package org.example;

import iaik.pkcs.pkcs11.*;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.objects.*;
import iaik.pkcs.pkcs11.objects.Object;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import iaik.pkcs.pkcs11.parameters.RSAPkcsOaepParameters;
import iaik.pkcs.pkcs11.parameters.RSAPkcsParameters;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

public class HSMManagerImp {
    private boolean login;

    public HSMFunction hsmFunction;

    private String passsword;

    private Session sessionLogin;

    private int slotNumber;

    private static ReentrantLock lock = new ReentrantLock();

    private static volatile HSMManagerImp instance = null;

    public HSMManagerImp(String pkcs11LibName, String pkcs11Wrapper, int slot, String password) throws IOException, TokenException {
        hsmFunction = new HSMFunction();
        hsmFunction.loadDll(pkcs11LibName, pkcs11Wrapper);
        this.slotNumber = slot;

        this.login = false;

        this.passsword = password;
    }

    public static HSMManagerImp getInstance(String pkcs11LibName, String pkcs11Wrapper, int slot, String password) {
        lock.lock();
        try {
            instance = new HSMManagerImp(pkcs11LibName, pkcs11Wrapper, slot, password);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            lock.unlock();
        }
        return instance;
    }

    public enum KeyType {
        RSA, ECDSA, AES;
    }

//    generate key AES
    public AESSecretKey genAESSecretKey(String keyID, int size, boolean isToken) throws TokenException {
        if (!isLogin()) {
            loginHSM();
        }

        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            AESSecretKey response = hsmFunction.genAESKey(keyID, size, session, isToken, true);
            //not close session when crate AES-key
            session.closeSession();
            logoutHSM();
            return response;
        }
        return null;
    }

//    generate key pair
    public KeyPair genKeyPair(HSMFunction.KeyType keyType, int size, String KeyLabel) throws TokenException {
        if (null == keyType) {
            throw new IllegalArgumentException("Unknown key type: " + keyType);
        }
        switch (keyType) {
            case RSA:
                return GenerateRSAKeyPair(KeyLabel, size, 16);
            case ECDSA:
                return genECDSAKeyPair(size, KeyLabel);
        }
        throw new IllegalArgumentException("Unknown key type: " + keyType);
    }

//    Gen Key Pair EDCSA
    public KeyPair genECDSAKeyPair(int Lenght, String KeyLabel) throws TokenException {
        KeyPair keyPair = null;
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = this.hsmFunction.openSession(this.slotNumber);
            if (findPrivateKey(KeyLabel, "ECDSA") == null && findPublicKey(KeyLabel, "ECDSA") == null) {
                keyPair = this.hsmFunction.genECDSAKeyPair(KeyLabel, Lenght, session);
            } else {
                throw new IllegalArgumentException("Key name alredy exist");
            }
            session.closeSession();
        }
        return keyPair;
    }

//    generate key pair RSA
    public KeyPair GenerateRSAKeyPair(String keyLabel, int keyLength, int publicExponent) throws NumberFormatException, TokenException {
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            BigInteger exponent = BigInteger.valueOf(2L).shiftLeft(publicExponent - 1).add(BigInteger.ONE);
            if (publicExponent == 0) {
                exponent = null;
            }

            Session session = hsmFunction.openSession(slotNumber);

//            Token token = hsmFunction.getToken(slotNumber);
//            Module module = hsmFunction.getModule(slotNumber);

            Module module = session.getModule();
            Token token = session.getToken();

            HashSet supportedMechanisms = new HashSet(Arrays.asList(token.getMechanismList()));

            MechanismInfo signatureMechanismInfo;
            if (supportedMechanisms.contains(Mechanism.RSA_PKCS)) {
                signatureMechanismInfo = token.getMechanismInfo(Mechanism.RSA_PKCS);
            } else if (supportedMechanisms.contains(Mechanism.RSA_X_509)) {
                signatureMechanismInfo = token.getMechanismInfo(Mechanism.RSA_X_509);
            } else if (supportedMechanisms.contains(Mechanism.RSA_9796)) {
                signatureMechanismInfo = token.getMechanismInfo(Mechanism.RSA_9796);
            } else if (supportedMechanisms.contains(Mechanism.RSA_PKCS_OAEP)) {
                signatureMechanismInfo = token.getMechanismInfo(Mechanism.RSA_PKCS_OAEP);
            } else {
                signatureMechanismInfo = null;
            }

            KeyPair kp = hsmFunction.genRSAKeyPair(keyLabel, keyLength, exponent, session, signatureMechanismInfo, module);
            session.closeSession();
            return kp;
        } else {
            return null;
        }
    }

//    Find key AES
    public AESSecretKey findAESSecretKey(String keyLabel) throws TokenException {
        if (keyLabel == null || keyLabel.isEmpty()) {
            throw new IllegalArgumentException("Key label must not be null or empty");
        }
        if (!isLogin()) {
            loginHSM();
        }

        Session session = this.hsmFunction.openSession(slotNumber);

        return this.hsmFunction.findAESKeyTemplate(keyLabel, session);
    }

//    Find Public Key
    public PublicKey findPublicKey(String keyLabel, String keyType) throws TokenException {
        if (!isLogin()) {
            loginHSM();
        }

        Session session = this.hsmFunction.openSession(this.slotNumber);

        return hsmFunction.findPublicKeyTemplate(keyLabel, keyType, session);
    }

//    Find Public Key Template
    private PublicKey findPublicKeyTemplate(String keyLabel, String keyType) throws TokenException {
        ECDSAPublicKey eCDSAPublicKey;
        RSAPublicKey rSAPublicKey;
        if (!isLogin()) {
            loginHSM();
        }
        Session session = this.hsmFunction.openSession(this.slotNumber);
        PublicKey foundPublicKey = null;

        if (keyLabel != null) {
            switch (keyType) {
                case "RSA":
                    rSAPublicKey = new RSAPublicKey();
                    rSAPublicKey.getLabel().setCharArrayValue(keyLabel.toCharArray());
                    rSAPublicKey.getToken().setBooleanValue(true);

                    try {
                        session.findObjectsInit(rSAPublicKey);
                        Object[] arrayOfObject = session.findObjects(1);
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

//    Find Primary key
    public PrivateKey findPrivateKey(String keyLabel, String keyType) throws TokenException {
        if (!isLogin()) {
            loginHSM();
        }

        Session session = this.hsmFunction.openSession(this.slotNumber);

        return hsmFunction.findPrivateKeyTemplate(keyLabel, keyType, session);
    }

//    Find Primary Key Template
    private PrivateKey findPrivateKeyTemplate(String keyLabel, String keyType) throws TokenException {
        RSAPrivateKey rSAPrivateKey;
        ECDSAPrivateKey eCDSAPrivateKey;

        if (!isLogin()) {
            loginHSM();
        }

        Session session = this.hsmFunction.openSession(this.slotNumber);

        PrivateKey foundPrivateKey = null;
        if (keyLabel != null) {
            switch (keyType) {
                case "RSA":
                    rSAPrivateKey = new RSAPrivateKey();

                    rSAPrivateKey.getLabel().setCharArrayValue(keyLabel.toCharArray());
//                    rSAPrivateKey.getToken().setBooleanValue(true);
//                    rSAPrivateKey.getPrivate().setBooleanValue(true);
//                    rSAPrivateKey.getModifiable().setBooleanValue(true);
//                    rSAPrivateKey.getSign().setBooleanValue(Boolean.TRUE);
//                    rSAPrivateKey.getObjectClass().setLongValue(PKCS11Constants.CKO_PRIVATE_KEY);
//                    rSAPrivateKey.getKeyType().setLongValue(PKCS11Constants.CKK_RSA);
                    try {
                        session.findObjectsInit(rSAPrivateKey);
                        iaik.pkcs.pkcs11.objects.Object[] arrayOfObject = session.findObjects(10);
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
//                    eCDSAPrivateKey.getToken().setBooleanValue(true);
//                    eCDSAPrivateKey.getPrivate().setBooleanValue(true);
//                    eCDSAPrivateKey.getModifiable().setBooleanValue(true);
//                    eCDSAPrivateKey.getSign().setBooleanValue(Boolean.TRUE);
//                    eCDSAPrivateKey.getObjectClass().setLongValue(PKCS11Constants.CKO_PRIVATE_KEY);
//                    eCDSAPrivateKey.getKeyType().setLongValue(PKCS11Constants.CKK_EC);

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

//    Wrap key
    public byte[] wrapKey(Key wrappedKey, Key wrappingKey, long mode, byte[] iv) throws TokenException {
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            Mechanism mechanism = Mechanism.get(mode);

//            Mechanism mechanism = Mechanism.get(mode);
//            RSAPkcsOaepParameters rsaPkcsOaepParameters =
//                    new RSAPkcsOaepParameters(
//                            Mechanism.get(PKCS11Constants.CKM_SHA256),
//                            RSAPkcsParameters.MessageGenerationFunctionType.SHA256,
//                            RSAPkcsOaepParameters.SourceType.DATA_SPECIFIED,
//                            null);
//            mechanism.setParameters(rsaPkcsOaepParameters);

            if (iv != null) {
                mechanism.setParameters(new InitializationVectorParameters(iv));
            }
            byte[] rawKeyWrapped = hsmFunction.wrapKey(wrappingKey, wrappedKey, session, mechanism);
            session.closeSession();
            return rawKeyWrapped;
        } else {
            return null;
        }
    }

//    UnWrap Key
    public Key unWrapKey(byte[] secretKeyWrapped, Key wrappingKey, long mode, byte[] iv, Long keyType, String keyID, boolean isToken) throws TokenException {
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            Mechanism mechanism = Mechanism.get(mode);
            if (iv != null) {
                mechanism.setParameters(new InitializationVectorParameters(iv));
            }
            Key wrappedKey = hsmFunction.unwrapKey(wrappingKey, secretKeyWrapped, session, mechanism, keyType, keyID, isToken);
            session.closeSession();
            return wrappedKey;

        } else {
            return null;
        }
    }

//    Create Signature with PrivateKey
    public byte[] signWithPrivateKey(long pkcs11MechanismCode, byte[] plaintext, Key privateKey)
            throws TokenException {
        // TODO Auto-generated method stub
        if (!isLogin()) {

            loginHSM();
        }
        if (isLogin()) {

            Session session = hsmFunction.openSession(slotNumber);

            if (privateKey == null) {
                session.closeSession();
                return null;
            }

            byte[] signed = hsmFunction.sign(pkcs11MechanismCode, plaintext, privateKey, session);

            session.closeSession();
            return signed;
        }
        return null;
    }

//    Delete Key
    public boolean deleteKey(Key key) throws TokenException {
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            hsmFunction.deleteKey(key, session);
            session.closeSession();
            return true;
        } else {
            return false;
        }
    }

//    Check label exists
    public boolean labelExists(String keyLabel) throws TokenException {
        boolean isExisted = false;
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            isExisted = hsmFunction.labelExists(session, keyLabel);
            session.closeSession();
            return isExisted;
        }
        return isExisted;
    }

//    Get ECDSA key by label
    public List<ECDSAPrivateKey> getPrivateECKeyByLabel(String keyLabel) throws Exception {
        // TODO Auto-generated method stub
        List<ECDSAPrivateKey> keys;
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            keys = hsmFunction.getPrivateECKeyByLabel(session, keyLabel);
            session.closeSession();
        } else {
            throw new Exception("Cannot login to HSM");
        }
        return keys;
    }

//    Get public ECDSA key by label
    public List<ECDSAPublicKey> getPublicECKeyByLabel(String keyLabel) throws Exception {
        // TODO Auto-generated method stub
        List<ECDSAPublicKey> keys;
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            keys = hsmFunction.getPublicECKeyByLabel(session, keyLabel);
            session.closeSession();
        } else {
            throw new Exception("Cannot login to HSM");
        }
        return keys;
    }

//    Get RSA key by label
    public List<RSAPrivateKey> getPrivateRSAKeyByLabel(String keyLabel) throws Exception {
        // TODO Auto-generated method stub
        List<RSAPrivateKey> keys;
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            keys = hsmFunction.getPrivateRSAKeyByLabel(session, keyLabel);
            session.closeSession();
        } else {
            throw new Exception("Cannot login to HSM");
        }
        return keys;
    }

//    Get public RSA key by label
    public List<RSAPublicKey> getPublicRSAKeyByLabel(String keyLabel) throws Exception {
        // TODO Auto-generated method stub
        List<RSAPublicKey> keys;
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            keys = hsmFunction.getPublicRSAKeyByLabel(session, keyLabel);
            session.closeSession();
        } else {
            throw new Exception("Cannot login to HSM");
        }
        return keys;
    }

//    Get ECDSA key by label
    public List<AESSecretKey> getAESKeyByLabel(String keyLabel) throws Exception {
        // TODO Auto-generated method stub
        List<AESSecretKey> keys;
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            keys = hsmFunction.getAESKeyByLabel(session, keyLabel);
            session.closeSession();
        } else {
            throw new Exception("Cannot login to HSM");
        }
        return keys;
    }

//    Log in
    public boolean loginHSM() throws TokenException {
        // TODO Auto-generated method stub
        if (isLogin()) {
            return true;
        }

        lock.lock();
        if (isLogin()) {
            lock.unlock();
            return true;
        }

        try {
            sessionLogin = hsmFunction.openSession(slotNumber);
            login = hsmFunction.login(sessionLogin, passsword);
        } catch (Exception e) {
            // TODO: handle exception
            e.printStackTrace();
            throw e;
        } finally {
            lock.unlock();
        }
        return login;
    }

//    Check Login
    private boolean isLogin() {
        return login;
    }

//    LogOut HSM
    public boolean logoutHSM() throws TokenException {
        // TODO Auto-generated method stub
        boolean status1 = hsmFunction.logout(sessionLogin);
        if (status1) {
            login = false;
            sessionLogin.closeSession();
            return true;
        } else {
            return false;
        }
    }
}
