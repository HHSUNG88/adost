package sample;

/*

 * Copyright (c) 2018 SafeNet. All rights reserved.
 *
 * This file contains information that is proprietary to SafeNet and may not be
 * distributed or copied without written consent from SafeNet.
 */

import com.safenetinc.jcprov.CKR_Exception;
import com.safenetinc.jcprov.CK_ATTRIBUTE;
import com.safenetinc.jcprov.CK_BBOOL;
import com.safenetinc.jcprov.CK_C_INITIALIZE_ARGS;
import com.safenetinc.jcprov.CK_MECHANISM;
import com.safenetinc.jcprov.CK_OBJECT_HANDLE;
import com.safenetinc.jcprov.CK_SESSION_HANDLE;
import com.safenetinc.jcprov.Cryptoki;
import com.safenetinc.jcprov.CryptokiEx;
import com.safenetinc.jcprov.LongRef;
import com.safenetinc.jcprov.constants.CKA;
import com.safenetinc.jcprov.constants.CKF;
import com.safenetinc.jcprov.constants.CKK;
import com.safenetinc.jcprov.constants.CKM;
import com.safenetinc.jcprov.constants.CKO;
import com.safenetinc.jcprov.constants.CKR;
import com.safenetinc.jcprov.constants.CKU;
import com.safenetinc.jcprov.constants.CK_RV;
import com.safenetinc.jcprov.params.CK_EDDSA_PARAMS;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * This class demonstrates the usage of Edwards Elliptic Curve keys.
 * <p>
 * Usage : java EdwardsKeysSample [-slot &lt;slotId&gt;] [-password &lt;password&gt;]
 * <li><i>slotId</i>   slot containing the token to delete the key from -
 * default (1)
 * <li><i>password</i> user password of the slot. If specified, a private key
 * is used
 */
public class EdwardsKeysSample {

    boolean derivable = true;
    boolean extractable = true;
    CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
    CK_OBJECT_HANDLE hAESKey = new CK_OBJECT_HANDLE();
    CK_MECHANISM mechanism = new CK_MECHANISM(CKM.AES_KWP);;

    // Test data for sign/verify
    String startString = new String("0123456789ABCDEF");
    byte[] OrigPlainText = startString.getBytes();

    // Handles for generated keys
    static CK_OBJECT_HANDLE jcprov_Edwards_Pub = new CK_OBJECT_HANDLE ();
    static CK_OBJECT_HANDLE jcprov_Edwards_Priv = new CK_OBJECT_HANDLE ();
    static CK_OBJECT_HANDLE jcprov_Montgomery_Pub = new CK_OBJECT_HANDLE ();
    static CK_OBJECT_HANDLE jcprov_Montgomery_Priv = new CK_OBJECT_HANDLE ();

    // Curve identifiers.
    static byte[] oid_Ed25519 = {0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, (byte) 0xDA, 0x47, 0x0F, 0x01};
    static byte[] oid_Curve25519 = { 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, (byte) 0x97, 0x55, 0x01, 0x05, 0x01 };

    // Labels for templates
    static String label_EdwardsPublic = "Edwards ECC Public Key";
    static String label_EdwardsPrivate = "Edwards ECC Private Key";
    static String label_MontgomeryPublic = "Montgomery ECC Public Key";
    static String label_MontgomeryPrivate = "Montgomery ECC Private Key";

    // Templates
    static CK_ATTRIBUTE [] EdwardsPublic = {
        new CK_ATTRIBUTE (CKA.LABEL, label_EdwardsPublic.getBytes()),
        new CK_ATTRIBUTE (CKA.TOKEN, CK_BBOOL.TRUE),
        new CK_ATTRIBUTE (CKA.CLASS, CKO.PUBLIC_KEY),
        new CK_ATTRIBUTE (CKA.KEY_TYPE, CKK.EC_EDWARDS),
        new CK_ATTRIBUTE (CKA.PRIVATE, CK_BBOOL.FALSE),
        new CK_ATTRIBUTE (CKA.VERIFY, CK_BBOOL.TRUE),
        new CK_ATTRIBUTE (CKA.ECDSA_PARAMS, oid_Ed25519)
    };

    static CK_ATTRIBUTE [] EdwardsPrivate = {
        new CK_ATTRIBUTE (CKA.LABEL, label_EdwardsPrivate.getBytes()),
        new CK_ATTRIBUTE (CKA.TOKEN, CK_BBOOL.TRUE),
        new CK_ATTRIBUTE (CKA.CLASS, CKO.PRIVATE_KEY),
        new CK_ATTRIBUTE (CKA.KEY_TYPE, CKK.EC_EDWARDS),
        new CK_ATTRIBUTE (CKA.PRIVATE, CK_BBOOL.TRUE),
        new CK_ATTRIBUTE (CKA.SENSITIVE, CK_BBOOL.TRUE),
        new CK_ATTRIBUTE (CKA.SIGN, CK_BBOOL.TRUE)
    };

    static CK_ATTRIBUTE [] MontgomeryPublic = {
        new CK_ATTRIBUTE (CKA.LABEL, label_MontgomeryPublic.getBytes()),
        new CK_ATTRIBUTE (CKA.TOKEN, CK_BBOOL.TRUE),
        new CK_ATTRIBUTE (CKA.CLASS, CKO.PUBLIC_KEY),
        new CK_ATTRIBUTE (CKA.KEY_TYPE, CKK.EC_MONTGOMERY),
        new CK_ATTRIBUTE (CKA.PRIVATE, CK_BBOOL.FALSE),
        new CK_ATTRIBUTE (CKA.ECDSA_PARAMS, oid_Curve25519)
    };

    static CK_ATTRIBUTE [] MontgomeryPrivate = {
        new CK_ATTRIBUTE (CKA.LABEL, label_MontgomeryPrivate.getBytes()),
        new CK_ATTRIBUTE (CKA.TOKEN, CK_BBOOL.TRUE),
        new CK_ATTRIBUTE (CKA.CLASS, CKO.PRIVATE_KEY),
        new CK_ATTRIBUTE (CKA.KEY_TYPE, CKK.EC_MONTGOMERY),
        new CK_ATTRIBUTE (CKA.PRIVATE, CK_BBOOL.TRUE),
        new CK_ATTRIBUTE (CKA.SENSITIVE, CK_BBOOL.TRUE),
        new CK_ATTRIBUTE (CKA.DERIVE, CK_BBOOL.TRUE)
    };

    // easy access to System.out.println
    public static void println(String s) {
        System.out.println(s);
    }

    /**
     * main execution method
     */
    public static void main(String[] args) {
        EdwardsKeysSample sample = new EdwardsKeysSample();
        sample.Run(args);
    }

    /**
     * display runtime usage of the class
     */
    public void Usage() {
        println("java EdwardsKeysSample [-slot <slotId>] [-password <password>]");
        println("");
        println("<slotId>   slot containing the token with the key to use - " +
            "default (1)");
        println("<password> user password of the slot. If specified, a " +
            "private key is used.");
        println("");

        System.exit(1);
    }

    private void Run(String[] args)
    {
        long slotId = 1;
        String password = "";

        /*
         * process command line arguments
         */

        for (int i = 0; i < args.length; ++i) {
            if (args[i].equalsIgnoreCase("-slot")) {
                if (++i >= args.length) {
                    Usage();
                }

                slotId = Integer.parseInt(args[i]);
            } else if (args[i].equalsIgnoreCase("-password")) {
                if (++i >= args.length) {
                    Usage();
                }

                password = args[i];
            } else {
                Usage();
            }
        }

        try {
            /*
             * Initialize Cryptoki so that the library takes care
             * of multithread locking
             */
            CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(
                CKF.OS_LOCKING_OK));

            /*
             * Open a session
             */
            CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null,
                session);

            /*
             * Login - if we have a password
             */
            if (password.length() > 0) {
                CryptokiEx.C_Login(session, CKU.USER, password.getBytes(),
                    password.length());
            } else {
                Usage();
            }

            /*
            Begin!
             */

            CK_OBJECT_HANDLE hPrvImpKey = ImportPrivateEdwardsKey();
            assert(hPrvImpKey.isValidHandle());
            CK_OBJECT_HANDLE hPubImpKey = ImportPublicEdwardsKey();
            assert(hPubImpKey.isValidHandle());
            CK_RV rv = GenerateEdwardsKeypair();
            assert(CKR.OK == rv);
            rv = GenerateMontgomeryKeypair();
            assert(CKR.OK == rv);
            rv = SignVerify();
            assert(CKR.OK == rv);
            rv = SignVerifyPh();
            assert(CKR.OK == rv);

        } catch (CKR_Exception ex) {
            /*
             * A Cryptoki related exception was thrown
             */
            ex.printStackTrace();
        } catch (Exception ex) {
            ex.printStackTrace();
        } finally {
            /*
             * Logout in case we logged in.
             *
             * Note that we are not using CryptokiEx and we are not checking the
             * return value. This is because if we did not log in then an error
             * will be reported - and we don't really care because we are
             * shutting down.
             */
            Cryptoki.C_Logout(session);

            /*
             * Close the session.
             *
             * Note that we are not using CryptokiEx.
             */
            Cryptoki.C_CloseSession(session);

            /*
             * All done with Cryptoki
             *
             * Note that we are not using CryptokiEx.
             */
            Cryptoki.C_Finalize(null);
        }
    }

    private CK_OBJECT_HANDLE ImportPrivateEdwardsKey() {

        String katPrvKey = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42";
        byte[] privateKey = hexStringToByteArray(katPrvKey);
        LongRef lRefEnc = new LongRef();

        CryptokiEx.CA_EncodeEdwardsPrivateKey(oid_Ed25519, privateKey, null, lRefEnc);

        // Alloc required space for encoded key.
        byte[] encodedKey = new byte[(int) lRefEnc.value];

        CryptokiEx.CA_EncodeEdwardsPrivateKey(oid_Ed25519, privateKey, encodedKey, lRefEnc);

        /*
         Convert the template to an arraylist for simple manipulation.
         Next, update the two attributes we need (curve parameters and key bytes).
         Finally, convert back to an array for passing to corelibrary via jni.
         */
        List<CK_ATTRIBUTE> alNewKey = new ArrayList<>(Arrays.asList(EdwardsPrivate));
        alNewKey.add(new CK_ATTRIBUTE(CKA.EXTRACTABLE, extractable));
        alNewKey.add(new CK_ATTRIBUTE(CKA.DERIVE, derivable));
        CK_ATTRIBUTE[] newKeyTmpl = alNewKey.toArray(new CK_ATTRIBUTE[0]);

        return doUnwrapKey(encodedKey, newKeyTmpl);
    }

    private CK_OBJECT_HANDLE ImportPublicEdwardsKey() {
        String katPubKey = "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf";
        byte[] publicKey = hexStringToByteArray(katPubKey);
        LongRef lRefEnc = new LongRef();

        CryptokiEx.CA_EncodeEdwardsPublicKey(publicKey, null, lRefEnc);

        // Alloc required space for encoded key.
        byte[] encodedKey = new byte[(int) lRefEnc.value];

        CryptokiEx.CA_EncodeEdwardsPublicKey(publicKey, encodedKey, lRefEnc);

        /*
         Convert the template to an arraylist for simple manipulation.
         Next, update the two attributes we need (curve parameters and key bytes).
         Finally, convert back to an array for passing to corelibrary via jni.
         */
        List<CK_ATTRIBUTE> alNewKey = new ArrayList<>(Arrays.asList(EdwardsPublic));
        alNewKey.add(new CK_ATTRIBUTE(CKA.EC_POINT, encodedKey, encodedKey.length));
        CK_ATTRIBUTE[] newKeyTmpl = alNewKey.toArray(new CK_ATTRIBUTE[0]);

        return doCreateObject(newKeyTmpl);
    }

    private CK_RV GenerateEdwardsKeypair() {
        return CryptokiEx.C_GenerateKeyPair(session,
            new CK_MECHANISM(CKM.EC_EDWARDS_KEY_PAIR_GEN),
            EdwardsPublic, EdwardsPublic.length,
            EdwardsPrivate, EdwardsPrivate.length,
            jcprov_Edwards_Pub, jcprov_Edwards_Priv);
    }

    private CK_RV GenerateMontgomeryKeypair() {
        return CryptokiEx.C_GenerateKeyPair(session,
            new CK_MECHANISM(CKM.EC_MONTGOMERY_KEY_PAIR_GEN),
            MontgomeryPublic, MontgomeryPublic.length,
            MontgomeryPrivate, MontgomeryPrivate.length,
            jcprov_Montgomery_Pub, jcprov_Montgomery_Priv);
    }

    private CK_RV SignVerify() {
        CryptokiEx.C_GenerateKeyPair(session,
            new CK_MECHANISM(CKM.EC_EDWARDS_KEY_PAIR_GEN),
            EdwardsPublic, EdwardsPublic.length,
            EdwardsPrivate, EdwardsPrivate.length,
            jcprov_Edwards_Pub, jcprov_Edwards_Priv);

        LongRef lRefSign = new LongRef();
        byte [] signature = null;
        CK_MECHANISM mech = new CK_MECHANISM(CKM.EDDSA);

        CryptokiEx.C_SignInit(session, mech, jcprov_Edwards_Priv);
        CryptokiEx.C_SignUpdate(session, OrigPlainText, OrigPlainText.length);
        CryptokiEx.C_SignFinal(session, null, lRefSign);
        signature = new byte [(int)lRefSign.value];
        CryptokiEx.C_SignFinal(session, signature, lRefSign);

        CryptokiEx.C_VerifyInit(session, mech, jcprov_Edwards_Pub);
        CryptokiEx.C_VerifyUpdate(session, OrigPlainText, OrigPlainText.length);
        return CryptokiEx.C_VerifyFinal(session, signature, signature.length);
    }

    private CK_RV SignVerifyPh() {
        CryptokiEx.C_GenerateKeyPair(session,
            new CK_MECHANISM(CKM.EC_EDWARDS_KEY_PAIR_GEN),
            EdwardsPublic, EdwardsPublic.length,
            EdwardsPrivate, EdwardsPrivate.length,
            jcprov_Edwards_Pub, jcprov_Edwards_Priv);

        LongRef lRefSign = new LongRef();
        byte [] signature = null;
        CK_EDDSA_PARAMS eddsaParams = new CK_EDDSA_PARAMS(CK_BBOOL.TRUE);
        CK_MECHANISM mech = new CK_MECHANISM(CKM.EDDSA, eddsaParams);

        CryptokiEx.C_SignInit(session, mech, jcprov_Edwards_Priv);
        CryptokiEx.C_SignUpdate(session, OrigPlainText, OrigPlainText.length);
        CryptokiEx.C_SignFinal(session, null, lRefSign);
        signature = new byte [(int)lRefSign.value];
        CryptokiEx.C_SignFinal(session, signature, lRefSign);

        CryptokiEx.C_VerifyInit(session, mech, jcprov_Edwards_Pub);
        CryptokiEx.C_VerifyUpdate(session, OrigPlainText, OrigPlainText.length);
        return CryptokiEx.C_VerifyFinal(session, signature, signature.length);
    }

    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private void createWrappingKey() {
        CK_MECHANISM keyGenMech = new CK_MECHANISM(CKM.AES_KEY_GEN);

        // ****************************
        // Generate AES Encrypt/Unwrap key.

        String label = "AES Unwrap Key";

        CK_ATTRIBUTE[] template = {
            new CK_ATTRIBUTE(CKA.CLASS, CKO.SECRET_KEY)
            , new CK_ATTRIBUTE(CKA.TOKEN, CK_BBOOL.FALSE)
            , new CK_ATTRIBUTE(CKA.KEY_TYPE, CKK.AES)
            , new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.TRUE)
            , new CK_ATTRIBUTE(CKA.LABEL, label.getBytes())
            , new CK_ATTRIBUTE(CKA.PRIVATE, CK_BBOOL.TRUE)
            , new CK_ATTRIBUTE(CKA.ENCRYPT, CK_BBOOL.TRUE)
            , new CK_ATTRIBUTE(CKA.DECRYPT, CK_BBOOL.TRUE)
            , new CK_ATTRIBUTE(CKA.WRAP, CK_BBOOL.TRUE)
            , new CK_ATTRIBUTE(CKA.UNWRAP, CK_BBOOL.TRUE)
            , new CK_ATTRIBUTE(CKA.VALUE_LEN, 16)
        };

        CryptokiEx.C_GenerateKey(session, keyGenMech, template, template.length, hAESKey);
    }

    private CK_OBJECT_HANDLE doUnwrapKey(byte[] keyBytes, CK_ATTRIBUTE[] keyTemplate) {
        LongRef lRefEnc = new LongRef();

        createWrappingKey();

        // ****************************
        // Encrypt the key bytes.

        CryptokiEx.C_EncryptInit(session, mechanism, hAESKey);

        // Apparently, this mechanism has no need for calls to EncryptUpdate to fill in an output buffer...
        // but it also will not work without a call with a valid buffer. Will get:
        // C_EncryptFinal rv=0x21 - CKR_DATA_LEN_RANGE
        byte[] dummy = new byte[1];
        CryptokiEx.C_EncryptUpdate(session, mechanism, keyBytes, keyBytes.length, dummy,
            lRefEnc);

        // First call to get the required size of the output buffer.
        CryptokiEx.C_EncryptFinal(session, mechanism, null, lRefEnc);

        // Alloc required space for encrypted key.
        byte[] encKey = new byte[(int) lRefEnc.value];

        // Second call to populate the buffer.
        CryptokiEx.C_EncryptFinal(session, mechanism, encKey, lRefEnc);

        // ****************************
        // Unwrap the key.
        CK_OBJECT_HANDLE hKey = new CK_OBJECT_HANDLE();

        CryptokiEx.C_UnwrapKey(session, mechanism, hAESKey, encKey, encKey.length,
            keyTemplate, keyTemplate.length, hKey);

        return hKey;
    }

    private CK_OBJECT_HANDLE doCreateObject(CK_ATTRIBUTE[] keyTemplate) {
        CK_OBJECT_HANDLE hKey = new CK_OBJECT_HANDLE();
        CryptokiEx.C_CreateObject(session, keyTemplate, keyTemplate.length, hKey);
        return hKey;
    }

}
