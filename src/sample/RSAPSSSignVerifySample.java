package sample;

/*
 * Copyright (c) 2020 SafeNet. All rights reserved.
 *
 * This file contains information that is proprietary to SafeNet and may not be
 * distributed or copied without written consent from SafeNet.
 */

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

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
import com.safenetinc.jcprov.constants.CKG;
import com.safenetinc.jcprov.constants.CKM;
import com.safenetinc.jcprov.constants.CKR;
import com.safenetinc.jcprov.constants.CKU;
import com.safenetinc.jcprov.constants.CK_RV;
import com.safenetinc.jcprov.params.CK_RSA_PKCS_PSS_PARAMS;

/**
 * This class demonstrates the usage of the RSA PSS sign mechanism.
 * <p>
 * Usage : java RSAPSSSignVerifySample [-slot &lt;slotId&gt;] [-password &lt;password&gt;]
 * <li><i>slotId</i>   slot containing the token to delete the key from -
 * default (1)
 * <li><i>password</i> user password of the slot. If specified, a private key
 * is used
 */
public class RSAPSSSignVerifySample {

    boolean derivable = true;
    boolean extractable = true;
    CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
    CK_OBJECT_HANDLE hAESKey = new CK_OBJECT_HANDLE();
    CK_MECHANISM mechanism = new CK_MECHANISM(CKM.AES_KWP);
    byte[] pubExponent = {0x01, 0x00, 0x01};
    long ll = 2048L;
    Long modulusBits = new Long(ll);

    // Test data for sign/verify
    String startString = new String("0123456789ABCDEF");
    byte[] OrigPlainText = startString.getBytes();

    // Handles for generated keys
    static CK_OBJECT_HANDLE jcprov_Pub = new CK_OBJECT_HANDLE ();
    static CK_OBJECT_HANDLE jcprov_Priv = new CK_OBJECT_HANDLE ();


    // Labels for templates
    static String label_Public = "RSA Public Key";
    static String label_Private = "RSA Private Key";

    // Templates
    CK_ATTRIBUTE[] publicTemplate =
    {
      new CK_ATTRIBUTE(CKA.LABEL,         label_Public.getBytes()),
      new CK_ATTRIBUTE(CKA.TOKEN,         CK_BBOOL.FALSE),
      new CK_ATTRIBUTE(CKA.VERIFY,        CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.ENCRYPT,       CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.WRAP,          CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.MODIFIABLE,    CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.MODULUS_BITS,    modulusBits),
      new CK_ATTRIBUTE(CKA.PUBLIC_EXPONENT,   pubExponent),
    };

    CK_ATTRIBUTE[] privateTemplate =
    {
      new CK_ATTRIBUTE(CKA.PRIVATE,      new CK_BBOOL(true)),
      new CK_ATTRIBUTE(CKA.LABEL,         label_Private.getBytes()),
      new CK_ATTRIBUTE(CKA.TOKEN,         CK_BBOOL.FALSE),
      new CK_ATTRIBUTE(CKA.SENSITIVE,     CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.SIGN,          CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.DECRYPT,       CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.UNWRAP,        CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.MODIFIABLE,    CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.EXTRACTABLE,   CK_BBOOL.TRUE),
    };
    // easy access to System.out.println
    public static void println(String s) {
        System.out.println(s);
    }

    /**
     * main execution method
     */
    public static void main(String[] args) {
        RSAPSSSignVerifySample sample = new RSAPSSSignVerifySample();
        sample.Run(args);
    }

    /**
     * display runtime usage of the class
     */
    public void Usage() {
        println("java RSAPSSSignVerifySample [-slot <slotId>] [-password <password>]");
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

            CK_RV rv = GenerateRSAKeypair();
            assert(CKR.OK == rv);

            rv = SignVerify();
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

    private CK_RV GenerateRSAKeypair() {
        return CryptokiEx.C_GenerateKeyPair(session,
            new CK_MECHANISM(CKM.RSA_PKCS_KEY_PAIR_GEN),
            publicTemplate, publicTemplate.length,
            privateTemplate, privateTemplate.length,
            jcprov_Pub, jcprov_Priv);
    }

    private CK_RV SignVerify() {
        LongRef lRefSign = new LongRef();
        byte [] signature = null;
//        CK_RSA_PKCS_PSS_PARAMS RSAPSSParams = new CK_RSA_PKCS_PSS_PARAMS(CKM.SHA_1,CKG.MGF1_SHA1,20L);
        CK_RSA_PKCS_PSS_PARAMS RSAPSSParams = new CK_RSA_PKCS_PSS_PARAMS(CKM.SHA3_256,CKG.MGF1_SHA3_256,20L);
        //CK_RSA_PKCS_PSS_PARAMS RSAPSSParams = new CK_RSA_PKCS_PSS_PARAMS(CKM.SHA_256,CKG.MGF1_SHA256,32L);
//        CK_MECHANISM mech = new CK_MECHANISM(CKM.RSA_PKCS_PSS, RSAPSSParams);
        CK_MECHANISM mech = new CK_MECHANISM(CKM.SHA3_256_RSA_PKCS_PSS, RSAPSSParams);
//        CK_MECHANISM mech = new CK_MECHANISM(CKM.SHA3_256_RSA_PKCS, null);

        CryptokiEx.C_SignInit(session, mech, jcprov_Priv);
        CryptokiEx.C_SignUpdate(session, OrigPlainText, OrigPlainText.length);
        CryptokiEx.C_SignFinal(session, null, lRefSign);
        signature = new byte [(int)lRefSign.value];
        CryptokiEx.C_SignFinal(session, signature, lRefSign);

        CryptokiEx.C_VerifyInit(session, mech, jcprov_Pub);
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
}
