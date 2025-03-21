package sample;

import java.util.Arrays;
import java.util.Random;

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
import com.safenetinc.jcprov.constants.CKU;

/**
 * This class demonstrates the wrap/unwrap operations using the UNWRAP_TEMPLATE attribute.
 * <p>
 * Operations: Generate RSA keypair where the RSA private key has the UNWRAP_TEMPLATE attribute.
 *             Generate AES key.
 *             Encrypt AES key with plain text.
 *             Wrap this AES key with RSA public key.
 *             Unwrap wrapped AES key above with RSA private key (External template used in this operation).
 *             Decrypt unwrapped AES key.
 *             Verify the original plainText and decrypted string are matched.
 * <p>
 * Usage : java UnwrapTempltAttrib -slot &lt;slotId&gt; -password &lt;password&gt;
 *
 * <li><i>slotId</i>   slot containing the token.
 * <li><i>password</i> user password of the slot.
 */
public class UnwrapTempltAttrib
{
    // IV
    private static byte[] iv = null;

    private static byte[] StringBytes = null;

    private static long bufSize;

    private static CK_OBJECT_HANDLE hPublicKey = new CK_OBJECT_HANDLE();
    private static CK_OBJECT_HANDLE hPrivateKey = new CK_OBJECT_HANDLE();
    private static CK_OBJECT_HANDLE hAESKey = new CK_OBJECT_HANDLE();
    private static CK_OBJECT_HANDLE hUnwrappedKey = new CK_OBJECT_HANDLE();

    /** display runtime usage of the class */
    public static void usage()
    {
        System.out.println("java UnwrapTempltAttrib...-slot <slotId> -password <password>");
        System.out.println("");
        System.out.println("<slotId>   slot containing the token to create the key on");
        System.out.println("<password> user password of the slot.");
        System.out.println("");

        System.exit(1);
    }

    // Unwrap template used by UNWRAP_TEMPLATE attribute.
    static String templatekeyName = "special";

    static CK_ATTRIBUTE[] unWrapTemplate =
    {
        new CK_ATTRIBUTE(CKA.CLASS,     CKO.SECRET_KEY),
        new CK_ATTRIBUTE(CKA.KEY_TYPE,  CKK.AES),
        new CK_ATTRIBUTE(CKA.TOKEN,     CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.PRIVATE,   CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.ENCRYPT,   CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.DECRYPT,   CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.LABEL,     templatekeyName.getBytes())
    };

    // External template used by unwrap operation.
    static String externalTemplateName = "special";

    static CK_ATTRIBUTE[] externalTemplate =
    {
        new CK_ATTRIBUTE(CKA.CLASS,     CKO.SECRET_KEY),
        new CK_ATTRIBUTE(CKA.KEY_TYPE,  CKK.AES),
        new CK_ATTRIBUTE(CKA.TOKEN,     CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.PRIVATE,   CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.ENCRYPT,   CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.DECRYPT,   CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.LABEL,    	externalTemplateName.getBytes())
    };

    // RSA public template
    static Byte pubExponent = 03;
    static long modulusBits = 1024L;

    static String RSAPubkeyName = "RSA Public";
    static CK_ATTRIBUTE[] publicTemplate =
    {
        new CK_ATTRIBUTE(CKA.CLASS, CKO.PUBLIC_KEY),
        new CK_ATTRIBUTE(CKA.TOKEN, CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.KEY_TYPE, CKK.RSA),
        new CK_ATTRIBUTE(CKA.LABEL, RSAPubkeyName.getBytes()),
        new CK_ATTRIBUTE(CKA.MODULUS_BITS, modulusBits),
        new CK_ATTRIBUTE(CKA.PUBLIC_EXPONENT, pubExponent),
        new CK_ATTRIBUTE(CKA.ENCRYPT, CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.WRAP, CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.DERIVE, CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.VERIFY, CK_BBOOL.TRUE)
    };

    // RSA private template
    static String RSAPrivkeyName = "RSA Private";
    static CK_ATTRIBUTE[] privateTemplate =
    {
        new CK_ATTRIBUTE(CKA.CLASS,     CKO.PRIVATE_KEY),
        new CK_ATTRIBUTE(CKA.TOKEN,     CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.KEY_TYPE,  CKK.RSA),
        new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.LABEL,     RSAPrivkeyName.getBytes()),
        new CK_ATTRIBUTE(CKA.PRIVATE,   CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.DECRYPT,   CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.DERIVE,    CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.UNWRAP,    CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.SIGN,      CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.UNWRAP_TEMPLATE, unWrapTemplate, unWrapTemplate.length )

    };

    // AES template
    static String AESkeyName = "AES";
    static CK_ATTRIBUTE[] AEStemplate =
    {
        new CK_ATTRIBUTE(CKA.CLASS,     CKO.SECRET_KEY),
        new CK_ATTRIBUTE(CKA.TOKEN,     CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.KEY_TYPE,  CKK.AES),
        new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.LABEL,     AESkeyName.getBytes()),
        new CK_ATTRIBUTE(CKA.PRIVATE,   CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.ENCRYPT,   CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.DECRYPT,   CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.VALUE_LEN, 16),
    };

    /** main execution method */
    public static void main(String[] args)
    {
        CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
        long slotId = 0;
        String keyType = "";
        String password = "";

        if(args.length == 0)
            usage();

        // Process command line arguments
        for (int i = 0; i < args.length; ++i)
        {
            // Check for slot
            if(args[i].equalsIgnoreCase("-slot"))
            {
                if (++i >= args.length)
                    usage();

                slotId = Integer.parseInt(args[i]);
            }
            // Check for password
            else if (args[i].equalsIgnoreCase("-password"))
            {
                if (++i >= args.length)
                    usage();

                password = args[i];
            }
            else
            {
                usage();
            }
        }

        // Values to receive the required buffer sizes in the coming operations.
        // Outside the try .. catch so that the values may be examined within an exception.
        LongRef lRefEnc = new LongRef();
        LongRef lRefDec = new LongRef();
        LongRef lWrapkey = new LongRef();

        try
        {
            // Initialize Cryptoki library
            CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(
                        CKF.OS_LOCKING_OK));

            // Open a session
            CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null,
                    session);

            // Login
            CryptokiEx.C_Login(session, CKU.USER, password.getBytes(),
                                   password.length());

            System.out.println("\n---------------------------------------------------------------------------------");

            // Setup and generate RSA keypair
            CK_MECHANISM     RSAkeyGenMech = new CK_MECHANISM(CKM.RSA_PKCS_KEY_PAIR_GEN);

            CryptokiEx.C_GenerateKeyPair(session, RSAkeyGenMech,
                                         publicTemplate, publicTemplate.length,
                                         privateTemplate, privateTemplate.length,
                                         hPublicKey, hPrivateKey);

            System.out.println("RSA key pair generated. Handles: public(" + hPublicKey.longValue() +") private(" + hPrivateKey.longValue() + ")");

            // Setup and generate symmetric AES key
            CK_MECHANISM     AESkeyGenMech = new CK_MECHANISM(CKM.AES_KEY_GEN);

            CryptokiEx.C_GenerateKey(session, AESkeyGenMech, AEStemplate, AEStemplate.length, hAESKey);

            System.out.println("AES key generated - handle (" + hAESKey.longValue() + ")");

            // *******************************************
            //   Encrypt the AES key with the plain text
            // *******************************************

            System.out.println("Encrypt the AES key with the plain text - handle (" + hAESKey.longValue() + ")");

            // Generate random IV and setup IV params,
            Random r = new Random();
            iv = new byte[8];
            r.nextBytes(iv);

            // Setup mechanism.
            CK_MECHANISM mechanism = new CK_MECHANISM(CKM.AES_KW, iv);

            // Create buffer size 63K approx.
            long bufSize = (1024*63);

            // Create plaintext with that buffer size.
            char[] fillBytes = new char[(int)bufSize];
            // Fill chars
            Arrays.fill(fillBytes, 'a');
            String plainText = new String(fillBytes);
            // Convert to bytes to be encrypted.
            StringBytes = plainText.getBytes();

            System.out.println("Plaintext is setup with size: " + StringBytes.length + " bytes");


            /* get ready to encrypt this AES key*/
            CryptokiEx.C_EncryptInit(session, mechanism, hAESKey);

            // Observe that, AES_KW does not return the encrypted size, nor the data, in the call(s) to C_EncryptUpdate.
            // The HSM accumulates all data until C_EncryptFinal is called, whereby the same PKCS approach may be employed:
            // first call with a null buffer to get the size, then allocate the buffer and call again to receive the
            // encrypted data.

            CryptokiEx.C_EncryptUpdate(session, mechanism, StringBytes, StringBytes.length, null, lRefEnc);

            // First call to get the required size of the output buffer.
            CryptokiEx.C_EncryptFinal(session, mechanism, null, lRefEnc);

            /* allocate space */
            byte[] aesencrypted = new byte[(int)lRefEnc.value];

            // Second call to populate the buffer.
            CryptokiEx.C_EncryptFinal(session, mechanism, aesencrypted, lRefEnc);

            // ***********************************
            //   Wrap AES key with RSA public key
            // ***********************************

            System.out.println("Wrap AES key with RSA public key: public handle (" + hPublicKey.longValue() +") AES handle(" + hAESKey.longValue() + ")");

            CK_MECHANISM mech = new CK_MECHANISM(CKM.RSA_PKCS);
            byte [] wrappedKey = null;

            CryptokiEx.C_WrapKey(session, mech, hPublicKey, hAESKey, null, lWrapkey);

            wrappedKey = new byte [(int)lWrapkey.value];

            CryptokiEx.C_WrapKey(session, mech, hPublicKey, hAESKey, wrappedKey, lWrapkey);

            // *********************************************
            //   Unwrap wrapped AES key with RSA private key
            // *********************************************

            CryptokiEx.C_UnwrapKey(session, mech, hPrivateKey, wrappedKey, wrappedKey.length,
                                  externalTemplate, externalTemplate.length, hUnwrappedKey);

            System.out.println("Unwrap wrapped AES key with RSA private key: private handle (" +
                               hPrivateKey.longValue() +") - Unwrapped AES handle (" +
                               hUnwrappedKey.longValue() + ")");

            // ****************************
            //   Decrypt the unwrapped key.
            // ****************************

            /* get ready to decrypt this unwrapped key*/
            CryptokiEx.C_DecryptInit(session, mechanism, hUnwrappedKey);

            // Observe that, AES_KW does not return the decrypted size, nor the data, in the call(s) to C_DecryptUpdate.
            // The HSM accumulates all data until C_DecryptFinal is called, whereby the same PKCS approach may be employed:
            // first call with a null buffer to get the size, then allocate the buffer and call again to receive the
            // decrypted data.

            CryptokiEx.C_DecryptUpdate(session, mechanism, aesencrypted, lRefEnc.value, null, lRefDec);

            // First call to get the required size of the output buffer.
            CryptokiEx.C_DecryptFinal(session, mechanism, null, lRefDec);

            /* allocate space */
            byte[] aesdecrypted = new byte[(int)(lRefDec.value)];

            // Second call to populate the buffer.
            CryptokiEx.C_DecryptFinal(session, mechanism, aesdecrypted, lRefDec);

            // ******************************************************************
            //   Verify the original plainText and decrypted string are matched.
            // *******************************************************************

            String decryptedString = new String(aesdecrypted, 0, (int)lRefDec.value);

            if (plainText.compareTo(decryptedString) == 0)
            {
                System.out.println("Decrypted string matches original string - Decryption was successful\n");
            }
            else
            {
                System.out.println("*** Decrypted string does not match original string - Decryption failed ***\n");
            }

            System.out.println("\n---------------------------------------------------------------------------------");
        }
        catch (CKR_Exception ex)
        {
            /*
             * A Cryptoki related exception was thrown
             */
            ex.printStackTrace();
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
        finally
        {
            Cleanup(session);
        }
    }

    // ********************************************
    // Clean up.
    // ********************************************
    private static void Cleanup(CK_SESSION_HANDLE session)
    {
        // Destroy objects
        CryptokiEx.C_DestroyObject(session, hPublicKey);
        CryptokiEx.C_DestroyObject(session, hPrivateKey);
        CryptokiEx.C_DestroyObject(session, hAESKey);
        CryptokiEx.C_DestroyObject(session, hUnwrappedKey);

        // Logout
        Cryptoki.C_Logout(session);
        // Close the session.
        Cryptoki.C_CloseSession(session);
        // All done with Cryptoki
        Cryptoki.C_Finalize(null);
    }

}
