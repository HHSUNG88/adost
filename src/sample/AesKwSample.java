
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
 * This class demonstrates the encryption/decryption and wrap/unwrap operations with IV using the 38F AES KW mechanism.
 * <p>
 * Usage : java AesKwSample [-slot &lt;slotId&gt;] [-password &lt;password&gt;]
 *
 * <li><i>slotId</i>   slot containing the token.
 * <li><i>password</i> user password of the slot.
 */
public class AesKwSample
{
    static public void println(String s)
    {
        System.out.print(s);
    }

    /** display runtime usage of the class */
    public static void usage()
    {
        println("java ...AesKwSample -slot <slotId> -password <password>\n");
        println("");

        System.exit(1);
    }

    // IV
    private static byte[] iv = null;

    // Symmetric template.
    private static String keyLabel = "AesKey";

    private static CK_ATTRIBUTE[] template =
    {
       new CK_ATTRIBUTE(CKA.CLASS,       CKO.SECRET_KEY),
       new CK_ATTRIBUTE(CKA.TOKEN,       CK_BBOOL.TRUE),
       new CK_ATTRIBUTE(CKA.CLASS,       CKO.SECRET_KEY),
       new CK_ATTRIBUTE(CKA.KEY_TYPE,    CKK.AES),
       new CK_ATTRIBUTE(CKA.SENSITIVE,   CK_BBOOL.TRUE),
       new CK_ATTRIBUTE(CKA.LABEL,       keyLabel.getBytes()),
       new CK_ATTRIBUTE(CKA.PRIVATE,     new CK_BBOOL(true)),
       new CK_ATTRIBUTE(CKA.ENCRYPT,     CK_BBOOL.TRUE),
       new CK_ATTRIBUTE(CKA.DECRYPT,     CK_BBOOL.TRUE),
       new CK_ATTRIBUTE(CKA.DERIVE,      CK_BBOOL.TRUE),
       new CK_ATTRIBUTE(CKA.WRAP, 	     CK_BBOOL.TRUE),
       new CK_ATTRIBUTE(CKA.UNWRAP,      CK_BBOOL.TRUE),
       new CK_ATTRIBUTE(CKA.EXTRACTABLE, CK_BBOOL.TRUE),
       new CK_ATTRIBUTE(CKA.VALUE_LEN, 16)
    };

    /** main execution method */
    public static void main(String[] args)
    {
        CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
        long slotId = 0;
        String keyType = "";
        String password = "";
        boolean bPrivate = false;

        /*
         * process command line arguments
         */

        for (int i = 0; i < args.length; ++i)
        {

            if(args[i].equalsIgnoreCase("-slot"))
            {
                if (++i >= args.length)
                    usage();

                slotId = Integer.parseInt(args[i]);
            }
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
            /*
             * Initialize Cryptoki so that the library takes care
             * of multithread locking
             */
            //specify null as the threading locking policy argument
            CryptokiEx.C_Initialize(null);
            //OR...explicitly specify a threading locking policy
            //CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));

            /*
             * Open a session
             */
            CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null,
                    session);

            /*
             * Login - if we have a password
             */
            if (password.length() > 0)
            {
                CryptokiEx.C_Login(session, CKU.USER, password.getBytes(),
                        password.length());

                bPrivate = true;
            }

            // Generate random IV and setup IV params,
            Random r = new Random();
            //iv = new byte[8];//AES_KW
            iv = new byte[4];//AES_KWP
            r.nextBytes(iv);

            // Setup mechanism.
            //CK_MECHANISM mechanism = new CK_MECHANISM(CKM.AES_KW, iv);
            CK_MECHANISM mechanism = new CK_MECHANISM(CKM.AES_KWP, iv);

            CK_OBJECT_HANDLE hKeyToBeWrap = new CK_OBJECT_HANDLE();
            CK_OBJECT_HANDLE hWrappingKey = new CK_OBJECT_HANDLE();

            // Generate AES keys.
            CK_MECHANISM keyGenMech = new CK_MECHANISM(CKM.AES_KEY_GEN);
            CryptokiEx.C_GenerateKey(session, keyGenMech, template, template.length, hKeyToBeWrap);
            CryptokiEx.C_GenerateKey(session, keyGenMech, template, template.length, hWrappingKey);

            // ***********************
            //   ENCRYPTION
            // ***********************

            // Create buffer size 63K approx.
            long bufSize = (1024*63);

            // Create plaintext with that buffer size.
            char[] fillBytes = new char[(int)bufSize];
            // Fill chars
            Arrays.fill(fillBytes, 'a');
            String ByteString = new String(fillBytes);

            byte[] plainText = ByteString.getBytes();

            System.out.println("\n---------------------------------------------------------------------------------");

            System.out.println("Plaintext is setup with size: " + plainText.length + " bytes");

            /* get ready to encrypt */
            CryptokiEx.C_EncryptInit(session, mechanism, hKeyToBeWrap);

            // For multi part, use C_EncryptUpdate and C_EncryptFinal.

            // Observe that, AES_KW does not return the encrypted size, nor the data, in the call(s) to C_EncryptUpdate.
            // The HSM accumulates all data until C_EncryptFinal is called, whereby the same PKCS approach may be employed:
            // first call with a null buffer to get the size, then allocate the buffer and call again to receive the
            // encrypted data.

            CryptokiEx.C_EncryptUpdate(session, mechanism, plainText, plainText.length, null, lRefEnc);

            byte[] cipherTextPart1 = new byte[plainText.length];

            CryptokiEx.C_EncryptUpdate(session, mechanism, plainText, plainText.length, cipherTextPart1,
                lRefEnc);

            // First call to get the required size of the output buffer.
            CryptokiEx.C_EncryptFinal(session, mechanism, null, lRefEnc);

            /* allocate space */
            byte[] aesencrypted = new byte[(int)lRefEnc.value];

            // Second call to populate the buffer.
            CryptokiEx.C_EncryptFinal(session, mechanism, aesencrypted, lRefEnc);

            // ***********************
            //   WRAP
            // ***********************

            byte[] wrappedKey = null;

            // Get the size to allocate for wrappedKey
            CryptokiEx.C_WrapKey(session, mechanism, hWrappingKey, hKeyToBeWrap, null, lWrapkey);

            wrappedKey = new byte [(int)(lWrapkey.value)];

            // Wrap AES key using another AES key.
            CryptokiEx.C_WrapKey(session, mechanism, hWrappingKey, hKeyToBeWrap, wrappedKey, lWrapkey);

            // ***********************
            //   UNWRAP
            // ***********************

            // Unwrap wrapped AES key.

            CK_OBJECT_HANDLE hAesUnWrapKey = new CK_OBJECT_HANDLE();

            CryptokiEx.C_UnwrapKey(session, mechanism, hWrappingKey, wrappedKey, wrappedKey.length,
                                   template, template.length, hAesUnWrapKey);

            // ***********************
            //   DECRYPTION
            // ***********************

            /* get ready to decrypt */
            CryptokiEx.C_DecryptInit(session, mechanism, hAesUnWrapKey);

            // For multi part, use C_DecryptUpdate and C_DecryptFinal.

            // Observe that, AES_KW does not return the decrypted size, nor the data, in the call(s) to C_DecryptUpdate.
            // The HSM accumulates all data until C_DecryptFinal is called, whereby the same PKCS approach may be employed:
            // first call with a null buffer to get the size, then allocate the buffer and call again to receive the
            // decrypted data.

            CryptokiEx.C_DecryptUpdate(session, mechanism, aesencrypted, lRefEnc.value, null, lRefDec);

            byte[] decryptedTextPart1 = new byte[(int) lRefDec.value];

            CryptokiEx.C_DecryptUpdate(session, mechanism, aesencrypted, aesencrypted.length,
                decryptedTextPart1, lRefDec);

            // First call to get the required size of the output buffer.
            CryptokiEx.C_DecryptFinal(session, mechanism, null, lRefDec);

            /* allocate space */
            byte[] aesdecrypted = new byte[(int)(lRefDec.value)];

            // Second call to populate the buffer.
            CryptokiEx.C_DecryptFinal(session, mechanism, aesdecrypted, lRefDec);

            // ***********************
            //   VERIFY
            // ***********************

            String endString = new String(aesdecrypted, 0, (int)lRefDec.value);

            if (ByteString.compareTo(endString) == 0)
            {
              println("Decrypted string matches original string - Decryption was successful\n");
            }
            else
            {
              println("*** Decrypted string does not match original string - Decryption failed ***\n");
            }

            System.out.println("\n---------------------------------------------------------------------------------");

            // Destroy objects
            CryptokiEx.C_DestroyObject(session, hWrappingKey);
            CryptokiEx.C_DestroyObject(session, hKeyToBeWrap);
            CryptokiEx.C_DestroyObject(session, hAesUnWrapKey);
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

}
