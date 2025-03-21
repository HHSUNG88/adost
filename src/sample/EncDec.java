
import com.safenetinc.jcprov.*;
import com.safenetinc.jcprov.constants.*;

/**
 * This class demonstrates the encryption and decryption operations.
 * <p>
 * The types of keys supported are :-
 * <li>des          single DES key
 * <li>des2         double length Triple DES key
 * <li>des3         triple length Triple DES key
 * <li>rsa          RSA Key Pair
 * <p>
 * Usage : java ...EncDec -keyType &lt;keytype&gt; -keyName &lt;keyname&gt;
 *         [-slot &lt;slotId&gt;] [-password &lt;password&gt;]
 * <li><i>keytype</i>  one of (des, des2, des3, rsa)
 * <li><i>keyname</i>  name (label) of the key to delete
 * <li><i>slotId</i>   slot containing the token to delete the key from -
 *                     default (1)
 * <li><i>password</i> user password of the slot. If specified, a private key
 *                     is used
 */
public class EncDec
{
    final static String fileVersion = "FileVersion: " +
"$Source: src/com/safenetinc/jcprov/sample/EncDec.java $" +
        "$Revision: 1.1.1.3 $";

    /** easy access to System.out.println
     * Changed to use print, instead, soas not to get system-specific line terminators in the string. JSE 9Jan2015
     */
    static public void println(String s)
    {
        System.out.println(s);
    }

    /** display runtime usage of the class */
    public static void usage()
    {
        println("java ...EncDec -keyType <keytype> -keyName <keyname> " +
                "[-slot <slotId>] [-password <password>]");
        println("");
        println("<keytype>  one of (des, des2, des3, rsa)");
        println("<keyname>  name (label) of the generated key");
        println("<slotId>   slot containing the token with the key to use - " +
                "default (1)");
        println("<password> user password of the slot. If specified, a " +
                "private key is used.");
        println("");

        System.exit(1);
    }

    /** main execution method */
    public static void main(String[] args)
    {
        CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
        long slotId = 1;
        String keyType = "";
        String keyName = "";
        String password = "";
        boolean bPrivate = false;

        /*
         * process command line arguments
         */

        for (int i = 0; i < args.length; ++i)
        {
            if (args[i].equalsIgnoreCase("-keyType"))
            {
                if (++i >= args.length)
                    usage();

                keyType = args[i];
            }
            else if (args[i].equalsIgnoreCase("-keyName"))
            {
                if (++i >= args.length)
                    usage();

                keyName = args[i];
            }
            else if(args[i].equalsIgnoreCase("-slot"))
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

        try
        {
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
            if (password.length() > 0)
            {
                CryptokiEx.C_Login(session, CKU.USER, password.getBytes(),
                        password.length());

                bPrivate = true;
            }

            /*
             * determine the key type to use
             */

            if (keyType.equalsIgnoreCase("des"))
            {
                CK_OBJECT_HANDLE hKey = null;

                hKey = findKey(session, CKO.SECRET_KEY, CKK.DES, keyName,
                        bPrivate);

                if (!hKey.isValidHandle())
                {
                    println("des key (" + keyName + ") not found");
                    return;
                }

                symetricEncDec(session, hKey, new CK_MECHANISM(CKM.DES_ECB));
            }
            else if (keyType.equalsIgnoreCase("des2"))
            {
                CK_OBJECT_HANDLE hKey = null;

                hKey = findKey(session, CKO.SECRET_KEY, CKK.DES2, keyName,
                        bPrivate);

                if (!hKey.isValidHandle())
                {
                    println("des2 key (" + keyName + ") not found");
                    return;
                }

                symetricEncDec(session, hKey, new CK_MECHANISM(CKM.DES3_ECB));
            }
            else if (keyType.equalsIgnoreCase("des3"))
            {
                CK_OBJECT_HANDLE hKey = null;

                hKey = findKey(session, CKO.SECRET_KEY, CKK.DES3, keyName,
                        bPrivate);

                if (!hKey.isValidHandle())
                {
                    println("des3 key (" + keyName + ") not found");
                    return;
                }

                symetricEncDec(session, hKey, new CK_MECHANISM(CKM.DES3_ECB));
            }
            else if (keyType.equalsIgnoreCase("rsa"))
            {
                CK_OBJECT_HANDLE hPublicKey = null;
                CK_OBJECT_HANDLE hPrivateKey = null;

                hPublicKey = findKey(session, CKO.PUBLIC_KEY, CKK.RSA, keyName,
                        false);

                if (!hPublicKey.isValidHandle())
                {
                    println("rsa public key (" + keyName + ") not found");
                    return;
                }

                hPrivateKey = findKey(session, CKO.PRIVATE_KEY, CKK.RSA,
                        keyName, bPrivate);

                if (!hPrivateKey.isValidHandle())
                {
                    println("rsa private key (" + keyName + ") not found");
                    return;
                }

                asymetricEncDec(session, hPublicKey, hPrivateKey,
                        new CK_MECHANISM(CKM.RSA_PKCS));
            }
            else
            {
                usage();
            }
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


    /**
     * Locate the specified key. 
     *
     * @param session
     *  handle to an open session
     *
     * @param keyClass
     *  {@link com.safenetinc.jcprov.constants.CKO} class of the key to locate
     *
     * @param keyName
     *  name (label) of the key to locate
     *
     * @param bPrivate
     *  true if the key to locate is a private object
     */
    static CK_OBJECT_HANDLE findKey(CK_SESSION_HANDLE session,
                                    CK_OBJECT_CLASS keyClass,
                                    CK_KEY_TYPE keyType,
                                    String keyName,
                                    boolean bPrivate)
    {
        /* array of one object handles */
        CK_OBJECT_HANDLE[] hObjects = {new CK_OBJECT_HANDLE()};
 
        /* to receive the number of objects located */
        LongRef objectCount = new LongRef();

        /* setup the template of the object to search for */
        CK_ATTRIBUTE[] template =
        {
            new CK_ATTRIBUTE(CKA.CLASS,     keyClass),
            new CK_ATTRIBUTE(CKA.KEY_TYPE,  keyType),
            new CK_ATTRIBUTE(CKA.TOKEN,     CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.LABEL,     keyName.getBytes()),
            new CK_ATTRIBUTE(CKA.PRIVATE,   new CK_BBOOL(bPrivate))
        };

        CryptokiEx.C_FindObjectsInit(session, template, template.length);

        CryptokiEx.C_FindObjects(session, hObjects, hObjects.length,
                objectCount);

        CryptokiEx.C_FindObjectsFinal(session);

        if (objectCount.value == 1)
        {
            /* return the handle of the located object */
            return hObjects[0];
        }
        else
        {
            /* return an object handle which is invalid */
            return new CK_OBJECT_HANDLE();
        }
    }

    /**
     * Symetric key encryption/decryption.
     *
     * @param session
     *  handle to an open session
     *
     * @param hKey
     *  handle to symetric key to use
     *
     * @param mechanism
     *  mechanism to use
     */
    static void symetricEncDec(CK_SESSION_HANDLE session,
                               CK_OBJECT_HANDLE hKey,
                               CK_MECHANISM mechanism)
    {
        String startString = "this is 16 bytes";
        byte[] plainText = startString.getBytes();
        byte[] cipherText = null;
        LongRef lRefEnc = new LongRef();
        LongRef lRefDec = new LongRef();

        /* get ready to encrypt */
        CryptokiEx.C_EncryptInit(session, mechanism, hKey);

        /* get the size of the cipher text (may be larger than actually
         * required)
         */
        CryptokiEx.C_Encrypt(session, plainText, plainText.length, null,
                lRefEnc);

        /* allocate space */
        cipherText = new byte[(int)lRefEnc.value];

        /* encrypt */
        CryptokiEx.C_Encrypt(session, plainText, plainText.length, cipherText,
                lRefEnc);

        /*
         * After doing an encrypt, it is possible that the resulting data size
         * is smaller than the created buffer, so MUST ensure that the value of
         * lRefEnc is used for the length of cipherText, NOT its .length
         */
        
        /* get ready to decrypt */
        CryptokiEx.C_DecryptInit(session, mechanism, hKey);

        /* get the size of the plain text */
        CryptokiEx.C_Decrypt(session, cipherText, lRefEnc.value, null, lRefDec);

        /* allocate space */
        plainText = new byte[(int)lRefDec.value];

        /* decrypt */
        CryptokiEx.C_Decrypt(session, cipherText, lRefEnc.value, plainText,
                lRefDec);

        /* make sure that we end up with what we started with */
        String endString = new String(plainText, 0, (int)lRefDec.value);

        if (startString.compareTo(endString) == 0)
        {
            println("Decrypted string matches original string - hurray");
        }
        else
        {
            println("Decrypted string does not match original string - boo");
        }
    }

    /**
     * Aymetric key encryption/decryption.
     *
     * Typically you would not do this, but rather do sign/verify operations.
     *
     * @param session
     *  handle to an open session
     *
     * @param hPublicKey
     *  handle to public asymetric key to use for encryption
     *
     * @param hPrivateKey
     *  handle to private asymetric key to use for decryption
     *
     * @param mechanism
     *  mechanism to use
     */
    static void asymetricEncDec(CK_SESSION_HANDLE session,
                                CK_OBJECT_HANDLE hPublicKey,
                                CK_OBJECT_HANDLE hPrivateKey,
                                CK_MECHANISM mechanism)
    {
        String startString = "this is 16 bytes";
        byte[] plainText = startString.getBytes();
        byte[] cipherText = null;
        LongRef lRefEnc = new LongRef();
        LongRef lRefDec = new LongRef();

        /* get ready to encrypt */
        CryptokiEx.C_EncryptInit(session, mechanism, hPublicKey);

        /* get the size of the cipher text */
        CryptokiEx.C_Encrypt(session, plainText, plainText.length, null,
                lRefEnc);

        /* allocate space */
        cipherText = new byte[(int)lRefEnc.value];

        /* encrypt */
        CryptokiEx.C_Encrypt(session, plainText, plainText.length, cipherText,
                lRefEnc);

        /* get ready to decrypt */
        CryptokiEx.C_DecryptInit(session, mechanism, hPrivateKey);

        /* get the size of the plain text */
        CryptokiEx.C_Decrypt(session, cipherText, lRefEnc.value, null, lRefDec);

        /* allocate space */
        plainText = new byte[(int)lRefDec.value];

        /* decrypt */
        CryptokiEx.C_Decrypt(session, cipherText, lRefEnc.value, plainText,
                lRefDec);

        /* make sure that we end up with what we started with */
        String endString = new String(plainText, 0, (int)lRefDec.value);

        if (startString.compareTo(endString) == 0)
        {
            println("Decrypted string matches original string - hurray");
        }
        else
        {
            println("Decrypted string does not match original string - boo");
        }
    }
}
