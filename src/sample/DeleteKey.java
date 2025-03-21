import com.safenetinc.jcprov.*;
import com.safenetinc.jcprov.constants.*;

/**
 * This class demonstrates the deletion of keys.
 * <p>
 * The types of keys supported are :-
 * <li>des          single DES key
 * <li>des2         double length Triple DES key
 * <li>des3         triple length Triple DES key
 * <li>rsa          RSA Key Pair
 *
 * <p>
 * Usage : java ...DeleteKey -keyType &lt;keytype&gt; -keyName &lt;keyname&gt; [-slot &lt;slotId&gt;] [-password &lt;password&gt;]
 * <li><i>keytype</i>  one of (des, des2, des3, rsa)
 * <li><i>keyname</i>  name (label) of the key to delete
 * <li><i>slotId</i>   slot containing the token to delete the key from - default (1)
 * <li><i>password</i> user password of the slot. If specified, a private key is deleted
 */
public class DeleteKey
{
    final static String fileVersion = "FileVersion: $Source: src/com/safenetinc/jcprov/sample/DeleteKey.java $ $Revision: 1.1.1.2 $";

    /** easy access to System.out.println */
    static public void println(String s)
    {
        System.out.println(s);
    }

    /** display runtime usage of the class */
    public static void usage()
    {
        println("java ...DeleteKey -keyType <keytype> -keyName <keyname> [-slot <slotId>] [-password <password>]");
        println("");
        println("<keytype>  one of (des, des2, des3, rsa)");
        println("<keyname>  name (label) of the key to delete");
        println("<slotId>   slot containing the token to delete the key from - default (1)");
        println("<password> user password of the slot. If specified, a private key is deleted.");
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
            CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));

            /*
             * Open a session
             */
            CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null, session);

            /*
             * Login - if we have a password
             */
            if (password.length() > 0)
            {
                CryptokiEx.C_Login(session, CKU.USER, password.getBytes(), password.length());

                bPrivate = true;
            }

            /*
             * determine the key type to delete, and delete the key
             */

            if (keyType.equalsIgnoreCase("des"))
            {
                CK_OBJECT_HANDLE hKey = null;

                hKey = findKey(session, CKO.SECRET_KEY, CKK.DES, keyName, bPrivate);

                if (!hKey.isValidHandle())
                {
                    println("des key (" + keyName + ") not found");
                }
                else
                {
                    CryptokiEx.C_DestroyObject(session, hKey);
                    println("des key (" + keyName + ") deleted");
                }
            }
            else if (keyType.equalsIgnoreCase("des2"))
            {
                CK_OBJECT_HANDLE hKey = null;

                hKey = findKey(session, CKO.SECRET_KEY, CKK.DES2, keyName, bPrivate);

                if (!hKey.isValidHandle())
                {
                    println("des2 key (" + keyName + ") not found");
                }
                else
                {
                    CryptokiEx.C_DestroyObject(session, hKey);
                    println("des2 key (" + keyName + ") deleted");
                }
            }
            else if (keyType.equalsIgnoreCase("des3"))
            {
                CK_OBJECT_HANDLE hKey = null;

                hKey = findKey(session, CKO.SECRET_KEY, CKK.DES3, keyName, bPrivate);

                if (!hKey.isValidHandle())
                {
                    println("des3 key (" + keyName + ") not found");
                }
                else
                {
                    CryptokiEx.C_DestroyObject(session, hKey);
                    println("des3 key (" + keyName + ") deleted");
                }
            }
            else if (keyType.equalsIgnoreCase("rsa"))
            {
                CK_OBJECT_HANDLE hPublicKey = null;
                CK_OBJECT_HANDLE hPrivateKey = null;

                hPublicKey = findKey(session, CKO.PUBLIC_KEY, CKK.RSA, keyName, bPrivate);

                if (!hPublicKey.isValidHandle())
                {
                    println("rsa public key (" + keyName + ") not found");
                }
                else
                {
                    CryptokiEx.C_DestroyObject(session, hPublicKey);
                    println("rsa public key (" + keyName + ") deleted");
                }

                hPrivateKey = findKey(session, CKO.PRIVATE_KEY, CKK.RSA, keyName, bPrivate);

                if (!hPrivateKey.isValidHandle())
                {
                    println("rsa private key (" + keyName + ") not found");
                }
                else
                {
                    CryptokiEx.C_DestroyObject(session, hPrivateKey);
                    println("rsa private key (" + keyName + ") deleted");
                }
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
             * will be reported - and we don't really care because we are shutting down.
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

        CryptokiEx.C_FindObjects(session, hObjects, hObjects.length, objectCount);

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
}
