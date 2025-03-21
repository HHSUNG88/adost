import java.util.Arrays;
import java.util.Random;

import com.safenetinc.jcprov.CKR_Exception;
import com.safenetinc.jcprov.CK_ATTRIBUTE;
import com.safenetinc.jcprov.CK_BBOOL;
import com.safenetinc.jcprov.CK_C_INITIALIZE_ARGS;
import com.safenetinc.jcprov.CK_MECHANISM;
import com.safenetinc.jcprov.CK_OBJECT_HANDLE;
import com.safenetinc.jcprov.CK_SESSION_HANDLE;
import com.safenetinc.jcprov.params.CK_KEY_TRANSLATE_PARAMS;
import com.safenetinc.jcprov.Cryptoki;
import com.safenetinc.jcprov.CryptokiEx;
import com.safenetinc.jcprov.LongRef;
import com.safenetinc.jcprov.constants.CKA;
import com.safenetinc.jcprov.constants.CKF;
import com.safenetinc.jcprov.constants.CKK;
import com.safenetinc.jcprov.constants.CKM;
import com.safenetinc.jcprov.constants.CKO;
import com.safenetinc.jcprov.constants.CKU;
import com.safenetinc.jcprov.constants.CK_MECHANISM_TYPE;
import com.safenetinc.jcprov.CTUtil;

/**
 * This class demonstrates the Re-encryption (translation) of external keys.
 * <p>
 * The key being translated and the two keys used to unwrap/wrap are randomly generated
 * A DES2 key is translated from DES3_ECB to AES_KWP wrapping.
 * <p>
 * Usage : java ...Key [-slot &lt;slotId&gt;] [-password &lt;password&gt;]
 * <li><i>slotId</i>   slot containing the token to delete the key from - default (1)
 * <li><i>password</i> user password of the slot. If specified, a private key is created
 */
public class KeyTranslate
{
    final static String fileVersion = "FileVersion: $Source: $ $Revision: $";

    /** display runtime usage of the class */
    public static void usage()
    {
        System.out.println("java ...KeyTranslate [-slot <slotId>] [-password <password>]");
        System.out.println("A DES2 key is translated from DES3_CBC to AES_KWP wrapping.");
        System.out.println("");
        System.out.println("<slotId>   slot containing the token to create the keys on - default (1)");
        System.out.println("<password> user password of the slot. If specified, a private key is created.");
        System.out.println("");

        System.exit(1);
    }

    /** main execution method */
    public static void main(String[] args)
    {
        CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
        long slotId = 1;
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

            // orig mech DES3_CBC
            translateDES3CBCToAESKW(session, bPrivate);

            // orig mech AES_ECB
            translateAESECBToAESKW(session, bPrivate);

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
     * Generate a symmetric key.
     *
     * @param session
     *  handle to an open session
     *
     * @param mechanismType
     *  mechanism to use to generate the key. One of :- <br>
     *  CKM.DES_KEY_GEN                                 <br>
     *  CKM.DES2_KEY_GEN                                <br>
     *  CKM.DES3_KEY_GEN                                <br>
     *  CKM.AES_KEY_GEN                                 <br>
     *
     * @param keyName
     *  name (label) to give the generated key
     *
     * @param bPrivate
     *  true if the key is to be a private object
     *
     * @param hKey
     *  upon completion, handle of the generated key
     */
    public static void generateKey(CK_SESSION_HANDLE session,
                                   CK_MECHANISM_TYPE mechanismType,
                                   String keyName,
                                   boolean bPrivate,
                                   CK_OBJECT_HANDLE hKey)
    {
        CK_MECHANISM keyGenMech = new CK_MECHANISM(mechanismType);
        long keyLen = 16;

        if ( mechanismType.equals(CKM.DES_KEY_GEN) )
            keyLen = 8;
        else if ( mechanismType.equals(CKM.DES2_KEY_GEN) )
            keyLen = 16;
        else if ( mechanismType.equals(CKM.DES3_KEY_GEN) )
            keyLen = 24;
        else if ( mechanismType.equals(CKM.AES_KEY_GEN) )
            keyLen = 32;

        CK_ATTRIBUTE[] template =
        {
            new CK_ATTRIBUTE(CKA.CLASS,        CKO.SECRET_KEY),
            new CK_ATTRIBUTE(CKA.TOKEN,        CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.SENSITIVE,    CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.LABEL,        keyName.getBytes()),
            new CK_ATTRIBUTE(CKA.PRIVATE,      new CK_BBOOL(bPrivate)),
            new CK_ATTRIBUTE(CKA.ENCRYPT,      CK_BBOOL.FALSE),
            new CK_ATTRIBUTE(CKA.DECRYPT,      CK_BBOOL.FALSE),
            new CK_ATTRIBUTE(CKA.DERIVE,       CK_BBOOL.FALSE),
            new CK_ATTRIBUTE(CKA.WRAP,         CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.UNWRAP,       CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.EXTRACTABLE,  CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.VALUE_LEN,    keyLen),
        };

        CryptokiEx.C_GenerateKey(session, keyGenMech, template, template.length, hKey);
    }

    /**
     * Translate key.
     *
     * @param session
     *  handle to an open session
     *
     * @param orig_mech
     *  mechanism used in original wrap
     *
     * @param hOrigWrapKey
     *  handle of the key in original wrap
     *
     * @param new_mech
     *  mechanism used in new wrap
     *
     * @param hNewWrapKey
     *  handle of the key in new wrap
     *
     * @param wrappedKey
     *  cryptogram to convert
     *
     * @return
     *  byte[] of new cryptogram
     */
    public static byte[] KeyTranslateHelper(CK_SESSION_HANDLE session,
                                   CK_MECHANISM orig_mech,
                                   CK_OBJECT_HANDLE hOrigWrapKey,
                                   CK_MECHANISM new_mech,
                                   CK_OBJECT_HANDLE hNewWrapKey,
                                   byte[] wrappedKey)
    {
        LongRef lWrapkey = new LongRef();
        byte[] rewrappedKey = null;
        CK_OBJECT_HANDLE hInvalid = new CK_OBJECT_HANDLE ();
        CK_KEY_TRANSLATE_PARAMS params = new CK_KEY_TRANSLATE_PARAMS(
            0,
            new_mech,
            hOrigWrapKey,
            orig_mech,
            wrappedKey);
        CK_MECHANISM keytranslateMech = new CK_MECHANISM(CKM.KEY_TRANSLATE, params);

        // Get the size to allocate for rewrappedKey
        CryptokiEx.C_WrapKey(session, keytranslateMech, hNewWrapKey, hInvalid, rewrappedKey, lWrapkey);
        rewrappedKey = new byte [(int)(lWrapkey.value)];

        // perform the re-encryption
        CryptokiEx.C_WrapKey(session, keytranslateMech, hNewWrapKey, hInvalid, rewrappedKey, lWrapkey);

        // return the data output from the function
        return Arrays.copyOf(rewrappedKey, (int)lWrapkey.value);
    }


    public static void translateDES3CBCToAESKW( CK_SESSION_HANDLE session, boolean bPrivate )
    {

      CK_OBJECT_HANDLE hKey = new CK_OBJECT_HANDLE();
      CK_OBJECT_HANDLE hNewWrapKey = new CK_OBJECT_HANDLE();
      CK_OBJECT_HANDLE hOrigWrapKey = new CK_OBJECT_HANDLE();
      LongRef lWrapkey = new LongRef();
      byte[] wrappedKey = null;
      byte[] rewrappedKey = null;
      Random r = new Random();

      /*
       * generate the keys
       */

      generateKey(session, CKM.DES2_KEY_GEN, "targetKey", bPrivate, hKey);
      System.out.print("des2 key (targetKey) generated ");
      System.out.println("handle (" + hKey.longValue() + ")");

      generateKey(session, CKM.DES3_KEY_GEN, "OrigWrapKey", bPrivate, hOrigWrapKey);
      System.out.print("des3 key (orig WrapKey) generated ");
      System.out.println("handle (" + hOrigWrapKey.longValue() + ")");

      generateKey(session, CKM.AES_KEY_GEN, "NewWrapKey", bPrivate, hNewWrapKey);
      System.out.print("aes key (new WrapKey) generated ");
      System.out.println("handle (" + hNewWrapKey.longValue() + ")");

      byte[] orig_iv = { 1, 2, 3, 4, 5, 6, 7, 8 } ;
      orig_iv = new byte[8];  // DES_CBC
      r.nextBytes(orig_iv);
      CK_MECHANISM orig_mech = new CK_MECHANISM(CKM.DES3_CBC, orig_iv);

      byte[] new_iv = null;
      new_iv = new byte[4];   // AES_KWP
      r.nextBytes(new_iv);
      CK_MECHANISM new_mech = new CK_MECHANISM(CKM.AES_KWP, new_iv);

      /*
       * wrap the target key to make input cryptogram
       */

      System.out.print("Creating a DES3_CBC-wrapped key...");

      // Get the size to allocate for wrappedKey
      CryptokiEx.C_WrapKey(session, orig_mech, hOrigWrapKey, hKey, null, lWrapkey);
      wrappedKey = new byte [(int)(lWrapkey.value)];

      // Wrap hKey using hWrapKey.
      CryptokiEx.C_WrapKey(session, orig_mech, hOrigWrapKey, hKey, wrappedKey, lWrapkey);
      wrappedKey = Arrays.copyOf(wrappedKey, (int)lWrapkey.value);
      // dummy wrapped key
      //wrappedKey = "keytotranslate01keytotranslate02".getBytes();

      System.out.println("done");

      /*
       * do the key translate to make output cryptogram
       */

      System.out.print("Translate the DES3_CBC-wrapped key into an AES_KWP-wrapped key...");

      rewrappedKey = KeyTranslateHelper(session, orig_mech, hOrigWrapKey, new_mech, hNewWrapKey, wrappedKey);

      System.out.println("done");

      System.out.print("Test unwrap the AES_KWP-wrapped key...");

      CK_ATTRIBUTE[] template = {
          new CK_ATTRIBUTE(CKA.CLASS,        CKO.SECRET_KEY),
          new CK_ATTRIBUTE(CKA.KEY_TYPE,     CKK.DES2),
          new CK_ATTRIBUTE(CKA.TOKEN,        CK_BBOOL.FALSE),
          new CK_ATTRIBUTE(CKA.SENSITIVE,    CK_BBOOL.TRUE),
          new CK_ATTRIBUTE(CKA.PRIVATE,      new CK_BBOOL(bPrivate)),
          new CK_ATTRIBUTE(CKA.ENCRYPT,      CK_BBOOL.TRUE),
          new CK_ATTRIBUTE(CKA.DECRYPT,      CK_BBOOL.TRUE),
          new CK_ATTRIBUTE(CKA.DERIVE,       CK_BBOOL.FALSE),
          new CK_ATTRIBUTE(CKA.WRAP,         CK_BBOOL.TRUE),
          new CK_ATTRIBUTE(CKA.UNWRAP,       CK_BBOOL.TRUE),
          new CK_ATTRIBUTE(CKA.EXTRACTABLE,  CK_BBOOL.TRUE),
          new CK_ATTRIBUTE(CKA.LABEL,        "New DES2 Key"),
      };

      //use the original wrapped key
//      CryptokiEx.C_UnwrapKey(session, orig_mech, hOrigWrapKey, wrappedKey,
//          wrappedKey.length, template, template.length, hKey);
      //or use the translated wrapped key
      CryptokiEx.C_UnwrapKey(session, new_mech, hNewWrapKey, rewrappedKey,
          rewrappedKey.length, template, template.length, hKey);

      System.out.println("done");

    }

    public static void translateAESECBToAESKW( CK_SESSION_HANDLE session, boolean bPrivate )
    {

      CK_OBJECT_HANDLE hKey = new CK_OBJECT_HANDLE();
      CK_OBJECT_HANDLE hNewWrapKey = new CK_OBJECT_HANDLE();
      CK_OBJECT_HANDLE hOrigWrapKey = new CK_OBJECT_HANDLE();
      LongRef lWrapkey = new LongRef();
      byte[] wrappedKey = null;
      byte[] rewrappedKey = null;
      Random r = new Random();

      /*
       * generate the keys
       */

      generateKey(session, CKM.DES2_KEY_GEN, "targetKey", bPrivate, hKey);
      System.out.print("des2 key (targetKey) generated ");
      System.out.println("handle (" + hKey.longValue() + ")");

      generateKey(session, CKM.AES_KEY_GEN, "OrigWrapKey", bPrivate, hOrigWrapKey);
      System.out.print("aes key (orig WrapKey) generated ");
      System.out.println("handle (" + hOrigWrapKey.longValue() + ")");

      generateKey(session, CKM.AES_KEY_GEN, "NewWrapKey", bPrivate, hNewWrapKey);
      System.out.print("aes key (new WrapKey) generated ");
      System.out.println("handle (" + hNewWrapKey.longValue() + ")");

      CK_MECHANISM orig_mech = new CK_MECHANISM(CKM.AES_ECB, null);

      byte[] new_iv = new byte[4];   // AES_KWP
      r.nextBytes(new_iv);
      CK_MECHANISM new_mech = new CK_MECHANISM(CKM.AES_KWP, new_iv);

      lWrapkey = new LongRef();
      wrappedKey = null;
      rewrappedKey = null;

      /*
       * wrap the target key to make input cryptogram
       */

      System.out.print("Creating a AES_ECB-wrapped key...");

      // Get the size to allocate for wrappedKey
      CryptokiEx.C_WrapKey(session, orig_mech, hOrigWrapKey, hKey, null, lWrapkey);
      wrappedKey = new byte [(int)(lWrapkey.value)];

      // Wrap hKey using hWrapKey.
      CryptokiEx.C_WrapKey(session, orig_mech, hOrigWrapKey, hKey, wrappedKey, lWrapkey);
      wrappedKey = Arrays.copyOf(wrappedKey, (int)lWrapkey.value);
      // dummy wrapped key
      //wrappedKey = "keytotranslate01keytotranslate02".getBytes();

      System.out.println("done");

      /*
       * do the key translate to make output cryptogram
       */

      System.out.print("Translate the AES_ECB-wrapped key into an AES_KWP-wrapped key...");

      rewrappedKey = KeyTranslateHelper(session, orig_mech, hOrigWrapKey, new_mech, hNewWrapKey, wrappedKey);

      System.out.println("done");

      System.out.print("Test unwrap the AES_KWP-wrapped key...");

      CK_ATTRIBUTE[] template = {
          new CK_ATTRIBUTE(CKA.CLASS,        CKO.SECRET_KEY),
          new CK_ATTRIBUTE(CKA.KEY_TYPE,     CKK.DES2),
          new CK_ATTRIBUTE(CKA.TOKEN,        CK_BBOOL.FALSE),
          new CK_ATTRIBUTE(CKA.SENSITIVE,    CK_BBOOL.TRUE),
          new CK_ATTRIBUTE(CKA.PRIVATE,      new CK_BBOOL(bPrivate)),
          new CK_ATTRIBUTE(CKA.ENCRYPT,      CK_BBOOL.TRUE),
          new CK_ATTRIBUTE(CKA.DECRYPT,      CK_BBOOL.TRUE),
          new CK_ATTRIBUTE(CKA.DERIVE,       CK_BBOOL.FALSE),
          new CK_ATTRIBUTE(CKA.WRAP,         CK_BBOOL.TRUE),
          new CK_ATTRIBUTE(CKA.UNWRAP,       CK_BBOOL.TRUE),
          new CK_ATTRIBUTE(CKA.EXTRACTABLE,  CK_BBOOL.TRUE),
          new CK_ATTRIBUTE(CKA.LABEL,        "New DES2 Key"),
      };

      //use the original wrapped key
//      CryptokiEx.C_UnwrapKey(session, orig_mech, hOrigWrapKey, wrappedKey,
//          wrappedKey.length, template, template.length, hKey);
      //or use the translated wrapped key
      CryptokiEx.C_UnwrapKey(session, new_mech, hNewWrapKey, rewrappedKey,
          rewrappedKey.length, template, template.length, hKey);

      System.out.println("done");

    }

}
