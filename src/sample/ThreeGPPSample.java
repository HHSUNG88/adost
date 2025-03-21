
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
import com.safenetinc.jcprov.constants.CK;
import com.safenetinc.jcprov.constants.CKA;
import com.safenetinc.jcprov.constants.CKF;
import com.safenetinc.jcprov.constants.CKK;
import com.safenetinc.jcprov.constants.CKM;
import com.safenetinc.jcprov.constants.CKO;
import com.safenetinc.jcprov.constants.CKU;
import com.safenetinc.jcprov.params.CK_COMP128_SIGN_PARAMS;
import com.safenetinc.jcprov.params.CK_MILENAGE_SIGN_PARAMS;
import com.safenetinc.jcprov.params.CK_TUAK_SIGN_PARAMS;

/**
 * This class demonstrates various EC-based mechanisms
 * <p>
 * Usage : java ECIESExtSample [-slot &lt;slotId&gt;] [-password &lt;password&gt;]
 *
 * <li><i>slotId</i>   slot containing the token.
 * <li><i>password</i> user password of the slot.
 *
 */
public class ThreeGPPSample
{
  static public void println(String s) {
    System.out.println(s);
  }

  /** display runtime usage of the class */
  public static void usage() {
    println("java ...ThreeGPPSample -slot <slotId> -password <password>\n");
    println("");

    System.exit(1);
  }

  // IV
  private static byte[] iv = {0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0x0,0x1,0x2};

  private CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
  private static long slotId = 1;
  private static String password = "userpin1";

  private static long KI_LEN = 16;   // Can optionally be 32 for Tuak but hardcoded here
  private static long OP_LEN = 16;   // same for both Milenage and Tuak

  // Global Variables
  private static CK_OBJECT_HANDLE  hSK = new CK_OBJECT_HANDLE();
  private static CK_OBJECT_HANDLE  hOP = new CK_OBJECT_HANDLE();
  byte Ki[] = { (byte)0xA5, (byte)0xA5, (byte)0xA5, (byte)0xA5, (byte)0xA5, (byte)0xA5, (byte)0xA5, (byte)0xA5,
      (byte)0xA5, (byte)0xA5, (byte)0xA5, (byte)0xA5, (byte)0xA5, (byte)0xA5, (byte)0xA5, (byte)0xA5 };
  byte OP[] = { (byte)0xC7, (byte)0xC7, (byte)0xC7, (byte)0xC7, (byte)0xC7, (byte)0xC7, (byte)0xC7, (byte)0xC7,
      (byte)0xC7, (byte)0xC7, (byte)0xC7, (byte)0xC7, (byte)0xC7, (byte)0xC7, (byte)0xC7, (byte)0xC7 };
  byte RND[] = { (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77,
      (byte)0x88, (byte)0x99, (byte)0xAA, (byte)0xBB, (byte)0xCC, (byte)0xDD, (byte)0xEE, (byte)0xFF };
  byte SQN[] = { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06 };
  byte NEWSQN[] = { (byte)0x06, (byte)0x05, (byte)0x04, (byte)0x03, (byte)0x02, (byte)0x01 };
  byte AMF[] = { (byte)0xAF, (byte)0xAF };
  byte encKi[] = new byte[64];
  byte encOP[] = new byte[64];
  private static long encKiLen, encOPLen;

  void perform3GPPSetup()
  {
    try {

      String pSKKeyLabel = "AES Storage Key";
      String pOPLabel = "Operator Variant String";

      System.out.printf("Setting up the 3GPP Environment:");

      // Setup the encryption mechanism parameter structure - Note that the NIST approved
      // CKM_AES_KWP mechanism MUST be used as the Ki will be decrypted using this mechanism
      // Generate AES keys.
      CK_MECHANISM keyGenMech = new CK_MECHANISM(CKM.AES_KEY_GEN);

      CK_ATTRIBUTE[] pSKKeyAttributes = {
           new CK_ATTRIBUTE(CKA.TOKEN,       CK_BBOOL.FALSE),
           new CK_ATTRIBUTE(CKA.CLASS,       CKO.SECRET_KEY),
           new CK_ATTRIBUTE(CKA.KEY_TYPE,    CKK.AES),
           new CK_ATTRIBUTE(CKA.LABEL,       pSKKeyLabel.getBytes()),
           new CK_ATTRIBUTE(CKA.PRIVATE,     CK_BBOOL.TRUE),
           new CK_ATTRIBUTE(CKA.VALUE_LEN,   KI_LEN),
           new CK_ATTRIBUTE(CKA.SENSITIVE,   CK_BBOOL.TRUE),
           new CK_ATTRIBUTE(CKA.SIGN,        CK_BBOOL.TRUE),
           new CK_ATTRIBUTE(CKA.VERIFY,        CK_BBOOL.TRUE),
           new CK_ATTRIBUTE(CKA.ENCRYPT,     CK_BBOOL.TRUE),
           new CK_ATTRIBUTE(CKA.DECRYPT,     CK_BBOOL.TRUE),
           new CK_ATTRIBUTE(CKA.WRAP,        CK_BBOOL.TRUE),
           new CK_ATTRIBUTE(CKA.UNWRAP,      CK_BBOOL.TRUE),
           new CK_ATTRIBUTE(CKA.EXTRACTABLE, CK_BBOOL.FALSE),
      };

      CK_ATTRIBUTE   pOPAttributes[] =
      {
          new CK_ATTRIBUTE(CKA.CLASS,       CKO.SECRET_KEY),
          new CK_ATTRIBUTE(CKA.TOKEN,       CK_BBOOL.FALSE),
          new CK_ATTRIBUTE(CKA.KEY_TYPE,    CKK.GENERIC_SECRET),
          new CK_ATTRIBUTE(CKA.SENSITIVE,   CK_BBOOL.TRUE),
          new CK_ATTRIBUTE(CKA.LABEL,       pOPLabel.getBytes()),
          new CK_ATTRIBUTE(CKA.PRIVATE,     new CK_BBOOL(true)),
          new CK_ATTRIBUTE(CKA.VALUE_LEN,   OP_LEN)
      };

      CryptokiEx.C_GenerateKey(session, keyGenMech, pSKKeyAttributes, pSKKeyAttributes.length, hSK);
      System.out.printf("...SK Generated - handle=%d...", hSK.longValue());

      // Setup mechanism.
      CK_MECHANISM encmech = new CK_MECHANISM(CKM.AES_KWP, null);

      // Encrypt the Ki with the SK - Note that no IV provided so
      // HSM will use default value per spec
      CryptokiEx.C_EncryptInit(session, encmech, hSK);
      LongRef sizeForEnc = new LongRef(encKi.length);
      CryptokiEx.C_Encrypt(session, Ki, Ki.length, encKi, sizeForEnc);
      encKiLen = sizeForEnc.value;
      System.out.printf("Ki Encrypted...");

      // Encrypt the OP with the SK
      CryptokiEx.C_EncryptInit(session, encmech, hSK);
      sizeForEnc = new LongRef(encOP.length);
      CryptokiEx.C_Encrypt(session, OP, OP.length, encOP, sizeForEnc);
      encOPLen = sizeForEnc.value;
      System.out.printf("OP Encrypted...");

      // Lastly Unwrap the OP as an object on the HSM
      CryptokiEx.C_UnwrapKey(session, encmech, hSK, encOP, encOPLen,
          pOPAttributes, pOPAttributes.length, hOP);
      System.out.printf("OP imported to HSM - handle=%d...", hOP.longValue());

      System.out.printf("Done 3gpp setup%n");

    } catch (CKR_Exception ex) {
      /*
       * A Cryptoki related exception was thrown
       */
      ex.printStackTrace();
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

  void perform3GPPMilenageAuthenticate()
  {
    try {

      byte response[] = new byte[256];
      LongRef respLen = new LongRef(0);

      System.out.printf("Performing a Milenage Authentication operation:");

      CK_MILENAGE_SIGN_PARAMS milenageParams = new CK_MILENAGE_SIGN_PARAMS(
          0, // No encrypted/object OP, no TLV
          encKiLen,
          encKi,
          OP_LEN,
          OP,
          0, // key handle to OP generic secret object
          0, // key handle to user defined RC object (see Guide)
          SQN,
          AMF
      );

      CK_MECHANISM signmech = new CK_MECHANISM(CKM.MILENAGE, milenageParams);

      // Perform the signature function with plain OP and no TLV
      CryptokiEx.C_SignInit(session, signmech, hSK);
      respLen = new LongRef(response.length);
      CryptokiEx.C_Sign(session, null, 0, response, respLen);//NULL,0 could be RND,sizeof(RND)
      System.out.printf("...Unencrypted OP...");

      // If successful the function will return in the response buffer a
      // binary string containing a concatenation of the following:
      //      | RND | XRES(f2) | CK(f3) | IK(f4) | SQN xor AK(f5) | MAC-A(f1) |

      // Now perform the signature function with encrypted OP
      milenageParams = new CK_MILENAGE_SIGN_PARAMS(
          CK.LUNA_5G_ENCRYPTED_OP,
          encKiLen,
          encKi,
          encOPLen,
          encOP,
          0, // key handle to OP generic secret object
          0, // key handle to user defined RC object (see Guide)
          SQN,
          AMF
      );

      signmech = new CK_MECHANISM(CKM.MILENAGE, milenageParams);

      CryptokiEx.C_SignInit(session, signmech, hSK);
      respLen = new LongRef(response.length);
      CryptokiEx.C_Sign(session, null, 0, response, respLen);//NULL,0 could be RND,sizeof(RND)
      System.out.printf("Encrypted OP...");

      // Finally perform the signature function with the OP object
      milenageParams = new CK_MILENAGE_SIGN_PARAMS(
          CK.LUNA_5G_OP_OBJECT | CK.LUNA_5G_USE_TLV,
          encKiLen,
          encKi,
          0,
          null,
          hOP.longValue(), // key handle to OP generic secret object
          0, // key handle to user defined RC object (see Guide)
          SQN,
          AMF
      );

      signmech = new CK_MECHANISM(CKM.MILENAGE, milenageParams);

      CryptokiEx.C_SignInit(session, signmech, hSK);
      respLen = new LongRef(response.length);
      CryptokiEx.C_Sign(session, null, 0, response, respLen);//NULL,0 could be RND,sizeof(RND)
      System.out.printf("OP Object %d...", hOP.longValue());

      // If successful, this function will return in the response buffer as above, but
      // in TLV (tag/length/value) format (See Guide):
      //      | LUNA_5G_TAG_RANDOM | 16 | RND | LUNA_5G_TAG_RES | 8 | XRES | .....
      // NOTE - tag and length are single byte values (See Guide and cryptoki_v2.h header

      System.out.printf("Done%n");


    } catch (CKR_Exception ex) {
      /*
       * A Cryptoki related exception was thrown
       */
      ex.printStackTrace();
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

  void perform3GPPMilenageResync()
  {
    try {
      byte response[] = new byte[256];
      LongRef respLen = null;
      byte auts[] = new byte[256];

      System.out.printf("Performing a Milenage Resynchronization operation:");

      CK_MILENAGE_SIGN_PARAMS milenageParams = new CK_MILENAGE_SIGN_PARAMS(
          0, // No encrypted/object OP, no TLV
          encKiLen,
          encKi,
          OP_LEN,
          OP,
          0, // key handle to OP generic secret object
          0, // key handle to user defined RC object (see Guide)
          NEWSQN, // New sequence number requested by USIM
          AMF
      );

      CK_MECHANISM signmech = new CK_MECHANISM(CKM.MILENAGE_AUTS, milenageParams);

      // In order to do the resynchronization, it is first necessary to create the AUTS
      // data that is normally done by the USIM card - the HSM supports this operation
      // for test purposes only - NOTE: although all options regarding presentation
      // of the OP (or OPc) is available to this function (as with the authentication
      // function, only the unencrypted OP mode will be used here
      CryptokiEx.C_SignInit(session, signmech, hSK);
      respLen = new LongRef(response.length);
      CryptokiEx.C_Sign(session, RND, RND.length, auts, respLen);
      System.out.printf("OP Object %d...", hOP.longValue());

      System.out.printf("...AUTS string created...");

      // If that was successful, the response binary string should contain the following
      // concatenation:   | RND | SQN xor AK(f5*) | MAC-S(f1*) |   and this can now be
      // directly into the milenage resync API

      signmech = new CK_MECHANISM(CKM.MILENAGE_RESYNC, milenageParams);

      CryptokiEx.C_SignInit(session, signmech, hSK);
      CryptokiEx.C_Sign(session, auts, respLen.value, response, respLen);

      // Function will extract new sequence number from AUTS
      System.out.printf("Resync completed - New SQN:");
      for (int i = 0; i < respLen.value; i++) {
          System.out.printf("%02X", response[i]);
          System.out.printf("...");
      }

      // If successful the function will return the new SQN number, i.e.  | SQN |   If the
      // MAC-S(f1*) did not validate, the function will return error CKR_SIGNATURE_INVALID

      System.out.printf("Done%n");

    } catch (CKR_Exception ex) {
      /*
       * A Cryptoki related exception was thrown
       */
      ex.printStackTrace();
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

  void perform3GPPTuakAuthenticate()
  {
    try {

      byte response[] = new byte[256];
      LongRef respLen = new LongRef(0);

      System.out.printf("Performing a Tuak Authentication operation:");

      CK_TUAK_SIGN_PARAMS tuakParams = new CK_TUAK_SIGN_PARAMS(
          0, // No encrypted/object OP, no TLV
          encKiLen,
          encKi,
          OP_LEN,
          OP,
          1,
          0, // key handle to OP generic secret object
          4, // Can be 4, 8, 16 or 32 bytes
          8, // Can be 8, 16 or 32 bytes
          16, // Can be 16 or 32 bytes
          16, // Can be 16 or 32 bytes
          SQN,
          AMF
      );

      CK_MECHANISM signmech = new CK_MECHANISM(CKM.TUAK, tuakParams);

      // Perform the signature function with plain OP and no TLV
      CryptokiEx.C_SignInit(session, signmech, hSK);
      respLen = new LongRef(response.length);
      CryptokiEx.C_Sign(session, null, 0, response, respLen);//NULL,0 could be RND,sizeof(RND)
      System.out.printf("...Unencrypted OP...");

      // If successful the function will return in the response buffer a
      // binary string containing a concatenation of the following:
      //      | RND | XRES(f2) | CK(f3) | IK(f4) | SQN xor AK(f5) | MAC-A(f1) |

      // Now perform the signature function with encrypted OP
      tuakParams = new CK_TUAK_SIGN_PARAMS(
          CK.LUNA_5G_ENCRYPTED_OP,
          encKiLen,
          encKi,
          encOPLen,
          encOP,
          1,
          0, // key handle to OP generic secret object
          4, // Can be 4, 8, 16 or 32 bytes
          8, // Can be 8, 16 or 32 bytes
          16, // Can be 16 or 32 bytes
          16, // Can be 16 or 32 bytes
          SQN,
          AMF
      );

      signmech = new CK_MECHANISM(CKM.TUAK, tuakParams);

      CryptokiEx.C_SignInit(session, signmech, hSK);
      respLen = new LongRef(response.length);
      CryptokiEx.C_Sign(session, null, 0, response, respLen);//NULL,0 could be RND,sizeof(RND)
      System.out.printf("Encrypted OP...");

      // Finally perform the signature function with the OP object
      tuakParams = new CK_TUAK_SIGN_PARAMS(
          CK.LUNA_5G_OP_OBJECT | CK.LUNA_5G_USE_TLV,
          encKiLen,
          encKi,
          0,
          null,
          1,
          hOP.longValue(), // key handle to OP generic secret object
          4, // Can be 4, 8, 16 or 32 bytes
          8, // Can be 8, 16 or 32 bytes
          16, // Can be 16 or 32 bytes
          16, // Can be 16 or 32 bytes
          SQN,
          AMF
      );

      signmech = new CK_MECHANISM(CKM.TUAK, tuakParams);

      CryptokiEx.C_SignInit(session, signmech, hSK);
      respLen = new LongRef(response.length);
      CryptokiEx.C_Sign(session, null, 0, response, respLen);//NULL,0 could be RND,sizeof(RND)
      System.out.printf("OP Object %d...", hOP.longValue());

      // If successful, this function will return in the response buffer as above, but
      // in TLV (tag/length/value) format (See Guide):
      //      | LUNA_5G_TAG_RANDOM | 16 | RND | LUNA_5G_TAG_RES | 8 | XRES | .....
      // NOTE - tag and length are single byte values (See Guide and cryptoki_v2.h header

      System.out.printf("Done%n");


    } catch (CKR_Exception ex) {
      /*
       * A Cryptoki related exception was thrown
       */
      ex.printStackTrace();
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

  void perform3GPPTuakResync()
  {
    try {
      byte response[] = new byte[256];
      LongRef respLen = null;
      byte auts[] = new byte[256];

      System.out.printf("Performing a Tuak Resynchronization operation:");

      CK_TUAK_SIGN_PARAMS tuakParams = new CK_TUAK_SIGN_PARAMS(
          0, // No encrypted/object OP, no TLV
          encKiLen,
          encKi,
          OP_LEN,
          OP,
          1,
          0, // key handle to OP generic secret object
          4, // Can be 4, 8, 16 or 32 bytes
          8, // Can be 8, 16 or 32 bytes
          16, // Can be 16 or 32 bytes
          16, // Can be 16 or 32 bytes
          NEWSQN,
          AMF
        );

      CK_MECHANISM signmech = new CK_MECHANISM(CKM.TUAK_AUTS, tuakParams);

      // In order to do the resynchronization, it is first necessary to create the AUTS
      // data that is normally done by the USIM card - the HSM supports this operation
      // for test purposes only - NOTE: although all options regarding presentation
      // of the OP (or OPc) is available to this function (as with the authentication
      // function, only the unencrypted OP mode will be used here
      CryptokiEx.C_SignInit(session, signmech, hSK);
      respLen = new LongRef(auts.length);
      CryptokiEx.C_Sign(session, RND, RND.length, auts, respLen);
      System.out.printf("OP Object %d...", hOP.longValue());

      System.out.printf("...AUTS string created...");

      // If that was successful, the response binary string should contain the following
      // concatenation:   | RND | SQN xor AK(f5*) | MAC-S(f1*) |   and this can now be
      // directly into the milenage resync API

      signmech = new CK_MECHANISM(CKM.TUAK_RESYNC, tuakParams);

      CryptokiEx.C_SignInit(session, signmech, hSK);
      CryptokiEx.C_Sign(session, auts, respLen.value, response, respLen);

      // Function will extract new sequence number from AUTS
      System.out.printf("Resync completed - New SQN:");
      for (int i = 0; i < respLen.value; i++) {
          System.out.printf("%02X", response[i]);
          System.out.printf("...");
      }

      // If successful the function will return the new SQN number, i.e.  | SQN |   If the
      // MAC-S(f1*) did not validate, the function will return error CKR_SIGNATURE_INVALID

      System.out.printf("Done%n");

    } catch (CKR_Exception ex) {
      /*
       * A Cryptoki related exception was thrown
       */
      ex.printStackTrace();
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

  void perform3GPPComp128Authenticate()
  {
    try {

      byte response[] = new byte[256];
      LongRef respLen = null;

      System.out.printf("Performing a COMP128 Authentication operation:");

      CK_COMP128_SIGN_PARAMS comp128Params = new CK_COMP128_SIGN_PARAMS(
          1,//COMP128 version (1-3)
          encKiLen,
          encKi
      );

      CK_MECHANISM signmech = new CK_MECHANISM(CKM.COMP128, comp128Params);

      CryptokiEx.C_SignInit(session, signmech, hSK);
      respLen = new LongRef(response.length);
      CryptokiEx.C_Sign(session, null, 0, response, respLen);
      System.out.printf("...Unencrypted OP...");

      System.out.printf("Done%n");

    } catch (CKR_Exception ex) {
      /*
       * A Cryptoki related exception was thrown
       */
      ex.printStackTrace();
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

  void performInit()
  {

    try {
      /*
       * Initialize Cryptoki so that the library takes care of multithread
       * locking
       */
      CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));

      /*
       * Open a session
       */
      CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION | CKF.SERIAL_SESSION,
          null, null, session);

      /*
       * Login - if we have a password
       */
      if (password.length() > 0) {
        CryptokiEx.C_Login(session, CKU.USER, password.getBytes(),
            password.length());
      }

    } catch (CKR_Exception ex) {
      /*
       * A Cryptoki related exception was thrown
       */
      ex.printStackTrace();
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

  void performTeardown()
  {

    try {

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
       * return value. This is because if we did not log in then an error will
       * be reported - and we don't really care because we are shutting down.
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

  /** main execution method */
  public static void main(String[] args) {

    /*
     * process command line arguments
     */

    for (int i = 0; i < args.length; ++i) {

      if (args[i].equalsIgnoreCase("-slot")) {
        if (++i >= args.length)
          usage();

        slotId = Integer.parseInt(args[i]);
      } else if (args[i].equalsIgnoreCase("-password")) {
        if (++i >= args.length)
          usage();

        password = args[i];
      } else {
        usage();
      }
    }

    ThreeGPPSample aSample = new ThreeGPPSample();
    aSample.performInit();
    aSample.perform3GPPSetup();
    aSample.perform3GPPMilenageAuthenticate();
    aSample.perform3GPPMilenageResync();
    aSample.perform3GPPTuakAuthenticate();
    aSample.perform3GPPTuakResync();
    aSample.perform3GPPComp128Authenticate();
    aSample.performTeardown();

  }

}
