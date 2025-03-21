
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
import com.safenetinc.jcprov.constants.LUNA;
import com.safenetinc.jcprov.params.CK_PRF_KDF_PARAMS;

public class KeyDeriveSample {

  final static String fileVersion = "FileVersion: "
      + "$Source: src/com/safenetinc/jcprov/sample/KeyDeriveSample.java $"
      + "$Revision: 1.0.0.0 $";

  static public void println(String s) {
    System.out.println(s);
  }

  /** display runtime usage of the class */
  public static void usage() {
    println("java ...KeyDeriveSample -slot <slotId> -password <password>\n");
    println("");

    System.exit(1);
  }

  // IV
  private static byte[] iv = {0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0x0,0x1,0x2};

  // Symmetric template.
  private static String keyLabel = "AesKey";

  // Derive template
  private static CK_ATTRIBUTE [] derive_template = {
    new CK_ATTRIBUTE (CKA.SENSITIVE, CK_BBOOL.TRUE),
    new CK_ATTRIBUTE (CKA.ENCRYPT, CK_BBOOL.TRUE),
    new CK_ATTRIBUTE (CKA.DECRYPT, CK_BBOOL.TRUE)
  };

  private static CK_ATTRIBUTE[] template = {
      new CK_ATTRIBUTE(CKA.CLASS, CKO.SECRET_KEY),
      new CK_ATTRIBUTE(CKA.TOKEN, CK_BBOOL.FALSE),
      new CK_ATTRIBUTE(CKA.CLASS, CKO.SECRET_KEY),
      new CK_ATTRIBUTE(CKA.KEY_TYPE, CKK.AES),
      new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.LABEL, keyLabel.getBytes()),
      new CK_ATTRIBUTE(CKA.PRIVATE, new CK_BBOOL(true)),
      new CK_ATTRIBUTE(CKA.ENCRYPT, CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.DECRYPT, CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.DERIVE, CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.WRAP, CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.UNWRAP, CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.DERIVE_TEMPLATE, derive_template, derive_template.length),
      new CK_ATTRIBUTE(CKA.VALUE_LEN, 16)
  };

  private CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
  private static long slotId = 0;
  private static String password = "";
  private boolean bPrivate = false;

  // ===================================================================

  public CK_OBJECT_HANDLE findObjects (CK_ATTRIBUTE tem[]) {
    LongRef objCount = new LongRef();

    CK_OBJECT_HANDLE[] objHandles = {new CK_OBJECT_HANDLE()};

    CryptokiEx.C_FindObjectsInit(session, tem, tem.length);
    CryptokiEx.C_FindObjects(session, objHandles, objHandles.length, objCount);
    CryptokiEx.C_FindObjectsFinal(session);

    if (objCount.value == 1){
      return objHandles[0];
    }
    else {
      return new CK_OBJECT_HANDLE();
    }

  }

  void deriveKey()
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

        bPrivate = true;
      }

      // Generate AES GCM parameters
      // Generate random IV and setup IV params
      Random r = new Random();
      iv = new byte[12];
      r.nextBytes(iv);
      // Generate Additional Authentication Data(AAD) bytes
      String aad = "AAAD";
      // Generate tag bits size
      int tagBits = 128;

      CK_OBJECT_HANDLE key = new CK_OBJECT_HANDLE();

      // Generate AES keys.

      CK_MECHANISM keyGenMech = new CK_MECHANISM(CKM.AES_KEY_GEN);

      CryptokiEx.C_GenerateKey(session, keyGenMech, template, template.length,
          key);

      //derive the key
      CK_OBJECT_HANDLE hBaseKey = null;
      CK_OBJECT_HANDLE hVerifyKey = null;
      CK_OBJECT_HANDLE hderivedKey = new CK_OBJECT_HANDLE();
      hBaseKey = key;

      String keyLabel = "Derived Key_AES3: CKM_NIST_PRF_KDF";

      CK_ATTRIBUTE [] des_template = {
              new CK_ATTRIBUTE (CKA.TOKEN, CK_BBOOL.FALSE),
              new CK_ATTRIBUTE (CKA.CLASS, CKO.SECRET_KEY),
              new CK_ATTRIBUTE (CKA.LABEL, keyLabel.getBytes()),
              new CK_ATTRIBUTE (CKA.SENSITIVE, CK_BBOOL.TRUE),
              new CK_ATTRIBUTE (CKA.PRIVATE, CK_BBOOL.TRUE),
              new CK_ATTRIBUTE (CKA.KEY_TYPE, CKK.DES),
              new CK_ATTRIBUTE (CKA.ENCRYPT, CK_BBOOL.TRUE),
              new CK_ATTRIBUTE (CKA.WRAP, CK_BBOOL.TRUE),
              new CK_ATTRIBUTE (CKA.SIGN, CK_BBOOL.TRUE),
              new CK_ATTRIBUTE (CKA.DERIVE, CK_BBOOL.TRUE),
              new CK_ATTRIBUTE (CKA.DECRYPT, CK_BBOOL.TRUE),
              new CK_ATTRIBUTE (CKA.UNWRAP, CK_BBOOL.FALSE),
              new CK_ATTRIBUTE (CKA.VERIFY, CK_BBOOL.FALSE)
     };

      long count = des_template.length;

      byte[] paramsLabel = {1, 2, 3, 4, 5 ,6, 7, 8};
      byte[] context = {1, 2, 3, 4, 5 ,6, 7, 8};
      CK_PRF_KDF_PARAMS params = new CK_PRF_KDF_PARAMS(CK.NIST_PRF_KDF_AES_CMAC, paramsLabel,
              context, 1, LUNA.PRF_KDF_ENCODING_SCHEME_1);

      CK_MECHANISM mech = new CK_MECHANISM(CKM.NIST_PRF_KDF, params);

      CryptokiEx.C_DeriveKey(session, mech, hBaseKey, des_template, count, hderivedKey);
      hVerifyKey = findObjects(des_template);
      if(hderivedKey.longValue() == hVerifyKey.longValue()) {
        println("hderivedKey == hVerifyKey");
      }else {
        println("ERROR:hderivedKey != hVerifyKey");
      }


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
    if(args.length < 4) usage();
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

    KeyDeriveSample aSample = new KeyDeriveSample();
    aSample.deriveKey();

  }

}
