
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
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
import com.safenetinc.jcprov.constants.CK_MECHANISM_TYPE;
import com.safenetinc.jcprov.constants.CK_RV;

/**
 * This class demonstrates the encryption/decryption operations with IV/AAD/Tag
 * bits using the AES GCM mechanism.
 * <p>
 * Usage : java SKSPKASample [-slot &lt;slotId&gt;] [-password &lt;password&gt;]
 * [-keyName &lt;keyName&gt;]
 *
 * <li><i>slotId</i> slot containing the token.
 * <li><i>password</i> user password of the slot.
 * <li><i>keyName</i> user chosen key label.
 *
 */
public class SKSPKASample {
  static public void println(String s) {
    System.out.println(s);
  }

  /** display runtime usage of the class */
  public static void usage() {
    println("java ...SIMPKASample -slot <slotId> -password <password>\n");
    println("");

    System.exit(1);
  }

  // IV
  private static byte[] iv = { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x0, 0x1, 0x2 };

  // Symmetric template.
  private static String keyLabel = "AesKey";

  private static CK_ATTRIBUTE[] template = { new CK_ATTRIBUTE(CKA.CLASS, CKO.SECRET_KEY),
      new CK_ATTRIBUTE(CKA.TOKEN, CK_BBOOL.FALSE), new CK_ATTRIBUTE(CKA.CLASS, CKO.SECRET_KEY),
      new CK_ATTRIBUTE(CKA.KEY_TYPE, CKK.AES), new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.LABEL, keyLabel.getBytes()), new CK_ATTRIBUTE(CKA.PRIVATE, new CK_BBOOL(true)),
      new CK_ATTRIBUTE(CKA.ENCRYPT, CK_BBOOL.TRUE), new CK_ATTRIBUTE(CKA.DECRYPT, CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.DERIVE, CK_BBOOL.TRUE), new CK_ATTRIBUTE(CKA.WRAP, CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.UNWRAP, CK_BBOOL.TRUE), new CK_ATTRIBUTE(CKA.VALUE_LEN, 16) };

  private CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
  private static long slotId = 0;
  private static String password = "";
  private static String keyName = "";
  private boolean bPrivate = true;

  /**
   * Generate an asymetric key pair.
   *
   * @param session       handle to an open session
   *
   * @param mechanismType mechanism to use to generate the key. One of :- <br>
   *                      CKM.RSA_PKCS_KEY_PAIR_GEN <br>
   *
   * @param keyName       name (label) to give the generated keys
   *
   * @param bPrivate      true if the Private key of the key pair is to be a
   *                      private object
   *
   * @param hPublicKey    upon completion, the handle of the generated public key
   *
   * @param hPrivateKey   upon completion, the handle of the generated private key
   */
  public static void generateKeyPair(CK_SESSION_HANDLE session, CK_MECHANISM_TYPE mechanismType, String keyName,
      boolean bPrivate, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey, boolean authdataProvided ) {
    CK_MECHANISM keyGenMech = new CK_MECHANISM(mechanismType);
    byte bb = 03;
//    Byte pubExponent = new Byte(bb);
    byte[] pubExponent = { 0x01, 0x00, 0x01 };
    long ll = 1024L;
    ll = 2048L;
    Long modulusBits = new Long(ll);
    byte[] authData = "abcdefgh".getBytes();

    CK_ATTRIBUTE[] publicTemplate = { new CK_ATTRIBUTE(CKA.LABEL, keyName.getBytes()),
        new CK_ATTRIBUTE(CKA.TOKEN, CK_BBOOL.FALSE), new CK_ATTRIBUTE(CKA.VERIFY, CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.ENCRYPT, CK_BBOOL.TRUE), new CK_ATTRIBUTE(CKA.WRAP, CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.MODIFIABLE, CK_BBOOL.TRUE), new CK_ATTRIBUTE(CKA.MODULUS_BITS, modulusBits),
        new CK_ATTRIBUTE(CKA.PUBLIC_EXPONENT, pubExponent), };

    CK_ATTRIBUTE[] privateTemplate = null;
    if ( authdataProvided ) {
      CK_ATTRIBUTE[] privateTemplateTemp = { new CK_ATTRIBUTE(CKA.PRIVATE, new CK_BBOOL(bPrivate)), // needs to be true for
                                                                                                // PKA
        new CK_ATTRIBUTE(CKA.LABEL, keyName.getBytes()), new CK_ATTRIBUTE(CKA.TOKEN, CK_BBOOL.FALSE),
        new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.TRUE), new CK_ATTRIBUTE(CKA.SIGN, CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.DECRYPT, CK_BBOOL.TRUE), new CK_ATTRIBUTE(CKA.UNWRAP, CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.MODIFIABLE, CK_BBOOL.FALSE), // needs to be false for PKA
        new CK_ATTRIBUTE(CKA.EXTRACTABLE, CK_BBOOL.FALSE),// needs to be false for PKA
        new CK_ATTRIBUTE(CKA.AUTH_DATA,     authData),//needs to be set to some byte array of 7+ bytes (see spec)
                                                      //for PKA
      };
      privateTemplate = privateTemplateTemp;
    } else {
      CK_ATTRIBUTE[] privateTemplateTemp = { new CK_ATTRIBUTE(CKA.PRIVATE, new CK_BBOOL(bPrivate)), // needs to be true for
                                                                                                    // PKA
        new CK_ATTRIBUTE(CKA.LABEL, keyName.getBytes()), new CK_ATTRIBUTE(CKA.TOKEN, CK_BBOOL.FALSE),
        new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.TRUE), new CK_ATTRIBUTE(CKA.SIGN, CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.DECRYPT, CK_BBOOL.TRUE), new CK_ATTRIBUTE(CKA.UNWRAP, CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.MODIFIABLE, CK_BBOOL.FALSE), // needs to be false for PKA
        new CK_ATTRIBUTE(CKA.EXTRACTABLE, CK_BBOOL.FALSE),// needs to be false for PKA
      };
      privateTemplate = privateTemplateTemp;
    }

    CryptokiEx.C_GenerateKeyPair(session, keyGenMech, publicTemplate, publicTemplate.length, privateTemplate,
        privateTemplate.length, hPublicKey, hPrivateKey);
  }

  void doSIM() {

    System.out.println("doSIM");

    try {
      /*
       * Initialize Cryptoki so that the library takes care of multithread locking
       */
      CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));

      /*
       * Open a session
       */
      CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null, session);

      /*
       * Login - if we have a password
       */
      if (password.length() > 0) {
        CryptokiEx.C_Login(session, CKU.USER, password.getBytes(), password.length());

        bPrivate = true;
      }

      find(session);

      CK_OBJECT_HANDLE hPublicKey = new CK_OBJECT_HANDLE();
      CK_OBJECT_HANDLE hPrivateKey = new CK_OBJECT_HANDLE();
      CK_OBJECT_HANDLE hKey = new CK_OBJECT_HANDLE(119);

      generateKeyPair(session, CKM.RSA_PKCS_KEY_PAIR_GEN, keyName, bPrivate, hPublicKey, hPrivateKey, false);

      println("rsa key pair (" + keyName + ") generated");
      println("handles: public(" + hPublicKey.longValue() + ") private(" + hPrivateKey.longValue() + ")");

      // do SIMExtract
      long handleCountL = 2;
      CK_OBJECT_HANDLE[] objectHandles = new CK_OBJECT_HANDLE[2];
      objectHandles[0] = hPrivateKey;
      objectHandles[1] = hPublicKey;
      long authSubsetCount = 1;// m
      long authSecretCount = 2;// n
      long authForm = CK.SIM_PASSWORD;
      int[] authSecretSizes = {"password1".length(),"password2".length()};
      byte[][] authSecretList = {"password1".getBytes(),"password2".getBytes()};
      boolean deleteAfterExtract = true;
      LongRef blobLen = new LongRef(0);
      byte[] blob = null;
      CK_RV rv = new CK_RV(0);

      rv = CryptokiEx.CA_SIMExtract(session, handleCountL, objectHandles, authSecretCount, authSubsetCount, authForm,
          authSecretSizes, authSecretList, deleteAfterExtract, blobLen, blob);

      blob = new byte[(int) (blobLen.value)];

      rv = CryptokiEx.CA_SIMExtract(session, handleCountL, objectHandles, authSecretCount, authSubsetCount, authForm,
          authSecretSizes, authSecretList, deleteAfterExtract, blobLen, blob);

      // do SIMInsert
      authSubsetCount = 1;// m
      authSecretSizes = new int[] {"password1".length()};
      authSecretList = new byte[][] {"password1".getBytes()};
      // OR
      authSecretSizes = new int[] {"password2".length()};
      authSecretList = new byte[][] {"password2".getBytes()};
      // OR
      authSubsetCount = 2;// m
      authSecretSizes = new int[] {"password1".length() , "password2".length()};
      authSecretList = new byte[][] {"password1".getBytes() , "password2".getBytes()};

      LongRef handleCount = new LongRef(0);
      objectHandles = null;

      CryptokiEx.CA_SIMInsert(session, authSubsetCount, authForm, authSecretSizes, authSecretList, blobLen.value,
          blob, handleCount, objectHandles);

      objectHandles = new CK_OBJECT_HANDLE[(int) (handleCount.value)];
      for (int i = 0; i < objectHandles.length; i++) {
        objectHandles[i] = new CK_OBJECT_HANDLE(0);
      }

      CryptokiEx.CA_SIMInsert(session, authSubsetCount, authForm, authSecretSizes, authSecretList, blobLen.value,
          blob, handleCount, objectHandles);

      // Destroy created token objects
      for (int i = 0; objectHandles != null && i < objectHandles.length; i++) {
        System.out.println("destroying objectHandles[" + i + "]:" + objectHandles[i].longValue());
        CryptokiEx.C_DestroyObject(session, objectHandles[i]);
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
       * Note that we are not using CryptokiEx and we are not checking the return
       * value. This is because if we did not log in then an error will be reported -
       * and we don't really care because we are shutting down.
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

  void doSIMMultiSign() {

    System.out.println("doSIMMultiSign");

    try {
      /*
       * Initialize Cryptoki so that the library takes care of multithread locking
       */
      CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));

      /*
       * Open a session
       */
      CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null, session);

      /*
       * Login - if we have a password
       */
      if (password.length() > 0) {
        CryptokiEx.C_Login(session, CKU.USER, password.getBytes(), password.length());

        bPrivate = true;
      }

      find(session);

      CK_OBJECT_HANDLE hPublicKey = new CK_OBJECT_HANDLE();
      CK_OBJECT_HANDLE hPrivateKey = new CK_OBJECT_HANDLE();
      CK_OBJECT_HANDLE hKey = new CK_OBJECT_HANDLE(119);

      generateKeyPair(session, CKM.RSA_PKCS_KEY_PAIR_GEN, keyName, bPrivate, hPublicKey, hPrivateKey, false);

      println("rsa key pair (" + keyName + ") generated");
      println("handles: public(" + hPublicKey.longValue() + ") private(" + hPrivateKey.longValue() + ")");

      // do SIMExtract
      long handleCountL = 2;
      CK_OBJECT_HANDLE[] objectHandles = new CK_OBJECT_HANDLE[2];
      objectHandles[0] = hPrivateKey;
      objectHandles[1] = hPublicKey;
      long authSecretCount = 0;// n
      long authSubsetCount = 0;// m
      long authForm = CK.SIM_NO_AUTHORIZATION;
      int[] authSecretSizes = null;
      byte[][] authSecretList = null;
      boolean deleteAfterExtract = true;
      LongRef blobLen = new LongRef(0);
      long blobLenL = 0;
      byte[] blob = null;
      CK_RV rv = new CK_RV(0);

      rv = CryptokiEx.CA_SIMExtract(session, handleCountL, objectHandles, authSecretCount, authSubsetCount, authForm,
          authSecretSizes, authSecretList, deleteAfterExtract, blobLen, blob);

      blob = new byte[(int) (blobLen.value)];

      rv = CryptokiEx.CA_SIMExtract(session, handleCountL, objectHandles, authSecretCount, authSubsetCount, authForm,
          authSecretSizes, authSecretList, deleteAfterExtract, blobLen, blob);

      // do SIMMultiSign - CA_SimMultiSign requires pre-allocation of memory for the sig and sig
      // lengths and as such requires a single call unlike the typical PKCS#11 crypto function
      CK_MECHANISM mech = new CK_MECHANISM();
      mech.mechanism = CKM.RSA_PKCS;
      mech.pParameter = null;
      mech.parameterLen = 0;

      blobLenL = blobLen.value;
      // Need a DER-encoded signature block for the RSA_PKCS signing test.
      byte[] DERSignature = {
          (byte)0x30, (byte)0x31,
          (byte)0x30, (byte)0x0d, (byte)0x06, (byte)0x09, (byte)0x60, (byte)0x86, (byte)0x48, (byte)0x01, (byte)0x65,
            (byte)0x03, (byte)0x04, (byte)0x02, (byte)0x01,
          (byte)0x05, (byte)0x00,
          (byte)0x04, (byte)0x20,
          (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x88,
            (byte)0x99, (byte)0xaa, (byte)0xbb, (byte)0xcc, (byte)0xdd, (byte)0xee, (byte)0xff,
          (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x88,
            (byte)0x99, (byte)0xaa, (byte)0xbb, (byte)0xcc, (byte)0xdd, (byte)0xee, (byte)0xff,
      };
      byte[][] datas = { DERSignature, DERSignature };
      long dataCount = datas.length;
      int[] dataLens = { DERSignature.length, DERSignature.length };

      byte[][] signatures = new byte[(int) dataCount][];
      LongRef[] signatureLens = new LongRef[(int) dataCount];
      for (int i = 0; i < signatureLens.length; i++) {
        signatureLens[i] = new LongRef(3000);
        signatures[i] = new byte[3000];
      }

      rv = CryptokiEx.CA_SIMMultiSign(
          session,
          mech,
          authSubsetCount,
          authForm,
          authSecretSizes,
          authSecretList,
          blobLenL,
          blob,
          dataCount,
          dataLens,
          datas,
          signatureLens,
          signatures);

      for (int i = 0; i < signatureLens.length; i++) {
        System.out.println("signatureLens[" + i + "].value=" + signatureLens[i].value);
        System.out.print("0x");
        System.out.println( toHex(signatures[i] , signatureLens[i].value) );
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
       * Note that we are not using CryptokiEx and we are not checking the return
       * value. This is because if we did not log in then an error will be reported -
       * and we don't really care because we are shutting down.
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
   *
   * @param pairCount                     number of private keys to put into/expect from blob
   * @param genKeysAndWriteToBlobToFile   generate the keys then extract to blob and write this blob to a file
   * @param readBlobFromFile              read in the blob from a file
   */
  void doSIMPKATestUseCase(int pairCount , boolean genKeysAndWriteToBlobToFile , boolean readBlobFromFile) {

    System.out.println("doSIMPKATestUseCase");
    // java fflush
    System.out.flush();

    if ( !genKeysAndWriteToBlobToFile && !readBlobFromFile ) {
      System.out.println("doSIMPKATestUseCase: One of the bools must be true");
      System.exit(1);
    }

    try {
      /*
       * Initialize Cryptoki so that the library takes care of multithread locking
       */
      CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));

      /*
       * Open a session
       */
      CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null, session);

      /*
       * Login - if we have a password
       */
      if (password.length() > 0) {
        CryptokiEx.C_Login(session, CKU.USER, password.getBytes(), password.length());

        bPrivate = true;
      }

      find(session);

      int objCount = pairCount * 1;

      // SIM vars
      long authSecretCount = 0;// n
      long authSubsetCount = 0;// m
      long authForm = CK.SIM_NO_AUTHORIZATION;
      int[] authSecretSizes = null;
      byte[][] authSecretList = null;
      byte[] blob = null;
      CK_RV rv = new CK_RV(0);

      CK_OBJECT_HANDLE[] objectHandles = new CK_OBJECT_HANDLE[objCount];
      CK_OBJECT_HANDLE hPublicKey = new CK_OBJECT_HANDLE();
      CK_OBJECT_HANDLE hPrivateKey = new CK_OBJECT_HANDLE();
      String fn = "./blob" + objCount + ".bin";

      if (genKeysAndWriteToBlobToFile) {
        System.out.print("generating " + pairCount + " key pairs...");
        System.out.flush();
        for (int ctr = 0; ctr < objCount; ctr++) {
          keyName = "bob" + ctr;
          generateKeyPair(session, CKM.RSA_PKCS_KEY_PAIR_GEN, keyName, bPrivate, hPublicKey, hPrivateKey, true);

          objectHandles[ctr] = new CK_OBJECT_HANDLE(hPrivateKey.longValue());
          //perhaps you don't care about the public key don't and need it to be in the HSM
          //objectHandles[ctr + 1] = new CK_OBJECT_HANDLE(hPublicKey.longValue());
        }
        System.out.println("done");
        System.out.flush();

        //extract all private keys
        System.out.print("dumping " + pairCount + " key pairs to " + fn + " blob file..");
        System.out.flush();
        blob = null;
        LongRef blobLenL = new LongRef(0);
        long handleCount = objCount;
        boolean deleteAfterExtract = true;

        rv = CryptokiEx.CA_SIMExtract(session, handleCount, objectHandles, authSecretCount, authSubsetCount, authForm,
            authSecretSizes, authSecretList, deleteAfterExtract, blobLenL, blob);

        blob = new byte[(int) (blobLenL.value)];

        rv = CryptokiEx.CA_SIMExtract(session, handleCount, objectHandles, authSecretCount, authSubsetCount, authForm,
            authSecretSizes, authSecretList, deleteAfterExtract, blobLenL, blob);

        FileOutputStream fos;
        try {
          fos = new FileOutputStream(fn);
          fos.write(blob);
          fos.close();
        } catch (Exception e) {
          // TODO Auto-generated catch block
          e.printStackTrace();
          System.exit(1);
        }

        System.out.println("done");
        System.out.flush();

      }

      if (readBlobFromFile) {
        File file = new File(fn);
        FileInputStream fin = null;
        try {
          // create FileInputStream object
          fin = new FileInputStream(file);

          blob = new byte[(int) file.length()];

          // Reads up to certain bytes of data from this input stream into an array of
          // bytes.
          System.out.print("reading in " + fn + "...");
          System.out.flush();
          fin.read(blob);
          System.out.println("done");
          System.out.flush();
        } catch (FileNotFoundException e) {
          System.out.println("File not found" + e);
          System.exit(1);
        } catch (IOException ioe) {
          System.out.println("Exception while reading file " + ioe);
          System.exit(1);
        } finally {
          // close the streams using close method
          try {
            if (fin != null) {
              fin.close();
            }
          } catch (IOException ioe) {
            System.out.println("Error while closing stream: " + ioe);
            System.exit(1);
          }
        }
      }

      // insert all key private keys
      LongRef handleCountL = new LongRef(0);
      objectHandles = null;
      long blobLen = blob.length;

      CryptokiEx.CA_SIMInsert(session, authSubsetCount, authForm, authSecretSizes, authSecretList, blobLen, blob,
          handleCountL, objectHandles);

      objectHandles = new CK_OBJECT_HANDLE[(int) (handleCountL.value)];
      for (int i = 0; i < objectHandles.length; i++) {
        objectHandles[i] = new CK_OBJECT_HANDLE(0);
      }

      CryptokiEx.CA_SIMInsert(session, authSubsetCount, authForm, authSecretSizes, authSecretList, blobLen, blob,
          handleCountL, objectHandles);

      // open new session and authorize key in that session...create map linking key
      // handle to authorized session
      Map<CK_OBJECT_HANDLE, CK_SESSION_HANDLE> authSessions = new HashMap<>();
      for (int i = 0; i < objectHandles.length; i++) {
        CK_SESSION_HANDLE tempSession = new CK_SESSION_HANDLE();
        CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null, tempSession);
        CryptokiEx.CA_ResetAuthorizationData(tempSession, objectHandles[i], "ijklmnop".getBytes());
        //assign to a specific user with a password...assigned key cannot be reset
        CryptokiEx.CA_AssignKey(tempSession, objectHandles[i]);
        CryptokiEx.CA_AuthorizeKey(tempSession, objectHandles[i], "ijklmnop".getBytes());
        CryptokiEx.CA_SetAuthorizationData(tempSession, objectHandles[i], "ijklmnop".getBytes(), "qrstuvwx".getBytes());
        //change auth data thus must authorize session again
        CryptokiEx.CA_AuthorizeKey(tempSession, objectHandles[i], "qrstuvwx".getBytes());
        //the following call is just there to show how to use this API call
        CryptokiEx.CA_IncrementFailedAuthCount(tempSession, objectHandles[i]);
        authSessions.put(objectHandles[i], tempSession);
      }

      System.out.print("starting to sign...");
      System.out.flush();

      // Test data for sign/verify
      String startString = new String("0123456789ABCDEF");
      byte[] OrigPlainText = startString.getBytes();

      CK_MECHANISM mech = new CK_MECHANISM();
      mech.mechanism = CKM.RSA_PKCS;
      mech.pParameter = null;
      mech.parameterLen = 0;

      // now, randomly loop thru keys and sign with authorized session
      for (int i = 0; i < objectHandles.length; i++) {
        Random rn = new Random();
        int randomKey = rn.nextInt(objCount);

        // System.out.println("signing with key: " + randomKey);
        // System.out.flush();

        long start = System.nanoTime();
        CK_OBJECT_HANDLE tempKey = objectHandles[randomKey];
        CK_SESSION_HANDLE tempSession = authSessions.get(tempKey);

        LongRef lRefSign = new LongRef();
        byte[] signature = null;
        CryptokiEx.C_SignInit(tempSession, mech, tempKey);
        CryptokiEx.C_SignUpdate(tempSession, OrigPlainText, OrigPlainText.length);
        CryptokiEx.C_SignFinal(tempSession, null, lRefSign);
        signature = new byte[(int) lRefSign.value];
        CryptokiEx.C_SignFinal(tempSession, signature, lRefSign);
        long end = System.nanoTime();
        double duration = (end - start) / 1000000.0;

        // System.out.println("duration:" + duration + "ms");
        // System.out.flush();
      }

      System.out.println("done");
      System.out.flush();

      // destroy all inserted key pairs...no need if session objects

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
       * Note that we are not using CryptokiEx and we are not checking the return
       * value. This is because if we did not log in then an error will be reported -
       * and we don't really care because we are shutting down.
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
   *
   */
  void doSIMPKAPerfTest() {

    System.out.println("doSIMPKAPerfTest");
    // java fflush
    System.out.flush();

    try {
      /*
       * Initialize Cryptoki so that the library takes care of multithread locking
       */
      CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));

      /*
       * Open a session
       */
      CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null, session);

      /*
       * Login - if we have a password
       */
      if (password.length() > 0) {
        CryptokiEx.C_Login(session, CKU.USER, password.getBytes(), password.length());

        bPrivate = true;
      }

      find(session);

      int objCount =  1;

      // SIM vars
      long authSecretCount = 0;// n
      long authSubsetCount = 0;// m
      long authForm = CK.SIM_NO_AUTHORIZATION;
      int[] authSecretSizes = null;
      byte[][] authSecretList = null;
      byte[] blob = null;
      CK_RV rv = new CK_RV(0);

      CK_OBJECT_HANDLE[] objectHandles = new CK_OBJECT_HANDLE[objCount];
      CK_OBJECT_HANDLE hPublicKey = new CK_OBJECT_HANDLE();
      CK_OBJECT_HANDLE hPrivateKey = new CK_OBJECT_HANDLE();
      String fn = "./blob" + objCount + ".bin";

      System.out.print("generating " + 1 + " key pairs...");
      System.out.flush();
      for (int ctr = 0; ctr < objCount; ctr++) {
        keyName = "bob" + ctr;
        generateKeyPair(session, CKM.RSA_PKCS_KEY_PAIR_GEN, keyName, bPrivate, hPublicKey, hPrivateKey, true);

        objectHandles[ctr] = new CK_OBJECT_HANDLE(hPrivateKey.longValue());
        // perhaps you don't care about the public key don't and need it to be in the
        // HSM
        // objectHandles[ctr + 1] = new CK_OBJECT_HANDLE(hPublicKey.longValue());
      }
      System.out.println("done");
      System.out.flush();

      // extract all private keys
      System.out.print("dumping " + 1 + " key pairs to " + fn + " blob file..");
      System.out.flush();
      blob = null;
      LongRef blobLenL = new LongRef(0);
      long handleCount = objCount;
      boolean deleteAfterExtract = true;

      rv = CryptokiEx.CA_SIMExtract(session, handleCount, objectHandles, authSecretCount, authSubsetCount, authForm,
          authSecretSizes, authSecretList, deleteAfterExtract, blobLenL, blob);

      blob = new byte[(int) (blobLenL.value)];

      rv = CryptokiEx.CA_SIMExtract(session, handleCount, objectHandles, authSecretCount, authSubsetCount, authForm,
          authSecretSizes, authSecretList, deleteAfterExtract, blobLenL, blob);

      FileOutputStream fos;
      try {
        fos = new FileOutputStream(fn);
        fos.write(blob);
        fos.close();
      } catch (Exception e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
        System.exit(1);
      }

      System.out.println("done");
      System.out.flush();

      File file = new File(fn);
      FileInputStream fin = null;
      try {
        // create FileInputStream object
        fin = new FileInputStream(file);

        blob = new byte[(int) file.length()];

        // Reads up to certain bytes of data from this input stream into an array of
        // bytes.
        System.out.print("reading in " + fn + "...");
        System.out.flush();
        fin.read(blob);
        System.out.println("done");
        System.out.flush();
      } catch (FileNotFoundException e) {
        System.out.println("File not found" + e);
        System.exit(1);
      } catch (IOException ioe) {
        System.out.println("Exception while reading file " + ioe);
        System.exit(1);
      } finally {
        // close the streams using close method
        try {
          if (fin != null) {
            fin.close();
          }
        } catch (IOException ioe) {
          System.out.println("Error while closing stream: " + ioe);
          System.exit(1);
        }
      }

      for ( int ctr = 0; ctr <= 100 ; ctr++ ) {
        long start = System.nanoTime();

        // insert all key private keys
        LongRef handleCountL = new LongRef(0);
        objectHandles = null;
        long blobLen = blob.length;

        CryptokiEx.CA_SIMInsert(session, authSubsetCount, authForm, authSecretSizes, authSecretList, blobLen, blob,
            handleCountL, objectHandles);

        objectHandles = new CK_OBJECT_HANDLE[(int) (handleCountL.value)];
        for (int i = 0; i < objectHandles.length; i++) {
          objectHandles[i] = new CK_OBJECT_HANDLE(0);
        }

        CryptokiEx.CA_SIMInsert(session, authSubsetCount, authForm, authSecretSizes, authSecretList, blobLen, blob,
            handleCountL, objectHandles);

        // open new session and authorize key in that session...create map linking key
        // handle to authorized session
        Map<CK_OBJECT_HANDLE, CK_SESSION_HANDLE> authSessions = new HashMap<>();
        for (int i = 0; i < objectHandles.length; i++) {
          CK_SESSION_HANDLE tempSession = new CK_SESSION_HANDLE();
          CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null, tempSession);
          CryptokiEx.CA_AuthorizeKey(tempSession, objectHandles[i], "abcdefgh".getBytes());
          authSessions.put(objectHandles[i], tempSession);
        }

//        System.out.print("starting to sign...");
//        System.out.flush();

        // Test data for sign/verify
        String startString = new String("0123456789ABCDEF");
        byte[] OrigPlainText = startString.getBytes();

        CK_MECHANISM mech = new CK_MECHANISM();
        mech.mechanism = CKM.RSA_PKCS;
        mech.pParameter = null;
        mech.parameterLen = 0;

        // now, randomly loop thru keys and sign with authorized session
        for (int i = 0; i < objectHandles.length; i++) {
          Random rn = new Random();
          int randomKey = rn.nextInt(objCount);

          // System.out.println("signing with key: " + randomKey);
          // System.out.flush();

          //long start = System.nanoTime();
          CK_OBJECT_HANDLE tempKey = objectHandles[randomKey];
          CK_SESSION_HANDLE tempSession = authSessions.get(tempKey);

          LongRef lRefSign = new LongRef();
          byte[] signature = null;
          CryptokiEx.C_SignInit(tempSession, mech, tempKey);
          CryptokiEx.C_SignUpdate(tempSession, OrigPlainText, OrigPlainText.length);
          CryptokiEx.C_SignFinal(tempSession, null, lRefSign);
          signature = new byte[(int) lRefSign.value];
          CryptokiEx.C_SignFinal(tempSession, signature, lRefSign);
          long end = System.nanoTime();
          double duration = (end - start) / 1000000.0;

//          System.out.println("done");
//          System.out.flush();

          CryptokiEx.C_DestroyObject(tempSession, tempKey);

           System.out.println("duration:" + duration + "ms");
           System.out.flush();
        }
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
       * Note that we are not using CryptokiEx and we are not checking the return
       * value. This is because if we did not log in then an error will be reported -
       * and we don't really care because we are shutting down.
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
   *
   * @param value   1 (to start rollover) or 0 (to end rollover)
   */
  void doSMKRollover(int value) {

    System.out.println("doSMKRollover");

    try {
      /*
       * Initialize Cryptoki so that the library takes care of multithread locking
       */
      CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));

      /*
       * Open a session
       */
      CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null, session);

      /*
       * Login - if we have a password
       */
      if (password.length() > 0) {
        CryptokiEx.C_Login(session, CKU.USER, password.getBytes(), password.length());

        bPrivate = true;
      }

      CryptokiEx.CA_SMKRollover(session, value);

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
       * Note that we are not using CryptokiEx and we are not checking the return
       * value. This is because if we did not log in then an error will be reported -
       * and we don't really care because we are shutting down.
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
   * toHex.
   */
  public static String toHex(byte[] digest, long length) {
    String digits = "0123456789abcdef";
    StringBuilder sb = new StringBuilder((int)length * 2);
    for ( int i=0 ; i < length ; i++) {
    //for (byte b : digest) {
      int bi = digest[i] & 0xff;
      sb.append(digits.charAt(bi >> 4));
      sb.append(digits.charAt(bi & 0xf));
    }
    return sb.toString();
  }

  public static void find(CK_SESSION_HANDLE session) {

    CK_OBJECT_HANDLE[] hObjects = { new CK_OBJECT_HANDLE() };
    LongRef objectCount = new LongRef();
    CK_ATTRIBUTE[] template = {
        //empty template\ means find anything at all
        // new CK_ATTRIBUTE(CKA.CLASS, CKO.PRIVATE_KEY),
        // new CK_ATTRIBUTE(CKA.KEY_TYPE, keyType),
        // new CK_ATTRIBUTE(CKA.TOKEN, CK_BBOOL.TRUE),
        // new CK_ATTRIBUTE(CKA.LABEL, keyName.getBytes()),
        // new CK_ATTRIBUTE(CKA.PRIVATE, new CK_BBOOL(bPrivate))
    };

    hObjects = new CK_OBJECT_HANDLE[100];
    for (int i = 0; i < hObjects.length; i++) {
      hObjects[i] = new CK_OBJECT_HANDLE(0);
    }

    CryptokiEx.C_FindObjectsInit(session, template, template.length);

    CryptokiEx.C_FindObjects(session, hObjects, hObjects.length, objectCount);

    CryptokiEx.C_FindObjectsFinal(session);

    System.out.printf("all objects found on the partition: %d\n", objectCount.value);
    //perhaps you might want to display all the handles...or not
    //for (int i = 0; i < objectCount.value; i++) {
    //  System.out.println(hObjects[i].longValue());
    //}

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
      } else if (args[i].equalsIgnoreCase("-keyName")) {
        if (++i >= args.length)
          usage();

        keyName = args[i];
      } else {
        usage();
      }
    }

    System.out.println("**************************************************************************");
    System.out.flush();

    SKSPKASample aSample = new SKSPKASample();

    //create new SMK but don't remove the old one yet
    //aSample.doSMKRollover(1);

    aSample.doSIM();

    aSample.doSIMMultiSign();

    aSample.doSIMPKATestUseCase(35,true,true);

    aSample.doSIMPKAPerfTest();

    //commit to new SMK and delete the old one thus blobs created with the old key
    //can no longer be inserted
    //aSample.doSMKRollover(0);

  }

}
