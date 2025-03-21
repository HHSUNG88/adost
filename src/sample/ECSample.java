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
import com.safenetinc.jcprov.constants.CKDHP;
import com.safenetinc.jcprov.constants.CKES;
import com.safenetinc.jcprov.constants.CKF;
import com.safenetinc.jcprov.constants.CKG;
import com.safenetinc.jcprov.constants.CKK;
import com.safenetinc.jcprov.constants.CKM;
import com.safenetinc.jcprov.constants.CKMS;
import com.safenetinc.jcprov.constants.CKO;
import com.safenetinc.jcprov.constants.CKU;
import com.safenetinc.jcprov.constants.KDF;
import com.safenetinc.jcprov.params.CK_AES_CTR_PARAMS;
import com.safenetinc.jcprov.params.CK_AES_GCM_PARAMS;
import com.safenetinc.jcprov.params.CK_ECIES_PARAMS;
import com.safenetinc.jcprov.params.CK_ECIES_PARAMS_EXT;
import com.safenetinc.jcprov.params.CK_RSA_PKCS_PSS_PARAMS;

/**
 * This class demonstrates various EC-based mechanisms
 * <p>
 * Usage : java ECIESExtSample [-slot &lt;slotId&gt;] [-password &lt;password&gt;]
 *
 * <li><i>slotId</i>   slot containing the token.
 * <li><i>password</i> user password of the slot.
 *
 */
public class ECSample
{
  static public void println(String s) {
    System.out.println(s);
  }

  /** display runtime usage of the class */
  public static void usage() {
    println("java ...ECSample -slot <slotId> -password <password>\n");
    println("");

    System.exit(1);
  }

  // IV
  private static byte[] iv = {0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0x0,0x1,0x2};

  CK_OBJECT_HANDLE hPublicKey = new CK_OBJECT_HANDLE();
  CK_OBJECT_HANDLE hPrivateKey = new CK_OBJECT_HANDLE();

  static CK_ATTRIBUTE [] publicTemplate = {
    new CK_ATTRIBUTE (CKA.CLASS, CKO.PUBLIC_KEY),
    new CK_ATTRIBUTE (CKA.TOKEN, CK_BBOOL.FALSE),
    new CK_ATTRIBUTE (CKA.DERIVE, CK_BBOOL.TRUE),
    new CK_ATTRIBUTE (CKA.PRIVATE, CK_BBOOL.TRUE),
    new CK_ATTRIBUTE (CKA.ENCRYPT, CK_BBOOL.TRUE),
    new CK_ATTRIBUTE (CKA.VERIFY, CK_BBOOL.TRUE),
    new CK_ATTRIBUTE (CKA.WRAP, CK_BBOOL.TRUE),
//      0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A,                         /* [70] OID_secp256k1 */
    new CK_ATTRIBUTE (CKA.ECDSA_PARAMS, new byte[] { (byte)0x06, (byte)0x05,
        (byte)0x2B, (byte)0x81, (byte)0x04, (byte)0x00, (byte)0x0A } ),
    new CK_ATTRIBUTE (CKA.LABEL, "pubKey".getBytes())
  };

  static CK_ATTRIBUTE [] privateTemplate = {
    new CK_ATTRIBUTE (CKA.CLASS, CKO.PRIVATE_KEY),
    new CK_ATTRIBUTE (CKA.TOKEN, CK_BBOOL.FALSE),
    new CK_ATTRIBUTE (CKA.PRIVATE, CK_BBOOL.TRUE),
    new CK_ATTRIBUTE (CKA.SENSITIVE, CK_BBOOL.TRUE),
    new CK_ATTRIBUTE (CKA.DERIVE, CK_BBOOL.TRUE),
    new CK_ATTRIBUTE (CKA.DERIVE, CK_BBOOL.TRUE),
    new CK_ATTRIBUTE (CKA.UNWRAP, CK_BBOOL.TRUE),
    new CK_ATTRIBUTE (CKA.DECRYPT, CK_BBOOL.TRUE),
    new CK_ATTRIBUTE (CKA.EXTRACTABLE, CK_BBOOL.TRUE),
    new CK_ATTRIBUTE (CKA.SIGN, CK_BBOOL.TRUE),
    new CK_ATTRIBUTE (CKA.LABEL, "privKey".getBytes())
  };

  private CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
  private static long slotId = 1;
  private static String password = "userpin1";
  private Long MacScheme = 0L;

  void performSHA3ECTask()
  {

    System.out.println("\nperformSHA3ECTask\n");

    try {

      CK_MECHANISM mech = new CK_MECHANISM(CKM.ECDSA_SHA3_256, null);

      // Test data for sign/verify
      String startString = new String("0123456789ABCDEF");
      byte[] OrigPlainText = startString.getBytes();
      LongRef lRefSign = new LongRef();
      byte [] signature = null;

      CryptokiEx.C_SignInit(session, mech, hPrivateKey);
      CryptokiEx.C_SignUpdate(session, OrigPlainText, OrigPlainText.length);
      CryptokiEx.C_SignFinal(session, null, lRefSign);
      signature = new byte [(int)lRefSign.value];
      CryptokiEx.C_SignFinal(session, signature, lRefSign);
      System.out.println("C_SignFinal");

      CryptokiEx.C_VerifyInit(session, mech, hPublicKey);
      CryptokiEx.C_VerifyUpdate(session, OrigPlainText, OrigPlainText.length);
      CryptokiEx.C_VerifyFinal(session, signature, signature.length);
      System.out.println("C_VerifyFinal");

    } catch (CKR_Exception ex) {
      /*
       * A Cryptoki related exception was thrown
       */
      ex.printStackTrace();
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

  void performEciesXORTask()
  {

    System.out.println("\nperformEciesXORTask\n");

    try {

      CK_ECIES_PARAMS ECIESParams = new CK_ECIES_PARAMS(
          CKDHP.ECDH1_COFACTOR,
          KDF.CKD_SHA256_KDF,
          0,
          null,
          CKES.XOR,
          0,//XOR 0-length key
          CKMS.HMAC_SHA256,
          256,
          256,
          0,
          null);

      CK_ECIES_PARAMS_EXT ECIESParamsExt = new CK_ECIES_PARAMS_EXT(
          ECIESParams,
          null,
          0);

      CK_MECHANISM mech = new CK_MECHANISM(CKM.ECIES, ECIESParamsExt);

      long bufSize = 16;
      // Create plaintext with that buffer size.
      char[] fillBytes = new char[(int) bufSize];
      // Fill chars
      Arrays.fill(fillBytes, 'a');
      String ByteString = new String(fillBytes);
      byte[] plainText = ByteString.getBytes();

      CryptokiEx.C_EncryptInit(session, mech, hPublicKey);

      // Get the size for cipherText
      LongRef sizeForEnc = new LongRef(0);
      CryptokiEx.C_Encrypt(session, plainText,
          plainText.length, null, sizeForEnc);
      System.out.println("C_Encrypt initial size:" + sizeForEnc.value);

      /* allocate space for returned cipherText based upon sizeForEnc */
      byte[] cipherText = new byte[(int) sizeForEnc.value ];

      CryptokiEx.C_Encrypt(session, plainText,
          plainText.length, cipherText, sizeForEnc);
      System.out.println("C_Encrypt final size:" + sizeForEnc.value);

      CryptokiEx.C_DecryptInit(session, mech, hPrivateKey);

      // Get the size for cipherText
      LongRef sizeForDec  = new LongRef(0);
      CryptokiEx.C_Decrypt(session, cipherText,
          cipherText.length, null, sizeForDec);
      System.out.println("C_Decrypt initial size:" + sizeForDec.value);

      /* allocate space for returned cipherText based upon sizeForEnc */
      plainText = new byte[(int) sizeForDec.value ];

      CryptokiEx.C_Decrypt(session, cipherText,
          cipherText.length, plainText, sizeForDec);
      System.out.println("C_Decrypt final size:" + sizeForDec.value);

    } catch (CKR_Exception ex) {
      /*
       * A Cryptoki related exception was thrown
       */
      ex.printStackTrace();
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

  void performEciesAESCTRTask()
  {

    System.out.println("\nperformEciesAESCTRTask\n");

    try {

//      iv = new byte[] { (byte)1,(byte)2,(byte)3,(byte)4,(byte)5,(byte)6,(byte)7,(byte)8,(byte)9,(byte)10,(byte)11,(byte)12,(byte)13,(byte)14,(byte)15,(byte)16 };
      CK_AES_CTR_PARAMS ctrParams = new CK_AES_CTR_PARAMS(iv, 128L);

      CK_ECIES_PARAMS ECIESParams = new CK_ECIES_PARAMS(
          CKDHP.ECDH1_COFACTOR,
          KDF.CKD_SHA256_KDF,
          0,
          null,
          CKES.AES_CTR,
          256,
          CKMS.HMAC_SHA256,
          256,
          256,
          0,
          null);

      CK_ECIES_PARAMS_EXT ECIESParamsExt = new CK_ECIES_PARAMS_EXT(
          ECIESParams,
          ctrParams,
          0);

      CK_MECHANISM mech = new CK_MECHANISM(CKM.ECIES, ECIESParamsExt);

      long bufSize = 16;
      // Create plaintext with that buffer size.
      char[] fillBytes = new char[(int) bufSize];
      // Fill chars
      Arrays.fill(fillBytes, 'a');
      String ByteString = new String(fillBytes);
      byte[] plainText = ByteString.getBytes();

      CryptokiEx.C_EncryptInit(session, mech, hPublicKey);

      // Get the size for cipherText
      LongRef sizeForEnc = new LongRef(0);
      CryptokiEx.C_Encrypt(session, plainText,
          plainText.length, null, sizeForEnc);
      System.out.println("C_Encrypt initial size:" + sizeForEnc.value);

      /* allocate space for returned cipherText based upon sizeForEnc */
      byte[] cipherText = new byte[(int) sizeForEnc.value ];

      CryptokiEx.C_Encrypt(session, plainText,
          plainText.length, cipherText, sizeForEnc);
      System.out.println("C_Encrypt final size:" + sizeForEnc.value);

      CryptokiEx.C_DecryptInit(session, mech, hPrivateKey);

      // Get the size for cipherText
      LongRef sizeForDec  = new LongRef(0);
      CryptokiEx.C_Decrypt(session, cipherText,
          cipherText.length, null, sizeForDec);
      System.out.println("C_Decrypt initial size:" + sizeForDec.value);

      /* allocate space for returned cipherText based upon sizeForEnc */
      plainText = new byte[(int) sizeForDec.value ];

      CryptokiEx.C_Decrypt(session, cipherText,
          cipherText.length, plainText, sizeForDec);
      System.out.println("C_Decrypt final size:" + sizeForDec.value);

    } catch (CKR_Exception ex) {
      /*
       * A Cryptoki related exception was thrown
       */
      ex.printStackTrace();
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

  void performEciesAESCTRNullParmTask()
  {

    System.out.println("\nperformEciesAESCTRNullParmTask\n");

    try {

      CK_ECIES_PARAMS ECIESParams = new CK_ECIES_PARAMS(
          CKDHP.ECDH1_COFACTOR,
          KDF.CKD_SHA256_KDF,
          0,
          null,
          CKES.AES_CTR,
          256,
          CKMS.HMAC_SHA256,
          256,
          256,
          0,
          null);

      CK_ECIES_PARAMS_EXT ECIESParamsExt = new CK_ECIES_PARAMS_EXT(
          ECIESParams,
          null,
          0);

      CK_MECHANISM mech = new CK_MECHANISM(CKM.ECIES, ECIESParamsExt);

      long bufSize = 16;
      // Create plaintext with that buffer size.
      char[] fillBytes = new char[(int) bufSize];
      // Fill chars
      Arrays.fill(fillBytes, 'a');
      String ByteString = new String(fillBytes);
      byte[] plainText = ByteString.getBytes();

      CryptokiEx.C_EncryptInit(session, mech, hPublicKey);

      // Get the size for cipherText
      LongRef sizeForEnc = new LongRef(0);
      CryptokiEx.C_Encrypt(session, plainText,
          plainText.length, null, sizeForEnc);
      System.out.println("C_Encrypt initial size:" + sizeForEnc.value);

      /* allocate space for returned cipherText based upon sizeForEnc */
      byte[] cipherText = new byte[(int) sizeForEnc.value ];

      CryptokiEx.C_Encrypt(session, plainText,
          plainText.length, cipherText, sizeForEnc);
      System.out.println("C_Encrypt final size:" + sizeForEnc.value);

      CryptokiEx.C_DecryptInit(session, mech, hPrivateKey);

      // Get the size for cipherText
      LongRef sizeForDec  = new LongRef(0);
      CryptokiEx.C_Decrypt(session, cipherText,
          cipherText.length, null, sizeForDec);
      System.out.println("C_Decrypt initial size:" + sizeForDec.value);

      /* allocate space for returned cipherText based upon sizeForEnc */
      plainText = new byte[(int) sizeForDec.value ];

      CryptokiEx.C_Decrypt(session, cipherText,
          cipherText.length, plainText, sizeForDec);
      System.out.println("C_Decrypt final size:" + sizeForDec.value);

    } catch (CKR_Exception ex) {
      /*
       * A Cryptoki related exception was thrown
       */
      ex.printStackTrace();
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

  void performEciesAESGCMTask()
  {

    System.out.println("\nperformEciesAESGCMTask\n");

    try {

      //create AES GCM parameters
      String aad = "AAAD";
      // Generate tag bits size
      int tagBits = 128;

//      iv = new byte[] { (byte)1,(byte)2,(byte)3,(byte)4,(byte)5,(byte)6,(byte)7,(byte)8 };
      CK_AES_GCM_PARAMS gcmParams = new CK_AES_GCM_PARAMS(
          iv,
          aad.getBytes(),
          tagBits);

      CK_ECIES_PARAMS ECIESParams = new CK_ECIES_PARAMS(
          CKDHP.ECDH1_COFACTOR,
          KDF.CKD_SHA256_KDF,
          0,
          null,
          CKES.AES_GCM,
          256,
          MacScheme,
          256,
          256,
          0,
          null);

      CK_ECIES_PARAMS_EXT ECIESParamsExt = new CK_ECIES_PARAMS_EXT(
          ECIESParams,
          gcmParams,
          0);

      CK_MECHANISM mech = new CK_MECHANISM(CKM.ECIES, ECIESParamsExt);

      long bufSize = 16;
      // Create plaintext with that buffer size.
      char[] fillBytes = new char[(int) bufSize];
      // Fill chars
      Arrays.fill(fillBytes, 'a');
      String ByteString = new String(fillBytes);
      byte[] plainText = ByteString.getBytes();

      CryptokiEx.C_EncryptInit(session, mech, hPublicKey);

      // Get the size for cipherText
      LongRef sizeForEnc = new LongRef(0);
      CryptokiEx.C_Encrypt(session, plainText,
          plainText.length, null, sizeForEnc);
      System.out.println("C_Encrypt initial size:" + sizeForEnc.value);

      /* allocate space for returned cipherText based upon sizeForEnc */
      byte[] cipherText = new byte[(int) sizeForEnc.value ];

      CryptokiEx.C_Encrypt(session, plainText,
          plainText.length, cipherText, sizeForEnc);
      System.out.println("C_Encrypt final size:" + sizeForEnc.value);

      CryptokiEx.C_DecryptInit(session, mech, hPrivateKey);

      // Get the size for cipherText
      LongRef sizeForDec  = new LongRef(0);
      CryptokiEx.C_Decrypt(session, cipherText,
          cipherText.length, null, sizeForDec);
      System.out.println("C_Decrypt initial size:" + sizeForDec.value);

      /* allocate space for returned cipherText based upon sizeForEnc */
      plainText = new byte[(int) sizeForDec.value ];

      CryptokiEx.C_Decrypt(session, cipherText,
          cipherText.length, plainText, sizeForDec);
      System.out.println("C_Decrypt final size:" + sizeForDec.value);

    } catch (CKR_Exception ex) {
      /*
       * A Cryptoki related exception was thrown
       */
      ex.printStackTrace();
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

  void performEciesAESKWTask()
  {

    System.out.println("\nperformEciesAESKWTask\n");

    try {

      CK_ECIES_PARAMS ECIESParams = new CK_ECIES_PARAMS(
          CKDHP.ECDH1_COFACTOR,
          KDF.CKD_SHA256_KDF,
          0,
          null,
          CKES.AES_KW,
          256,
          CKMS.HMAC_SHA256,
          256,
          256,
          0,
          null);

//      iv = new byte[] { (byte)1,(byte)2,(byte)3,(byte)4,(byte)5,(byte)6,(byte)7,(byte)8 };
      CK_ECIES_PARAMS_EXT ECIESParamsExt = new CK_ECIES_PARAMS_EXT(
          ECIESParams,
          iv,
          0);

      CK_MECHANISM mech = new CK_MECHANISM(CKM.ECIES, ECIESParamsExt);

      long bufSize = 16;
      // Create plaintext with that buffer size.
      char[] fillBytes = new char[(int) bufSize];
      // Fill chars
      Arrays.fill(fillBytes, 'a');
      String ByteString = new String(fillBytes);
      byte[] plainText = ByteString.getBytes();

      CryptokiEx.C_EncryptInit(session, mech, hPublicKey);

      // Get the size for cipherText
      LongRef sizeForEnc = new LongRef(0);
      CryptokiEx.C_Encrypt(session, plainText,
          plainText.length, null, sizeForEnc);
      System.out.println("C_Encrypt initial size:" + sizeForEnc.value);

      /* allocate space for returned cipherText based upon sizeForEnc */
      byte[] cipherText = new byte[(int) sizeForEnc.value ];

      CryptokiEx.C_Encrypt(session, plainText,
          plainText.length, cipherText, sizeForEnc);
      System.out.println("C_Encrypt final size:" + sizeForEnc.value);

      CryptokiEx.C_DecryptInit(session, mech, hPrivateKey);

      // Get the size for cipherText
      LongRef sizeForDec  = new LongRef(0);
      CryptokiEx.C_Decrypt(session, cipherText,
          cipherText.length, null, sizeForDec);
      System.out.println("C_Decrypt initial size:" + sizeForDec.value);

      /* allocate space for returned cipherText based upon sizeForEnc */
      plainText = new byte[(int) sizeForDec.value ];

      CryptokiEx.C_Decrypt(session, cipherText,
          cipherText.length, plainText, sizeForDec);
      System.out.println("C_Decrypt final size:" + sizeForDec.value);

    } catch (CKR_Exception ex) {
      /*
       * A Cryptoki related exception was thrown
       */
      ex.printStackTrace();
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

  void performEciesAESKWPTask()
  {

    System.out.println("\nperformEciesAESKWPTask\n");

    try {

      CK_ECIES_PARAMS ECIESParams = new CK_ECIES_PARAMS(
          CKDHP.ECDH1_COFACTOR,
          KDF.CKD_SHA256_KDF,
          0,
          null,
          CKES.AES_KWP,
          256,
          CKMS.HMAC_SHA256,
          256,
          256,
          0,
          null);

      CK_ECIES_PARAMS_EXT ECIESParamsExt = new CK_ECIES_PARAMS_EXT(
          ECIESParams,
          iv,
          0);

      CK_MECHANISM mech = new CK_MECHANISM(CKM.ECIES, ECIESParamsExt);

      long bufSize = 16;
      // Create plaintext with that buffer size.
      char[] fillBytes = new char[(int) bufSize];
      // Fill chars
      Arrays.fill(fillBytes, 'a');
      String ByteString = new String(fillBytes);
      byte[] plainText = ByteString.getBytes();

      CryptokiEx.C_EncryptInit(session, mech, hPublicKey);

      // Get the size for cipherText
      LongRef sizeForEnc = new LongRef(0);
      CryptokiEx.C_Encrypt(session, plainText,
          plainText.length, null, sizeForEnc);
      System.out.println("C_Encrypt initial size:" + sizeForEnc.value);

      /* allocate space for returned cipherText based upon sizeForEnc */
      byte[] cipherText = new byte[(int) sizeForEnc.value ];

      CryptokiEx.C_Encrypt(session, plainText,
          plainText.length, cipherText, sizeForEnc);
      System.out.println("C_Encrypt final size:" + sizeForEnc.value);

      CryptokiEx.C_DecryptInit(session, mech, hPrivateKey);

      // Get the size for cipherText
      LongRef sizeForDec  = new LongRef(0);
      CryptokiEx.C_Decrypt(session, cipherText,
          cipherText.length, null, sizeForDec);
      System.out.println("C_Decrypt initial size:" + sizeForDec.value);

      /* allocate space for returned cipherText based upon sizeForEnc */
      plainText = new byte[(int) sizeForDec.value ];

      CryptokiEx.C_Decrypt(session, cipherText,
          cipherText.length, plainText, sizeForDec);
      System.out.println("C_Decrypt final size:" + sizeForDec.value);

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

      CK_MECHANISM keyGenMech = new CK_MECHANISM(CKM.ECDSA_KEY_PAIR_GEN);

      System.out.println("C_GenerateKeyPair session object started");

      CryptokiEx.C_GenerateKeyPair(session, keyGenMech,
          publicTemplate, publicTemplate.length,
          privateTemplate, privateTemplate.length,
          hPublicKey, hPrivateKey);

      System.out.println("C_GenerateKeyPair session object completed");

    } catch (CKR_Exception ex) {
      /*
       * A Cryptoki related exception was thrown
       */
      ex.printStackTrace();
    } catch (Exception ex) {
      ex.printStackTrace();
    }

    //accommodate different FW versions
    String featureFwVer = "7.7.2";
    Long[] tokenFWVersion;
    Long[] featureInFWVersion = new Long[3];
    LongRef major = new LongRef();
    LongRef minor = new LongRef();
    LongRef subminor = new LongRef();
    CryptokiEx.CA_GetFirmwareVersion(slotId, major, minor, subminor);
    tokenFWVersion = new Long[]{major.value, minor.value, subminor.value};
    // Break the given firmware version into a Long[] for later comparison.
    int i = 0;
    for (String s : featureFwVer.split("\\.", 3)) {
        featureInFWVersion[i++] = Long.parseLong(s);
    }
    if (( tokenFWVersion[0] <  featureInFWVersion[0] )  // is hsm major version older than feature
     || ( tokenFWVersion[0] == featureInFWVersion[0]    // Assuming major versions are the same.
      &&  tokenFWVersion[1] <  featureInFWVersion[1] )  // Minor version on hsm is older,
     || ( tokenFWVersion[0] == featureInFWVersion[0]
      &&  tokenFWVersion[1] == featureInFWVersion[1]    // or, minor version is the same and
      &&  tokenFWVersion[2] <  featureInFWVersion[2] )) // release is older.
    {
      // don't allow MS = 0
      System.out.println("FW<7.7.2");
      MacScheme = CKMS.HMAC_SHA256;//7.7.0 & 7.7.1
      iv = new byte[] { (byte)1,(byte)2,(byte)3,(byte)4, (byte)5,(byte)6,(byte)7,(byte)8};//7.7.0
    } else {
      // allow MS = 0
      System.out.println("FW>=7.7.2");
      MacScheme = 0L;//7.7.2
      iv = new byte[] { (byte)1,(byte)2,(byte)3,(byte)4 };//7.7.2 FW-enforced iv size
    }

  }

  void performTeardown()
  {

    try {
      // Destroy created token objects
      CryptokiEx.C_DestroyObject(session, hPublicKey);
      CryptokiEx.C_DestroyObject(session, hPrivateKey);

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

    ECSample aSample = new ECSample();
    aSample.performInit();
    aSample.performSHA3ECTask();
    aSample.performEciesXORTask();
    aSample.performEciesAESCTRTask();
    aSample.performEciesAESCTRNullParmTask();
    aSample.performEciesAESGCMTask();
    aSample.performEciesAESKWTask();
    aSample.performEciesAESKWPTask();
    aSample.performTeardown();

  }

}
