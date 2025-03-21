
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
import com.safenetinc.jcprov.params.CK_AES_GCM_PARAMS;

/**
 * This class demonstrates the encryption/decryption operations with IV/AAD/Tag
 * bits using the AES GCM mechanism.
 * <p>
 * Usage : java AesGcmSample [-slot &lt;slotId&gt;] [-password &lt;password&gt;]
 *
 * <li><i>slotId</i>   slot containing the token.
 * <li><i>password</i> user password of the slot.
 *
 */
public class AesGcmSample
{
  static public void println(String s) {
    System.out.println(s);
  }

  /** display runtime usage of the class */
  public static void usage() {
    println("java ...AesGcmSample -slot <slotId> -password <password>\n");
    println("");

    System.exit(1);
  }

  // IV
  private static byte[] iv = {0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0x0,0x1,0x2};

  // Symmetric template.
  private static String keyLabel = "AesKey";

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
      new CK_ATTRIBUTE(CKA.VALUE_LEN, 16) };


  private CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
  private static long slotId = 0;
  private static String password = "";
  private boolean bPrivate = false;

  void singlePart()
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

      CK_AES_GCM_PARAMS gcmParams = new CK_AES_GCM_PARAMS(iv, aad.getBytes(),
          tagBits);
      // Setup mechanism.
      //old FW
      //CK_MECHANISM mechanism = new CK_MECHANISM(CKM.AES_GCM_2_20a5d1, gcmParams);
      //new FW
      CK_MECHANISM mechanism = new CK_MECHANISM(CKM.AES_GCM, gcmParams);

      CK_OBJECT_HANDLE key = new CK_OBJECT_HANDLE();

      // Generate AES keys.

      CK_MECHANISM keyGenMech = new CK_MECHANISM(CKM.AES_KEY_GEN);

      CryptokiEx.C_GenerateKey(session, keyGenMech, template, template.length,
          key);



      // ***********************
      // ENCRYPTION
      // ***********************

      // Create buffer size 15K approx.
      // K6 HSM card has limit of approx. 15kB
      // K7 HSM card has limit of approx. 64kB
      long bufSize = (1024 * 15);

      // Create plaintext with that buffer size.
      char[] fillBytes = new char[(int) bufSize];
      // Fill chars
      Arrays.fill(fillBytes, 'a');
      String ByteString = new String(fillBytes);
      byte[] plainText = ByteString.getBytes();

      System.out.println(
          "\n---------------- SINGLE-PART ENC/DEC--------------------------------------------\n");

      System.out.println("Encrypting...");

      System.out.println(
          "Plaintext is setup with size: " + plainText.length + " bytes");


      /* get ready to encrypt */
      CryptokiEx.C_EncryptInit(session, mechanism, key);

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

      // ***********************
      // DECRYPTION
      // ***********************

      /* get ready to decrypt */
      System.out.println("\nDecrypting...");
      CryptokiEx.C_DecryptInit(session, mechanism, key);

      // Get the size for clearText
      LongRef sizeForDec = new LongRef(bufSize);
      System.out.println("sizeForEnc:" + sizeForEnc.value);
      System.out.println("sizeForDec:" + sizeForDec.value);
      CryptokiEx.C_Decrypt(session, cipherText,
          sizeForEnc.value, null, sizeForDec);
      System.out.println("C_Decrypt initial size:" + sizeForDec.value);
      /* allocate space for clearText based upon sizeForDec */
      byte[] clearText = new byte[(int) (sizeForDec.value)];

      CryptokiEx.C_Decrypt(session, cipherText,
          sizeForEnc.value, clearText, sizeForDec);
      System.out.println("C_Decrypt final size:" + sizeForDec.value);
//      System.out.println("clearText:" + new String(clearText));

      // ***********************
      // VERIFY
      // ***********************

      String endString = new String(clearText, 0, (int) sizeForDec.value);

      if (ByteString.compareTo(endString) == 0) {
        println(
            "Decrypted string matches original string - Decryption was successful\n");
      } else {
        println(
            "*** Decrypted string does not match original string - Decryption failed ***\n");
      }

      System.out.println(
          "\n---------------------------------------------------------------------------------\n");

      // Destroy created token objects
      CryptokiEx.C_DestroyObject(session, key);

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

  void multiPart()
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

      CK_AES_GCM_PARAMS gcmParams = new CK_AES_GCM_PARAMS(iv, aad.getBytes(),
          tagBits);
      // Setup mechanism.
      CK_MECHANISM mechanism = new CK_MECHANISM(CKM.AES_GCM, gcmParams);

      CK_OBJECT_HANDLE key = new CK_OBJECT_HANDLE();

      // Generate AES keys.

      CK_MECHANISM keyGenMech = new CK_MECHANISM(CKM.AES_KEY_GEN);

      CryptokiEx.C_GenerateKey(session, keyGenMech, template, template.length,
          key);

      // ***********************
      // ENCRYPTION
      // ***********************

      // Create buffer size 15K approx.
      // K6 HSM card has limit of approx. 15kB
      long bufSize = (1024 * 15);

      // Create plaintext with that buffer size.
      char[] fillBytes = new char[(int) bufSize];
      // Fill chars
      Arrays.fill(fillBytes, 'a');
      String ByteString = new String(fillBytes);
      byte[] plainText = ByteString.getBytes();

      System.out.println(
          "\n---------------- MULTI-PART ENC/DEC-(only single part is done in FW for AES GCM)----------------------------------------\n");

      System.out.println("Encrypting...");

      System.out.println(
          "Plaintext is setup with size: " + plainText.length + " bytes");

      /* allocate space */
      LongRef lRefEnc = new LongRef();

      /* get ready to encrypt */
      CryptokiEx.C_EncryptInit(session, mechanism, key);

      // For multi part, use C_EncryptUpdate and C_EncryptFinal.

      // Observe that, AES_GCM does not return the encrypted size, nor the data, in the call(s) to C_EncryptUpdate.
      // The HSM accumulates all data until C_EncryptFinal is called, whereby the same PKCS approach may be employed:
      // first call with a null buffer to get the size, then allocate the buffer and call again to receive the
      // encrypted data.

      CryptokiEx.C_EncryptUpdate(session, mechanism, plainText,
          plainText.length, null, lRefEnc);

      byte[] cipherTextPart1 = new byte[(int) (lRefEnc.value)];

      CryptokiEx.C_EncryptUpdate(session, mechanism, plainText, plainText.length, cipherTextPart1,
          lRefEnc);

      CryptokiEx.C_EncryptFinal(session, mechanism, null, lRefEnc);
      System.out.println("C_EncryptFinal initial size:" + lRefEnc.value);

      // allocate space
      byte[] cipherTextLastPart = new byte[(int) lRefEnc.value ];

      CryptokiEx.C_EncryptFinal(session, mechanism, cipherTextLastPart, lRefEnc);
      System.out.println("C_EncryptFinal final size:" + lRefEnc.value);

      // ***********************
      // DECRYPTION
      // ***********************

      /* get ready to decrypt */
      System.out.println("\nDecrypting...");
      CryptokiEx.C_DecryptInit(session, mechanism, key);

      LongRef lRefDec = new LongRef();

      // For multi part, use C_DecryptUpdate and C_DecryptFinal.

      // Observe that, AES_GCM does not return the decrypted size, nor the data, in the call(s) to C_DecryptUpdate.
      // The HSM accumulates all data until C_DecryptFinal is called, whereby the same PKCS approach may be employed:
      // first call with a null buffer to get the size, then allocate the buffer and call again to receive the
      // decrypted data.

      CryptokiEx.C_DecryptUpdate(session, mechanism, cipherTextLastPart,
          cipherTextLastPart.length, null, lRefDec);

      /* allocate space */
      byte[] clearTextPart1 = new byte[(int) (lRefDec.value)];

      CryptokiEx.C_DecryptUpdate(session, mechanism, cipherTextLastPart, cipherTextLastPart.length,
          clearTextPart1,
          lRefDec);

      CryptokiEx.C_DecryptFinal(session, mechanism, null, lRefDec);
      System.out.println("C_DecryptFinal initial size:" + lRefDec.value);

      /* allocate space */
      byte[] clearText = new byte[(int) (lRefDec.value)];

      CryptokiEx.C_DecryptFinal(session, mechanism, clearText, lRefDec);
      System.out.println("C_DecryptFinal final size:" + lRefDec.value);

      byte[] clearTextFinal = new byte[(int) (lRefDec.value)];
      System.arraycopy(clearText, 0, clearTextFinal, 0, (int) lRefDec.value);

      //System.out.println("clearText:" + new String(clearText));

      // ***********************
      // VERIFY
      // ***********************

      String endString = new String(clearTextFinal, 0, clearTextFinal.length);

      if (ByteString.compareTo(endString) == 0) {
        println(
            "Decrypted string matches original string - Decryption was successful\n");
      } else {
        println(
            "*** Decrypted string does not match original string - Decryption failed ***\n");
      }

      System.out.println(
          "\n---------------------------------------------------------------------------------\n");

      // Destroy created token objects
      CryptokiEx.C_DestroyObject(session, key);

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

    AesGcmSample aSample = new AesGcmSample();
    aSample.singlePart();
    aSample.multiPart();

  }

}
