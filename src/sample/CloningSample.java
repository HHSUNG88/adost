package sample;

import java.util.Arrays;

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
import com.safenetinc.jcprov.constants.CK_MECHANISM_TYPE;
import com.safenetinc.jcprov.constants.CK_RV;

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
public class CloningSample
{
  static public void println(String s) {
    System.out.println(s);
  }

  /** display runtime usage of the class */
  public static void usage() {
    println("java ...CloningSample -slot1 <slotId> -slot2 <slotId> "
            + "-password <password> -keyName <label> -deleteAll");
    println("");
    println("N.B. -deleteAll will delete the previously created keys on both slots.");
    println("      Do not specify -deleteAll if you want to perform a clone operation.");

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


  private CK_SESSION_HANDLE sessionSource = new CK_SESSION_HANDLE();
  private CK_SESSION_HANDLE sessionTarget = new CK_SESSION_HANDLE();
  private static long slotId1 = 0;
  private static long slotId2 = 0;
  private static String password = "";
  private static String keyName = "";
  private static boolean deleteAll = false;
  private boolean bPrivate = true;
  private long objectTypeForUser = 0;
  private long objectTypeForSMK = 1;
  private CK_RV rv = new CK_RV(0);
  private CK_OBJECT_HANDLE hPrivateKey = new CK_OBJECT_HANDLE();
  private CK_OBJECT_HANDLE hPublicKey = new CK_OBJECT_HANDLE();
  private CK_OBJECT_HANDLE aClonedHandle1 = new CK_OBJECT_HANDLE(0);
  private CK_OBJECT_HANDLE aClonedHandle2 = new CK_OBJECT_HANDLE(0);

  /**
   * Generate an asymetric key pair.
   *
   * @param session
   *  handle to an open session
   *
   * @param mechanismType
   *  mechanism to use to generate the key. One of :- <br>
   *  CKM.RSA_PKCS_KEY_PAIR_GEN                       <br>
   *
   * @param keyName
   *  name (label) to give the generated keys
   *
   * @param bPrivate
   *  true if the Private key of the key pair is to be a private object
   *
   * @param hPublicKey
   *  upon completion, the handle of the generated public key
   *
   * @param hPrivateKey
   *  upon completion, the handle of the generated private key
   */
  public static void generateKeyPair(CK_SESSION_HANDLE session,
                                     CK_MECHANISM_TYPE mechanismType,
                                     String keyName,
                                     boolean bPrivate,
                                     CK_OBJECT_HANDLE hPublicKey,
                                     CK_OBJECT_HANDLE hPrivateKey)
  {
    CK_MECHANISM keyGenMech = new CK_MECHANISM(mechanismType);
    byte bb = 03;
//    Byte pubExponent = new Byte(bb);
    byte[] pubExponent = {0x01, 0x00, 0x01};
    long ll = 1024L;
    ll = 2048L;
    Long modulusBits = new Long(ll);
    byte[] authData = "abcdefgh".getBytes();


    CK_ATTRIBUTE[] publicTemplate =
    {
      new CK_ATTRIBUTE(CKA.LABEL,         keyName.getBytes()),
      new CK_ATTRIBUTE(CKA.TOKEN,         CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.VERIFY,        CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.ENCRYPT,       CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.WRAP,          CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.MODIFIABLE,    CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.MODULUS_BITS,    modulusBits),
      new CK_ATTRIBUTE(CKA.PUBLIC_EXPONENT,   pubExponent),
    };

    CK_ATTRIBUTE[] privateTemplate =
    {
      new CK_ATTRIBUTE(CKA.PRIVATE,   new CK_BBOOL(bPrivate)),//needs to be true for PKA
      new CK_ATTRIBUTE(CKA.LABEL,     keyName.getBytes()),
      new CK_ATTRIBUTE(CKA.TOKEN,         CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.SENSITIVE,     CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.SIGN,          CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.DECRYPT,      CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.UNWRAP,        CK_BBOOL.TRUE),
      new CK_ATTRIBUTE(CKA.MODIFIABLE,    CK_BBOOL.FALSE),//needs to be false for PKA
      new CK_ATTRIBUTE(CKA.EXTRACTABLE,   CK_BBOOL.FALSE),//needs to be false for PKA
//      new CK_ATTRIBUTE(CKA.AUTH_DATA,     authData),//needs to be set to some byte array of 7+ bytes (see spec)
//                                                    //for PKA
    };

    CryptokiEx.C_GenerateKeyPair(session, keyGenMech,
                                 publicTemplate, publicTemplate.length,
                                 privateTemplate, privateTemplate.length,
                                 hPublicKey, hPrivateKey);
  }

  void createObjects()
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
      CryptokiEx.C_OpenSession(slotId1, CKF.RW_SESSION | CKF.SERIAL_SESSION,
          null, null, sessionSource);

      /*
       * Login - if we have a password
       */
      if (password.length() > 0) {
        CryptokiEx.C_Login(sessionSource, CKU.USER, password.getBytes(),
            password.length());
      }

      generateKeyPair(sessionSource, CKM.RSA_PKCS_KEY_PAIR_GEN, keyName, bPrivate, hPublicKey, hPrivateKey);
      println("rsa key pair (" + keyName + ") generated");
      println("handles: public(" + hPublicKey.longValue() + ") private(" + hPrivateKey.longValue() + ")");

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
        Cryptoki.C_Logout(sessionSource);

      /*
       * Close the session.
       *
       * Note that we are not using CryptokiEx.
       */
        Cryptoki.C_CloseSession(sessionSource);

      /*
       * All done with Cryptoki
       *
       * Note that we are not using CryptokiEx.
       */
      Cryptoki.C_Finalize(null);
    }
  }

  void deleteObjects()
  {
    CK_SESSION_HANDLE sessionSource = new CK_SESSION_HANDLE();
    CK_SESSION_HANDLE sessionTarget = new CK_SESSION_HANDLE();

    try {
        CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));
        CryptokiEx.C_OpenSession(slotId1,
                CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null, sessionSource);
        CryptokiEx.C_Login(sessionSource, CKU.USER,
                password.getBytes(),
                password.length());
        CryptokiEx.C_OpenSession(slotId2,
                CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null, sessionTarget);
        CryptokiEx.C_Login(sessionTarget, CKU.USER,
                password.getBytes(),
                password.length());

        CK_OBJECT_HANDLE[] objHandles = {
                new CK_OBJECT_HANDLE(),
                new CK_OBJECT_HANDLE(),
                new CK_OBJECT_HANDLE(),
                new CK_OBJECT_HANDLE(),
                new CK_OBJECT_HANDLE(),
        };
        LongRef objCount = new LongRef();
        CryptokiEx.C_FindObjectsInit(sessionSource, null, 0);
        do
        {
            CryptokiEx.C_FindObjects(sessionSource, objHandles, objHandles.length, objCount);
            for (int i = 0; i < objCount.value; ++i)
            {
                CryptokiEx.C_DestroyObject(sessionSource, objHandles[i]);
            }
        } while (objCount.value == objHandles.length);
        CryptokiEx.C_FindObjectsInit(sessionTarget, null, 0);
        do
        {
            CryptokiEx.C_FindObjects(sessionTarget, objHandles, objHandles.length, objCount);
            for (int i = 0; i < objCount.value; ++i)
            {
                CryptokiEx.C_DestroyObject(sessionTarget, objHandles[i]);
            }
        } while (objCount.value == objHandles.length);

        CryptokiEx.C_Logout(sessionSource);
        CryptokiEx.C_Logout(sessionTarget);
        CryptokiEx.C_CloseSession(sessionSource);
        CryptokiEx.C_CloseSession(sessionTarget);
        CryptokiEx.C_Finalize(null);

    } catch (CKR_Exception ex) {
      /*
       * A Cryptoki related exception was thrown
       */
      ex.printStackTrace();
    } finally {
    }
  }

  void destroyObjects()
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
      CryptokiEx.C_OpenSession(slotId1, CKF.RW_SESSION | CKF.SERIAL_SESSION,
          null, null, sessionSource);

      /*
       * Login - if we have a password
       */
      if (password.length() > 0) {
        CryptokiEx.C_Login(sessionSource, CKU.USER, password.getBytes(),
            password.length());
      }

      /*
       * Open a session
       */
      CryptokiEx.C_OpenSession(slotId2, CKF.RW_SESSION | CKF.SERIAL_SESSION,
          null, null, sessionTarget);

      /*
       * Login - if we have a password
       */
      if (password.length() > 0) {
        CryptokiEx.C_Login(sessionTarget, CKU.USER, password.getBytes(),
            password.length());
      }

      System.out.println("destroying hPrivateKey:" + hPrivateKey.longValue());
      CryptokiEx.C_DestroyObject(sessionSource, hPrivateKey);
      System.out.println("destroying hPublicKey:" + hPublicKey.longValue());
      CryptokiEx.C_DestroyObject(sessionSource, hPublicKey);
      System.out.println("destroying aClonedHandle1:" + aClonedHandle1.longValue());
      CryptokiEx.C_DestroyObject(sessionTarget, aClonedHandle1);
      System.out.println("destroying aClonedHandle2:" + aClonedHandle2.longValue());
      CryptokiEx.C_DestroyObject(sessionTarget, aClonedHandle2);

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
        Cryptoki.C_Logout(sessionSource);
        Cryptoki.C_Logout(sessionTarget);

      /*
       * Close the session.
       *
       * Note that we are not using CryptokiEx.
       */
        Cryptoki.C_CloseSession(sessionSource);
        Cryptoki.C_CloseSession(sessionTarget);

      /*
       * All done with Cryptoki
       *
       * Note that we are not using CryptokiEx.
       */
      Cryptoki.C_Finalize(null);
    }
  }

  void doCloneObjectSMK()
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
      CryptokiEx.C_OpenSession(slotId1, CKF.RW_SESSION | CKF.SERIAL_SESSION,
          null, null, sessionSource);

      /*
       * Login - if we have a password
       */
      if (password.length() > 0) {
        CryptokiEx.C_Login(sessionSource, CKU.USER, password.getBytes(),
            password.length());
      }

      /*
       * Open a session
       */
      CryptokiEx.C_OpenSession(slotId2, CKF.RW_SESSION | CKF.SERIAL_SESSION,
          null, null, sessionTarget);

      /*
       * Login - if we have a password
       */
      if (password.length() > 0) {
        CryptokiEx.C_Login(sessionTarget, CKU.USER, password.getBytes(),
            password.length());
      }

      CK_OBJECT_HANDLE aHandle = new CK_OBJECT_HANDLE(0);
      CK_OBJECT_HANDLE theSMK = new CK_OBJECT_HANDLE(24);
      CryptokiEx.CA_CloneObject(
              sessionTarget,
              sessionSource,
              objectTypeForSMK,
              theSMK,
              aHandle);
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
        Cryptoki.C_Logout(sessionSource);
        Cryptoki.C_Logout(sessionTarget);

      /*
       * Close the session.
       *
       * Note that we are not using CryptokiEx.
       */
        Cryptoki.C_CloseSession(sessionSource);
        Cryptoki.C_CloseSession(sessionTarget);

      /*
       * All done with Cryptoki
       *
       * Note that we are not using CryptokiEx.
       */
      Cryptoki.C_Finalize(null);
    }
  }

  void doCloneObjectUserObject()
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
      CryptokiEx.C_OpenSession(slotId1, CKF.RW_SESSION | CKF.SERIAL_SESSION,
          null, null, sessionSource);

      /*
       * Login - if we have a password
       */
      if (password.length() > 0) {
        CryptokiEx.C_Login(sessionSource, CKU.USER, password.getBytes(),
            password.length());
      }

      /*
       * Open a session
       */
      CryptokiEx.C_OpenSession(slotId2, CKF.RW_SESSION | CKF.SERIAL_SESSION,
          null, null, sessionTarget);

      /*
       * Login - if we have a password
       */
      if (password.length() > 0) {
        CryptokiEx.C_Login(sessionTarget, CKU.USER, password.getBytes(),
            password.length());
      }

      CryptokiEx.CA_CloneObject(
              sessionTarget,
              sessionSource,
              objectTypeForUser,
              hPrivateKey,
              aClonedHandle1);
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
        Cryptoki.C_Logout(sessionSource);
        Cryptoki.C_Logout(sessionTarget);

      /*
       * Close the session.
       *
       * Note that we are not using CryptokiEx.
       */
        Cryptoki.C_CloseSession(sessionSource);
        Cryptoki.C_CloseSession(sessionTarget);

      /*
       * All done with Cryptoki
       *
       * Note that we are not using CryptokiEx.
       */
      Cryptoki.C_Finalize(null);
    }
  }

  void doClonePrimitiveUserObject()
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
      CryptokiEx.C_OpenSession(slotId1, CKF.RW_SESSION | CKF.SERIAL_SESSION,
          null, null, sessionSource);

      /*
       * Login - if we have a password
       */
      if (password.length() > 0) {
        CryptokiEx.C_Login(sessionSource, CKU.USER, password.getBytes(),
            password.length());
      }

      /*
       * Open a session
       */
      CryptokiEx.C_OpenSession(slotId2, CKF.RW_SESSION | CKF.SERIAL_SESSION,
          null, null, sessionTarget);

      /*
       * Login - if we have a password
       */
      if (password.length() > 0) {
        CryptokiEx.C_Login(sessionTarget, CKU.USER, password.getBytes(),
            password.length());
      }

      CK_OBJECT_HANDLE dummyObjectHandle = new CK_OBJECT_HANDLE(0);
      LongRef blobLen = new LongRef(0);
      LongRef outBlobLen = new LongRef(0);
      LongRef dummyLen = new LongRef(0);
      byte[] blob = null;
      byte[] outBlob = null;

      rv = CryptokiEx.CA_CloneAsSourceInit(
              sessionSource,
              (byte[])null,
              dummyLen,
              outBlob,
              outBlobLen,
              false
              );

      outBlob = new byte[(int)(outBlobLen.value)];

      rv = CryptokiEx.CA_CloneAsSourceInit(
              sessionSource,
              (byte[])null,
              dummyLen,
              outBlob,
              outBlobLen,
              false
              );

      blob = Arrays.copyOf(outBlob, (int)outBlobLen.value);
      blobLen.value = outBlobLen.value;
      outBlobLen = new LongRef(0);
      outBlob = null;

      rv = CryptokiEx.CA_CloneAsTargetInit(
              sessionTarget,
              blob,
              blobLen,
              (byte[])null,
              dummyLen,
              false,
              outBlob,
              outBlobLen
              );

      outBlob = new byte[(int)(outBlobLen.value)];

      rv = CryptokiEx.CA_CloneAsTargetInit(
              sessionTarget,
              blob,
              blobLen,
              (byte[])null,
              dummyLen,
              false,
              outBlob,
              outBlobLen
              );

      blob = Arrays.copyOf(outBlob, (int)outBlobLen.value);
      blobLen.value = blob.length;
      outBlob = null;
      outBlobLen = new LongRef(0);

      rv = CryptokiEx.CA_CloneAsSource(
              sessionSource,
              objectTypeForUser,
              hPublicKey,
              blob,
              blobLen,
              false,
              outBlob,
              outBlobLen
              );

      outBlob = new byte[(int)(outBlobLen.value)];

      rv = CryptokiEx.CA_CloneAsSource(
              sessionSource,
              objectTypeForUser,
              hPublicKey,
              blob,
              blobLen,
              false,
              outBlob,
              outBlobLen
              );

      blob = Arrays.copyOf(outBlob, (int)outBlobLen.value);
      blobLen.value = blob.length;

      rv = CryptokiEx.CA_CloneAsTarget(
              sessionTarget,
              (byte[])null,
              dummyLen,
              blob,
              blobLen,
              objectTypeForUser,
              dummyObjectHandle,
              false,
              aClonedHandle2
              );
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
        Cryptoki.C_Logout(sessionSource);
        Cryptoki.C_Logout(sessionTarget);

      /*
       * Close the session.
       *
       * Note that we are not using CryptokiEx.
       */
        Cryptoki.C_CloseSession(sessionSource);
        Cryptoki.C_CloseSession(sessionTarget);

      /*
       * All done with Cryptoki
       *
       * Note that we are not using CryptokiEx.
       */
      Cryptoki.C_Finalize(null);
    }
  }

  void doCloningPrimitiveSMK()
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
      CryptokiEx.C_OpenSession(slotId1, CKF.RW_SESSION | CKF.SERIAL_SESSION,
          null, null, sessionSource);

      /*
       * Login - if we have a password
       */
      if (password.length() > 0) {
        CryptokiEx.C_Login(sessionSource, CKU.USER, password.getBytes(),
            password.length());
      }

      /*
       * Open a session
       */
      CryptokiEx.C_OpenSession(slotId2, CKF.RW_SESSION | CKF.SERIAL_SESSION,
          null, null, sessionTarget);

      /*
       * Login - if we have a password
       */
      if (password.length() > 0) {
        CryptokiEx.C_Login(sessionTarget, CKU.USER, password.getBytes(),
            password.length());
      }

      CK_OBJECT_HANDLE theSMK = new CK_OBJECT_HANDLE(24);
      CK_OBJECT_HANDLE clonedObjectHandle = new CK_OBJECT_HANDLE(74);
      LongRef blobLen = new LongRef(0);
      LongRef outBlobLen = new LongRef(0);
      LongRef dummyLen = new LongRef(0);
      byte[] blob = null;
      byte[] outBlob = null;

      CryptokiEx.CA_CloneAsSourceInit(
              sessionSource,
              (byte[])null,
              dummyLen,
              outBlob,
              outBlobLen,
              false
              );

      outBlob = new byte[(int)(outBlobLen.value)];

      CryptokiEx.CA_CloneAsSourceInit(
              sessionSource,
              (byte[])null,
              dummyLen,
              outBlob,
              outBlobLen,
              false
              );

      blob = Arrays.copyOf(outBlob, (int)outBlobLen.value);
      blobLen.value = outBlobLen.value;
      outBlobLen = new LongRef(0);
      outBlob = null;

      CryptokiEx.CA_CloneAsTargetInit(
              sessionTarget,
              blob,
              blobLen,
              (byte[])null,
              dummyLen,
              false,
              outBlob,
              outBlobLen
              );

      outBlob = new byte[(int)(outBlobLen.value)];

      CryptokiEx.CA_CloneAsTargetInit(
              sessionTarget,
              blob,
              blobLen,
              (byte[])null,
              dummyLen,
              false,
              outBlob,
              outBlobLen
              );

      blob = Arrays.copyOf(outBlob, (int)outBlobLen.value);
      blobLen.value = blob.length;
      outBlob = new byte[65536];
      outBlobLen = new LongRef(65536);

      CryptokiEx.CA_CloneAsSource(
              sessionSource,
              objectTypeForSMK,
              theSMK,
              blob,
              blobLen,
              false,
              outBlob,
              outBlobLen
              );

      blob = Arrays.copyOf(outBlob, (int)outBlobLen.value);
      blobLen.value = blob.length;

      CryptokiEx.CA_CloneAsTarget(
              sessionTarget,
              (byte[])null,
              dummyLen,
              blob,
              blobLen,
              objectTypeForSMK,
              theSMK,
              false,
              clonedObjectHandle
              );
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
        Cryptoki.C_Logout(sessionSource);
        Cryptoki.C_Logout(sessionTarget);

      /*
       * Close the session.
       *
       * Note that we are not using CryptokiEx.
       */
        Cryptoki.C_CloseSession(sessionSource);
        Cryptoki.C_CloseSession(sessionTarget);

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

      if (args[i].equalsIgnoreCase("-slot1")) {
        if (++i >= args.length)
          usage();

        slotId1 = Integer.parseInt(args[i]);
      } else if (args[i].equalsIgnoreCase("-slot2")) {
        if (++i >= args.length)
          usage();

        slotId2 = Integer.parseInt(args[i]);
      } else if (args[i].equalsIgnoreCase("-password")) {
          if (++i >= args.length)
            usage();

          password = args[i];
      } else if (args[i].equalsIgnoreCase("-keyName")) {
          if (++i >= args.length)
              usage();

          keyName = args[i];
      } else if (args[i].equalsIgnoreCase("-deleteAll")) {

          deleteAll = true;
      } else {
        usage();
      }
    }

    CloningSample aSample = new CloningSample();
    if(deleteAll) {
        aSample.deleteObjects();
    } else {
        aSample.createObjects();
        aSample.doCloneObjectSMK();
        aSample.doCloningPrimitiveSMK();;
        aSample.doCloneObjectUserObject();
        aSample.doClonePrimitiveUserObject();
        //aSample.destroyObjects();
    }

  }

}
