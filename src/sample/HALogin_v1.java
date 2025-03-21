
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;

import com.safenetinc.jcprov.*;
import com.safenetinc.jcprov.constants.*;

/**
 * This class demonstrates using HALogin v1
 */
public class HALogin_v1 {

  /** easy access to System.out.println */
  public static void println(String s) {
    System.out.println(s);
  }

  /** display runtime usage of the class */
  public static void usage() {
    println("");
    println("java ...HALogin_v1 -source <sourceID> -target <targetID> " + "[-password <password>] "
        + "[-adminslot <adminSlot>] " + "[-deleteobjects] <deleteObjects>");
    println("");
    println("<sourceID> primary slot ID (source of login key)");
    println("<targetID> slot to log into");
    println("<password> user password on source slot (omit for PED login)");
    println("<adminSlot> slots are admin(true or false)");
    println("<deleteObjects> remove all created objects(true or false)");
    println("");

    System.exit(1);
  }

  /**
   * Locate the first occurrence of the specified key
   *
   * @param session  handle to and open session
   *
   * @param objLabel label of the key to locate
   */
  static CK_OBJECT_HANDLE findObject(CK_SESSION_HANDLE session, String objLabel) {
    byte[] label = objLabel.getBytes();
    LongRef objCount = new LongRef();
    CK_OBJECT_HANDLE[] hKey = { new CK_OBJECT_HANDLE() };

    CK_ATTRIBUTE[] template = { new CK_ATTRIBUTE(CKA.LABEL, label) };

    CryptokiEx.C_FindObjectsInit(session, template, template.length);
    CryptokiEx.C_FindObjects(session, hKey, hKey.length, objCount);
    CryptokiEx.C_FindObjectsFinal(session);
    if (objCount.value == 1) {
      return hKey[0];
    } else {
      return new CK_OBJECT_HANDLE();
    }
  }

  static void deleteObject(CK_SESSION_HANDLE session, String objLabel) {
    byte[] label = objLabel.getBytes();
    LongRef objCount = new LongRef();
    CK_OBJECT_HANDLE[] hKey = { new CK_OBJECT_HANDLE() };

    CK_ATTRIBUTE[] template = { new CK_ATTRIBUTE(CKA.LABEL, label) };

    CryptokiEx.C_FindObjectsInit(session, template, template.length);
    CryptokiEx.C_FindObjects(session, hKey, hKey.length, objCount);
    CryptokiEx.C_FindObjectsFinal(session);
    if (objCount.value >= 1) {
      CryptokiEx.C_DestroyObject(session, hKey[0]);
    } else {
      System.out.println("Could not find " + objLabel + " (nothing to delete)");
    }
  }

  public static void main(String[] args) {
    long sourceSlotId = 1;
    long targetSlotId = 2;
    CK_SESSION_HANDLE sourceSession = new CK_SESSION_HANDLE();
    CK_SESSION_HANDLE targetSession = new CK_SESSION_HANDLE();

    byte[] password = null;

    CK_OBJECT_HANDLE sourcePrivateKey = null;
    CK_OBJECT_HANDLE targetPrivateKey = new CK_OBJECT_HANDLE(0);
    CK_SESSION_INFO info = new CK_SESSION_INFO();

    LongRef twcLen = new LongRef();
    LongRef challengeBlobLen = new LongRef();
    LongRef encryptedPinLen = new LongRef();
    LongRef mOfNBlobLen = new LongRef();

    boolean adminSlot = false;
    boolean deleteObjects = false;

    // Setup command line arguments
    for (int i = 0; i < args.length; ++i) {
      if (args[i].equalsIgnoreCase("-source")) {
        if (++i >= args.length) {
          usage();
        }
        sourceSlotId = Integer.parseInt(args[i]);
      } else if (args[i].equalsIgnoreCase("-target")) {
        if (++i >= args.length) {
          usage();
        }
        targetSlotId = Integer.parseInt(args[i]);
      } else if (args[i].equalsIgnoreCase("-password")) {
        if (++i >= args.length) {
          usage();
        }
        password = args[i].getBytes();
      } else if (args[i].equalsIgnoreCase("-adminslot")) {
        if (++i >= args.length) {
          usage();
        }
        adminSlot = Boolean.parseBoolean(args[i]);
      } else if (args[i].equalsIgnoreCase("-deleteobjects")) {
        if (++i >= args.length) {
          usage();
        }
        deleteObjects = Boolean.parseBoolean(args[i]);
      } else {
        usage();
      }
    }

    try {

      CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));

      // To be able to use HA login
      // - open session to target
      // - login to target
      // - CA_HAInit on target
      // - logout

      String label_rsaPub4096 = "jcprov_rsaPub4096";
      String label_rsaPriv4096 = "jcprov_rsaPriv4096";
      byte[] pubExponent = {0x01, 0x00, 0x01};
      CK_OBJECT_HANDLE jcprov_rsaPub4096 = new CK_OBJECT_HANDLE ();
      CK_OBJECT_HANDLE jcprov_rsaPriv4096 = new CK_OBJECT_HANDLE ();

      if (deleteObjects) {

        if (adminSlot) {
          CryptokiEx.C_OpenSession(sourceSlotId, CKF.RW_SESSION | CKF.SERIAL_SESSION | CKF.SO_SESSION, null, null,
              sourceSession);
          CryptokiEx.C_Login(sourceSession, CKU.SO, password, (password == null ? 0 : password.length));
          CryptokiEx.C_OpenSession(targetSlotId, CKF.RW_SESSION | CKF.SERIAL_SESSION | CKF.SO_SESSION, null, null,
              targetSession);
          CryptokiEx.C_Login(targetSession, CKU.SO, password, (password == null ? 0 : password.length));
        } else {
          CryptokiEx.C_OpenSession(sourceSlotId, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null, sourceSession);
          CryptokiEx.C_Login(sourceSession, CKU.USER, password, (password == null ? 0 : password.length));
          CryptokiEx.C_OpenSession(targetSlotId, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null, targetSession);
          CryptokiEx.C_Login(targetSession, CKU.USER, password, (password == null ? 0 : password.length));
        }

        deleteObject(sourceSession, label_rsaPriv4096);
        deleteObject(sourceSession, label_rsaPub4096);
        deleteObject(targetSession, label_rsaPriv4096);

      } else {

        if(adminSlot) {
          CryptokiEx.C_OpenSession(sourceSlotId, CKF.RW_SESSION | CKF.SERIAL_SESSION | CKF.SO_SESSION, null, null, sourceSession);
          CryptokiEx.C_Login(sourceSession, CKU.SO, password, (password == null ? 0 : password.length));
        } else {
          CryptokiEx.C_OpenSession(sourceSlotId, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null, sourceSession);
          CryptokiEx.C_Login(sourceSession, CKU.USER, password, (password == null ? 0 : password.length));
        }

        // - make HA login key pair -> 4096 min key length
        // - no usage allowed ->
        //   sign/verify/encrypt/decrypt/derive/modifiable/extractable = 0
        CK_ATTRIBUTE[] temp_rsaPub4096 = { new CK_ATTRIBUTE(CKA.LABEL, label_rsaPub4096.getBytes()),
            new CK_ATTRIBUTE(CKA.CLASS, CKO.PUBLIC_KEY), new CK_ATTRIBUTE(CKA.MODULUS_BITS, new Long(4096L)),
            new CK_ATTRIBUTE(CKA.PUBLIC_EXPONENT, pubExponent), new CK_ATTRIBUTE(CKA.TOKEN, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.ENCRYPT, CK_BBOOL.FALSE), new CK_ATTRIBUTE(CKA.WRAP, CK_BBOOL.FALSE),
            new CK_ATTRIBUTE(CKA.VERIFY, CK_BBOOL.FALSE) };

        CK_ATTRIBUTE[] temp_rsaPriv4096 = { new CK_ATTRIBUTE(CKA.LABEL, label_rsaPriv4096.getBytes()),
            new CK_ATTRIBUTE(CKA.CLASS, CKO.PRIVATE_KEY), new CK_ATTRIBUTE(CKA.TOKEN, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.DERIVE, CK_BBOOL.FALSE), new CK_ATTRIBUTE(CKA.PRIVATE, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.TRUE), new CK_ATTRIBUTE(CKA.DECRYPT, CK_BBOOL.FALSE),
            new CK_ATTRIBUTE(CKA.UNWRAP, CK_BBOOL.FALSE), new CK_ATTRIBUTE(CKA.EXTRACTABLE, CK_BBOOL.FALSE),
            new CK_ATTRIBUTE(CKA.SIGN, CK_BBOOL.FALSE) };

        sourcePrivateKey = findObject(sourceSession,label_rsaPriv4096);
        if(sourcePrivateKey.longValue() == CK.INVALID_HANDLE) {
          System.out.println("Creating the source key pair...");
          CryptokiEx.C_GenerateKeyPair(sourceSession, new CK_MECHANISM(CKM.RSA_PKCS_KEY_PAIR_GEN),
            temp_rsaPub4096, temp_rsaPub4096.length, temp_rsaPriv4096,
            temp_rsaPriv4096.length, jcprov_rsaPub4096, jcprov_rsaPriv4096);
          sourcePrivateKey = jcprov_rsaPriv4096;
        }

        if(adminSlot) {
          CryptokiEx.C_OpenSession(targetSlotId, CKF.RW_SESSION | CKF.SERIAL_SESSION | CKF.SO_SESSION, null, null, targetSession);
          CryptokiEx.C_Login(targetSession, CKU.SO, password, (password == null ? 0 : password.length));
        } else {
          CryptokiEx.C_OpenSession(targetSlotId, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null, targetSession);
          CryptokiEx.C_Login(targetSession, CKU.USER, password, (password == null ? 0 : password.length));
        }

        targetPrivateKey = findObject(targetSession, label_rsaPriv4096);
        if (targetPrivateKey.longValue() == CK.INVALID_HANDLE) {
          try {
            CryptokiEx.CA_CloneObject(targetSession, sourceSession, 0, sourcePrivateKey, targetPrivateKey);
          } catch (Exception ex) {
            ex.printStackTrace();
          } finally {
          }
        }

        CryptokiEx.CA_HAInit(targetSession, targetPrivateKey);

        Cryptoki.C_Logout(sourceSession);
        Cryptoki.C_CloseSession(sourceSession);
        Cryptoki.C_Logout(targetSession);
        Cryptoki.C_CloseSession(targetSession);

        // Login to source HSM and get the shared private key

        if(adminSlot) {
          CryptokiEx.C_OpenSession(sourceSlotId,CKF.RW_SESSION | CKF.SERIAL_SESSION | CKF.SO_SESSION, null, null, sourceSession);
          CryptokiEx.C_Login(sourceSession, CKU.SO, password, (password == null ? 0 : password.length));
          CryptokiEx.C_OpenSession(targetSlotId, CKF.RW_SESSION | CKF.SERIAL_SESSION | CKF.SO_SESSION, null, null, targetSession);
        } else {
          CryptokiEx.C_OpenSession(sourceSlotId, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null, sourceSession);
          CryptokiEx.C_Login(sourceSession, CKU.USER, password, (password == null ? 0 : password.length));
          CryptokiEx.C_OpenSession(targetSlotId, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null, targetSession);
        }

        // Get the Token Wrapping Certificate (TWC) from the source HSM
        CryptokiEx.CA_HAGetMasterPublic(sourceSlotId, null, twcLen);
        byte[] twc = new byte[(int) twcLen.value];
        CryptokiEx.CA_HAGetMasterPublic(sourceSlotId, twc, twcLen);

        // Get the target challenge
        byte[] challengeBlob = null;
        if(adminSlot) {
          CryptokiEx.CA_HAGetLoginChallenge(targetSession, CKU.SO, twc, twcLen.value, null, challengeBlobLen);
          challengeBlob = new byte[(int) challengeBlobLen.value];
          CryptokiEx.CA_HAGetLoginChallenge(targetSession, CKU.SO, twc, twcLen.value, challengeBlob, challengeBlobLen);
        } else {
          CryptokiEx.CA_HAGetLoginChallenge(targetSession, CKU.USER, twc, twcLen.value, null, challengeBlobLen);
          challengeBlob = new byte[(int) challengeBlobLen.value];
          CryptokiEx.CA_HAGetLoginChallenge(targetSession, CKU.USER, twc, twcLen.value, challengeBlob, challengeBlobLen);
        }

        // Get the challenge response from the source HSM
        CryptokiEx.CA_HAAnswerLoginChallenge(sourceSession, sourcePrivateKey, challengeBlob, challengeBlobLen.value, null,
            encryptedPinLen);
        byte[] encryptedPin = new byte[(int) encryptedPinLen.value];
        CryptokiEx.CA_HAAnswerLoginChallenge(sourceSession, sourcePrivateKey, challengeBlob, challengeBlobLen.value,
            encryptedPin, encryptedPinLen);

        CryptokiEx.C_GetSessionInfo(targetSession, info);
        System.out.println("(pre-HALogin)Target session state = " + info.state.longValue());

        // Login to target HSM
        CryptokiEx.CA_HALogin(targetSession, encryptedPin, encryptedPinLen.value, null, mOfNBlobLen);

        // for admin partition, session should be logged in as SO state == 4
        // for user partition, session should be logged in as CO state == 3
        CryptokiEx.C_GetSessionInfo(targetSession, info);
        System.out.println("(post-HALogin)Target session state = " + info.state.longValue());

      }

      // Cleanup
      Cryptoki.C_Logout(sourceSession);
      Cryptoki.C_Logout(targetSession);
      Cryptoki.C_CloseSession(sourceSession);
      Cryptoki.C_CloseSession(targetSession);

      Cryptoki.C_Finalize(null);

    } catch (Exception ex) {
      ex.printStackTrace();
    }

  }

}
