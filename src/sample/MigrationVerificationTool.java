import com.safenetinc.jcprov.*;
import com.safenetinc.jcprov.constants.*;
import com.safenetinc.jcprov.params.CK_AES_GCM_PARAMS;
import com.safenetinc.jcprov.params.CK_RSA_PKCS_PSS_PARAMS;

import java.util.Arrays;
import java.util.Random;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.nio.ByteBuffer;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.Console;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;

public class MigrationVerificationTool {

  private static long slotId = 9999;
  private static String slotLabel = "";
  private static String keyType = "";
  private static String keyName = "";
  private static String password = "";
  private static String fileName = "";
  private static String operation = "";

  static public void println(String s) {
    System.out.println(s);
  }

  /** display runtime usage of the class */
  public static void usage() {
    println(
        "-slot <slotLabel> -password <password> -keyType <rsa/aes/3des> -keyName <keyName> -fileName <fileName> -operation <sign/verify/encrypt/decrypt> \n");
    println("");

    System.exit(1);
  }

  /** main execution method */
  public static void main(String[] args) {

    CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
    boolean bPrivate = false;

    parseArgs(args);

    try {

      CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));

      //get slot id from slot label
      long[] slotList = null;
      LongRef lRef = new LongRef();

      /* determine the size of the slot list */
      CryptokiEx.C_GetSlotList(CK_BBOOL.TRUE, null, lRef);

      /* allocate space */
      slotList = new long[(int)lRef.value];

      /* get the slot list */
      CryptokiEx.C_GetSlotList(CK_BBOOL.TRUE, slotList, lRef);

      /* enumerate over the list, displaying the relevant inforamtion */
      for (int i = 0; i < slotList.length; ++i)
      {
        CK_TOKEN_INFO info = new CK_TOKEN_INFO();
        CryptokiEx.C_GetTokenInfo(slotList[i], info);
        String infoLabel = new String(info.label);
        infoLabel = infoLabel.trim();
        if (infoLabel.compareTo(slotLabel) == 0) {
          slotId = slotList[i];
          break;
        }

      }

      CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null, session);

      // Login since we have password
      CryptokiEx.C_Login(session, CKU.USER, password.getBytes(), password.length());

      if (operation.equalsIgnoreCase("sign") ||
          operation.equalsIgnoreCase("verify") ||
          operation.equalsIgnoreCase("encrypt") ||
          operation.equalsIgnoreCase("decrypt")
          ) {
        bPrivate = true;
      }

      CK_OBJECT_HANDLE hKey = null;

      if (keyType.equalsIgnoreCase("3des")) {
        hKey = findKey(session, CKO.SECRET_KEY, CKK.DES3, keyName, bPrivate);
      } else if (keyType.equalsIgnoreCase("rsa") && operation.equalsIgnoreCase("dumpRSAPubKey")) {
        hKey = findKey(session, CKO.PRIVATE_KEY, CKK.RSA, keyName, bPrivate);
      } else if (keyType.equalsIgnoreCase("rsa") && operation.equalsIgnoreCase("decryptRSA")) {
        hKey = findKey(session, CKO.PRIVATE_KEY, CKK.RSA, keyName, bPrivate);
      } else if (keyType.equalsIgnoreCase("rsa") && operation.equalsIgnoreCase("verify")) {
        hKey = findKey(session, CKO.PUBLIC_KEY, CKK.RSA, keyName, bPrivate);
      } else if (keyType.equalsIgnoreCase("rsa")) {
        hKey = findKey(session, CKO.PRIVATE_KEY, CKK.RSA, keyName, bPrivate);
      } else if (keyType.equalsIgnoreCase("ec") && operation.equalsIgnoreCase("verify")) {
        hKey = findKey(session, CKO.PUBLIC_KEY, CKK.EC, keyName, bPrivate);
      } else if (keyType.equalsIgnoreCase("ec")) {
        hKey = findKey(session, CKO.PRIVATE_KEY, CKK.EC, keyName, bPrivate);
      } else if (keyType.equalsIgnoreCase("aes")) {
        hKey = findKey(session, CKO.SECRET_KEY, CKK.AES, keyName, bPrivate);
      }

      if (hKey != null && !hKey.isValidHandle()) {
        println("key (" + keyName + ") not found");
        System.exit(1);
      } else {
        CK_RSA_PKCS_PSS_PARAMS RSAPSSParams = new CK_RSA_PKCS_PSS_PARAMS(CKM.SHA3_256, CKG.MGF1_SHA3_256, 20L);

        // Generate AES GCM parameters
        byte[] iv = new byte[] {(byte)0, (byte)1, (byte)2, (byte)3, (byte)4, (byte)5, (byte)6, (byte)7 } ;
        // Generate Additional Authentication Data(AAD) bytes
        String aad = "AAAD";
        // Generate tag bits size
        int tagBits = 128;

        CK_AES_GCM_PARAMS gcmParams = new CK_AES_GCM_PARAMS(iv, aad.getBytes(),
            tagBits);

        if (operation.equalsIgnoreCase("sign") && keyType.equalsIgnoreCase("rsa")) {
          CK_MECHANISM mech = new CK_MECHANISM(CKM.SHA256_RSA_PKCS, null);
          sign(session, hKey, mech);
        } else if (operation.equalsIgnoreCase("verify") && keyType.equalsIgnoreCase("rsa")) {
          //need public key
          CK_MECHANISM mech = new CK_MECHANISM(CKM.SHA256_RSA_PKCS, null);
          verify(session, hKey, mech);
        //} else if (operation.equalsIgnoreCase("sign") && keyType.equalsIgnoreCase("rsa")) {
        //  CK_MECHANISM mech = new CK_MECHANISM(CKM.SHA3_256_RSA_PKCS_PSS, RSAPSSParams);
        //  sign(session, hKey, mech);
        //} else if (operation.equalsIgnoreCase("verify") && keyType.equalsIgnoreCase("rsa")) {
        //  //need public key
        //  CK_MECHANISM mech = new CK_MECHANISM(CKM.SHA3_256_RSA_PKCS_PSS, RSAPSSParams);
        //  verify(session, hKey, mech);
        } else if (keyType.equalsIgnoreCase("rsa") && operation.equalsIgnoreCase("dumpRSAPubKey")) {
          getModulusAndExponent(session, hKey);
        } else if (keyType.equalsIgnoreCase("rsa") && operation.equalsIgnoreCase("decryptRSA")) {
          CK_MECHANISM mech = new CK_MECHANISM(CKM.RSA_PKCS, null);
          decryptRSA(session, hKey, mech);
        } else if (operation.equalsIgnoreCase("sign") && keyType.equalsIgnoreCase("ec")) {
          //CK_MECHANISM mech = new CK_MECHANISM(CKM.ECDSA_SHA256, null);
          CK_MECHANISM mech = new CK_MECHANISM(CKM.ECDSA, null);
          sign(session, hKey, mech);
        } else if (operation.equalsIgnoreCase("verify") && keyType.equalsIgnoreCase("ec")) {
          //need public key
          //CK_MECHANISM mech = new CK_MECHANISM(CKM.ECDSA_SHA256, null);
          CK_MECHANISM mech = new CK_MECHANISM(CKM.ECDSA, null);
          verify(session, hKey, mech);
        } else if (operation.equalsIgnoreCase("encrypt") && keyType.equalsIgnoreCase("aes")) {
          CK_MECHANISM mech = new CK_MECHANISM(CKM.AES_GCM, gcmParams);
          encrypt(session, hKey, mech);
        } else if (operation.equalsIgnoreCase("decrypt") && keyType.equalsIgnoreCase("aes")) {
          CK_MECHANISM mech = new CK_MECHANISM(CKM.AES_GCM, gcmParams);
          decrypt(session, hKey, mech);
        //} else if (operation.equalsIgnoreCase("encrypt") && keyType.equalsIgnoreCase("3des")) {
        //  CK_MECHANISM mech = new CK_MECHANISM(CKM.DES3_CBC, iv);
        //  encrypt(session, hKey, mech);
        //} else if (operation.equalsIgnoreCase("decrypt") && keyType.equalsIgnoreCase("3des")) {
        //  CK_MECHANISM mech = new CK_MECHANISM(CKM.DES3_CBC, iv);
        //  decrypt(session, hKey, mech);
        } else if (operation.equalsIgnoreCase("encrypt") && keyType.equalsIgnoreCase("3des")) {
          CK_MECHANISM mech = new CK_MECHANISM(CKM.DES3_ECB, null);
          encrypt(session, hKey, mech);
        } else if (operation.equalsIgnoreCase("decrypt") && keyType.equalsIgnoreCase("3des")) {
          CK_MECHANISM mech = new CK_MECHANISM(CKM.DES3_ECB, null);
          decrypt(session, hKey, mech);
        }
      }

    } catch (CKR_Exception ex) {
      ex.printStackTrace();

    } catch (Exception ex) {
      ex.printStackTrace();

    } finally {
      Cryptoki.C_Logout(session);
      Cryptoki.C_CloseSession(session);
      Cryptoki.C_Finalize(null);
    }
  }

  private static CK_OBJECT_HANDLE findKey(CK_SESSION_HANDLE session, CK_OBJECT_CLASS keyClass, CK_KEY_TYPE keyType,
      String keyName, boolean bPrivate) {
    /* array of one object handles */
    CK_OBJECT_HANDLE[] hObjects = { new CK_OBJECT_HANDLE() };

    /* to receive the number of objects located */
    LongRef objectCount = new LongRef();

    /* setup the template of the object to search for */
    //CK_ATTRIBUTE[] template = { new CK_ATTRIBUTE(CKA.CLASS, keyClass), new CK_ATTRIBUTE(CKA.KEY_TYPE, keyType),
    //    new CK_ATTRIBUTE(CKA.TOKEN, CK_BBOOL.TRUE), new CK_ATTRIBUTE(CKA.LABEL, keyName.getBytes()),
    //    new CK_ATTRIBUTE(CKA.PRIVATE, new CK_BBOOL(bPrivate)) };
    CK_ATTRIBUTE[] template = { new CK_ATTRIBUTE(CKA.TOKEN, CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.LABEL, keyName.getBytes()) };

    CryptokiEx.C_FindObjectsInit(session, template, template.length);

    CryptokiEx.C_FindObjects(session, hObjects, hObjects.length, objectCount);

    CryptokiEx.C_FindObjectsFinal(session);

    if (objectCount.value == 1) {
      /* return the handle of the located object */
      return hObjects[0];
    } else {
      /* return an object handle which is invalid */
      return new CK_OBJECT_HANDLE();
    }
  }

  private static void parseArgs(String[] args) {

    for (int i = 0; i < args.length; ++i) {

      if (args[i].equalsIgnoreCase("-keyType")) {
        if (++i >= args.length)
          usage();
        keyType = args[i];
      }

      else if (args[i].equalsIgnoreCase("-keyName")) {
        if (++i >= args.length)
          usage();
        keyName = args[i];
        //handle key names with sentinels at the end of the string
        if(keyName.charAt(keyName.length() - 1) != '\0') {
          keyName = keyName + '\0';
        }
      }

      else if (args[i].equalsIgnoreCase("-nosentinel")) {
        if (++i >= args.length)
          usage();
        keyName = args[i];
      }

      else if (args[i].equalsIgnoreCase("-slot")) {
        if (++i >= args.length) {
          usage();
        }
        //slotId = Integer.parseInt(args[i]);
        slotLabel = args[i];
      }

      else if (args[i].equalsIgnoreCase("-password")) {
        if (++i >= args.length) {
          usage();
        }
        password = args[i];
      }

      else if (args[i].equalsIgnoreCase("-fileName")) {
        if (++i >= args.length) {
          usage();
        }
        fileName = args[i];
      }

      else if (args[i].equalsIgnoreCase("-operation")) {
        if (++i >= args.length) {
          usage();
        } else if (args[i].equalsIgnoreCase("sign") || args[i].equalsIgnoreCase("verify")
            || args[i].equalsIgnoreCase("encrypt") || args[i].equalsIgnoreCase("decrypt")
            || args[i].equalsIgnoreCase("decryptRSA") || args[i].equalsIgnoreCase("dumpRSAPubKey")) {
          operation = args[i];
        } else {
          usage();
        }
      }

      else {
        usage();
      }
    }
    if (password.length() == 0 || keyType.length() == 0 || keyName.length() == 0 || fileName.length() == 0
        || operation.length() == 0) {
      usage();
    }
  }

  private static void sign(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE hKey, CK_MECHANISM mechanism) {

    String startString = new String("0123456789ABCDEF");
    byte[] OrigPlainText = startString.getBytes();
    LongRef lRefSign = new LongRef();
    byte[] signature = null;

    CryptokiEx.C_SignInit(session, mechanism, hKey);
    CryptokiEx.C_SignUpdate(session, OrigPlainText, OrigPlainText.length);
    CryptokiEx.C_SignFinal(session, null, lRefSign);
    signature = new byte[(int) lRefSign.value];
    CryptokiEx.C_SignFinal(session, signature, lRefSign);

    //println("signature:");
    //println(Arrays.toString(signature));
    try {
      Path file = Paths.get(fileName);
      Files.write(file, signature);
    } catch (IOException e) {
      System.out.println("An error occurred.");
      e.printStackTrace();
      System.out.flush();
    }
  }

  /**
   * toHex.
   */
  public static String toHex(byte[] digest) {
    String digits = "0123456789abcdef";
    StringBuilder sb = new StringBuilder(digest.length * 2);
    for (byte b : digest) {
      int bi = b & 0xff;
      sb.append(digits.charAt(bi >> 4));
      sb.append(digits.charAt(bi & 0xf));
    }
    return sb.toString();
  }

  private static void getModulusAndExponent(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE hKey) {


    CK_ATTRIBUTE[] template = { new CK_ATTRIBUTE(CKA.MODULUS, null, 0) };
    CryptokiEx.C_GetAttributeValue(session, hKey, template, template.length);
    template[0].pValue = new byte[(int) template[0].valueLen];
    CryptokiEx.C_GetAttributeValue(session, hKey, template, template.length);
    Path filePath = Paths.get("modulus");
    try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath.toFile()))) {
      writer.write(toHex((byte[]) template[0].pValue));
    } catch (IOException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }

    template[0] = new CK_ATTRIBUTE(CKA.PUBLIC_EXPONENT, null, 0);
    CryptokiEx.C_GetAttributeValue(session, hKey, template, template.length);
    template[0].pValue = new byte[(int) template[0].valueLen];
    CryptokiEx.C_GetAttributeValue(session, hKey, template, template.length);
    filePath = Paths.get("exponent");
    try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath.toFile()))) {
      writer.write(toHex((byte[]) template[0].pValue));
    } catch (IOException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }

  }

  private static void verify(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE hKey, CK_MECHANISM mechanism) {

    String startString = new String("0123456789ABCDEF");
    byte[] OrigPlainText = startString.getBytes();
    byte[] signature = null;
    try {
      Path file = Paths.get(fileName);
      signature = Files.readAllBytes(file);
    } catch (IOException e) {
      System.out.println("An error occurred.");
      e.printStackTrace();
      System.out.flush();
    }

    CryptokiEx.C_VerifyInit(session, mechanism, hKey);
    CryptokiEx.C_VerifyUpdate(session, OrigPlainText, OrigPlainText.length);
    CK_RV rv = CryptokiEx.C_VerifyFinal(session, signature, signature.length);

    if (rv.equals(CKR.OK)) {
      println("Able to verify data");
      System.out.flush();
    } else {
      println("Unable to verify data");
      System.out.flush();
    }
  }

  private static void encrypt(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE hKey, CK_MECHANISM mechanism) {
    String startString = "this is 16 bytes";
    byte[] plainText = startString.getBytes();
    byte[] cipherText = null;
    LongRef lRefEnc = new LongRef();

    CryptokiEx.C_EncryptInit(session, mechanism, hKey);
    CryptokiEx.C_Encrypt(session, plainText, plainText.length, null, lRefEnc);
    cipherText = new byte[(int) lRefEnc.value];
    CryptokiEx.C_Encrypt(session, plainText, plainText.length, cipherText, lRefEnc);

    println("cypherText:");
    println(Arrays.toString(cipherText));
    try {
      Path file = Paths.get(fileName);
      Files.write(file, cipherText);
    } catch (IOException e) {
      System.out.println("An error occurred.");
      e.printStackTrace();
      System.out.flush();
    }
  }

  private static void decrypt(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE hKey, CK_MECHANISM mechanism) {
    String startString = "this is 16 bytes";
    byte[] plainText = startString.getBytes();
    byte[] cipherText = null;
    LongRef lRefDec = new LongRef();

    try {
      Path file = Paths.get(fileName);
      cipherText = Files.readAllBytes(file);
    } catch (IOException e) {
      System.out.println("An error occurred.");
      e.printStackTrace();
    }

    CryptokiEx.C_DecryptInit(session, mechanism, hKey);
    CryptokiEx.C_Decrypt(session, cipherText, cipherText.length, null, lRefDec);
    plainText = new byte[(int) lRefDec.value];
    CryptokiEx.C_Decrypt(session, cipherText, cipherText.length, plainText, lRefDec);

    String endString = new String(plainText, 0, (int) lRefDec.value);
    if (startString.compareTo(endString) == 0) {
      println("Decrypted string matches original string");
      System.out.flush();
    } else {
      println("Decrypted string does not match original string");
      System.out.flush();
    }
  }

  private static void decryptRSA(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE hKey, CK_MECHANISM mechanism) {
    String startString = "0123456789ABCDEF";
    byte[] plainText = startString.getBytes();
    byte[] cipherText = null;
    LongRef lRefDec = new LongRef();

    try {
      Path file = Paths.get("message.encrypted");
      cipherText = Files.readAllBytes(file);
    } catch (IOException e) {
      System.out.println("An error occurred.");
      e.printStackTrace();
    }

    CryptokiEx.C_DecryptInit(session, mechanism, hKey);
    CryptokiEx.C_Decrypt(session, cipherText, cipherText.length, null, lRefDec);
    plainText = new byte[(int) lRefDec.value];
    CryptokiEx.C_Decrypt(session, cipherText, cipherText.length, plainText, lRefDec);

    String endString = new String(plainText, 0, (int) lRefDec.value);
    if (startString.compareTo(endString) == 0) {
      println("Decrypted string matches original string");
      System.out.flush();
    } else {
      println("Decrypted string does not match original string");
      System.out.flush();
    }
  }

}
