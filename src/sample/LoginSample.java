package sample;

import com.safenetinc.jcprov.CK_C_INITIALIZE_ARGS;
import com.safenetinc.jcprov.CK_SESSION_HANDLE;
import com.safenetinc.jcprov.Cryptoki;
import com.safenetinc.jcprov.CryptokiEx;
import com.safenetinc.jcprov.constants.CKF;
import com.safenetinc.jcprov.constants.CKU;

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
public class LoginSample
{
  static public void println(String s) {
    System.out.println(s);
  }

  /** display runtime usage of the class */
  public static void usage() {
    println("java ...LoginSample -slot <slotId> -password <password>\n");
    println("");

    System.exit(1);
  }



  private CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
  private static long slotId = 5;
  private static String password = "";
  private boolean bPrivate = false;

  void loginLogout()
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
//        CryptokiEx.C_Login(session, CKU.USER, password.getBytes(), password.length());
//        CryptokiEx.C_Login(session, CKU.CRYPTO_USER, password.getBytes(), password.length());
        CryptokiEx.C_Login(session, CKU.LIMITED_CRYPTO_OFFICER, password.getBytes(), password.length());

      }
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

    LoginSample aSample = new LoginSample();
    aSample.loginLogout();

  }

}
