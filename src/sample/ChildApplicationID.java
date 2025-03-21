
import com.safenetinc.jcprov.CK_C_INITIALIZE_ARGS;
import com.safenetinc.jcprov.CK_SESSION_HANDLE;
import com.safenetinc.jcprov.CK_SESSION_INFO;
import com.safenetinc.jcprov.Cryptoki;
import com.safenetinc.jcprov.CryptokiEx;
import com.safenetinc.jcprov.constants.CKF;
import com.safenetinc.jcprov.constants.CKS;

/**
 * This class demonstrates how a second process uses CA_SetApplicationID to
 * share a token login.
 * <p>
 * usage: java ...ChildApplicationID -slot &lt;slotID&rt; -major &lt;majorID&rt;
 * -minor &lt;minorID&rt;
 * <li><i>slotID</i> slot number for shared login
 * <li><i>majorID</i> the major application ID value
 * <li><i>minorID</i> the minor application ID value
 */
public class ChildApplicationID {

  /** display runtime usage of the class */
  public static void usage() {
    System.out.println("");
    System.out.println("java ...ChildApplicationID -slot <slotID> -major <majorID> -minor <minorID>");
    System.out.println("");
    System.out.println("<slotID>  slot number for shared login");
    System.out.println("<majorID> the major application ID value");
    System.out.println("<minorID> the minor application ID value");
    System.out.println("");
    System.exit(1);
  }

  /** main execution method */
  public static void main(String[] args) {
    CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
    CK_SESSION_INFO info = new CK_SESSION_INFO();
    long slotID = 1;
    long majorID = 1;
    long minorID = 1;

    for (int i = 0; i < args.length; ++i) {
      if (args[i].equalsIgnoreCase("-major")) {
        if (++i >= args.length) {
          usage();
        }
        majorID = Integer.parseInt(args[i]);
      } else if (args[i].equalsIgnoreCase("-minor")) {
        if (++i >= args.length) {
          usage();
        }
        minorID = Integer.parseInt(args[i]);
      } else if (args[i].equalsIgnoreCase("-slot")) {
        if (++i >= args.length) {
          usage();
        }
        slotID = Integer.parseInt(args[i]);
      } else {
        usage();
      }
    }

    try {

      System.out.println();
      System.out.println("Ensure you first run some variant of: ");
      System.out.println("  /usr/safenet/lunaclient/bin/salogin -v -o -s 0 -i 1:1 -p userpin1");
      System.out.println("OR");
      System.out.println("  ApplicationID -slot 0 -password userpin1 -major 1 -minor 1");
      System.out.println();

      CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));

      CryptokiEx.CA_SetApplicationID(majorID, minorID);

      CryptokiEx.C_OpenSession(slotID, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null, session);

      CryptokiEx.C_GetSessionInfo(session, info);

      if (info.state.equals(CKS.RW_USER_FUNCTIONS)) {
        System.out.println("logged in to slot " + info.slotID);
      } else {
        System.out.println("user not logged in");
      }
      Cryptoki.C_CloseSession(session);
      Cryptoki.C_Finalize(null);
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }
}
