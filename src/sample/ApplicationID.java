
/*
 * Copyright (c) 2018 SafeNet. All rights reserved.
 *
 * This file contains information that is proprietary to SafeNet and may not be
 * distributed or copied without written consent from SafeNet.
 */

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

import com.safenetinc.jcprov.CK_C_INITIALIZE_ARGS;
import com.safenetinc.jcprov.CK_SESSION_HANDLE;
import com.safenetinc.jcprov.CK_SESSION_INFO;
import com.safenetinc.jcprov.Cryptoki;
import com.safenetinc.jcprov.CryptokiEx;
import com.safenetinc.jcprov.constants.CKF;
import com.safenetinc.jcprov.constants.CKS;
import com.safenetinc.jcprov.constants.CKU;

/**
 * This class demonstrates the use of application IDs to perform a shared login.
 * </p>
 * Usage: java ...ApplicationID -slot &lt;slotID&rt; -major &lt;majorID&rt;
 * -minor &lt;minorID&rt; -password &lt;password&rt;
 * <li><i>slotID</i> slot to perform login sharing on - default (1)
 * <li><i>majorID</i> application ID major value - default (1)
 * <li><i>minorID</i> application ID minor value - default (1)
 * <li><i>password</i> user password for the slot
 */
public class ApplicationID {

  /** display runtime usage of the class */
  public static void usage() {
    System.out.println("");
    System.out.println("java ...ApplicationID -slot <slotID> -major <majorID> -minor <minorID> -password <password>");
    System.out.println("<slotID>   slot to perform login sharing on - default (1)");
    System.out.println("<majorID>  application ID major value - default (1)");
    System.out.println("<minorID>  application ID minor value - default (1)");
    System.out.println("<password> user password for the slot");
    System.out.println("");
    System.exit(1);
  }

  /**
   * Spawn a child process with the given application ID
   *
   * @param slot  slot to log in to
   *
   * @param major major application ID value
   *
   * @param minor minor application ID value
   *
   */
  public static void callChild(long slot, long major, long minor) throws Exception {
    // Spawn a second process
    System.out.println("");
    Process p = new ProcessBuilder("java", "ChildApplicationID", "-slot", Long.toString(slot), "-major",
        Long.toString(major), "-minor", Long.toString(minor)).start();
    InputStream child_output = p.getInputStream();
    InputStreamReader r = new InputStreamReader(child_output);
    BufferedReader in = new BufferedReader(r);

    String line;
    while ((line = in.readLine()) != null) {
      System.out.println("Child:: " + line);
    }
    System.out.println("");
  }

  /** main execution method */
  public static void main(String[] args) {
    CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
    CK_SESSION_INFO info = new CK_SESSION_INFO();
    long slotID = 1;
    long majorID = 1;
    long minorID = 1;
    String password = "";

    for (int i = 0; i < args.length; ++i) {
      if (args[i].equalsIgnoreCase("-slot")) {
        if (++i >= args.length) {
          usage();
        }
        slotID = Long.parseLong(args[i]);
      } else if (args[i].equalsIgnoreCase("-major")) {
        if (++i >= args.length) {
          usage();
        }
        majorID = Long.parseLong(args[i]);
      } else if (args[i].equalsIgnoreCase("-minor")) {
        if (++i >= args.length) {
          usage();
        }
        minorID = Long.parseLong(args[i]);
      } else if (args[i].equalsIgnoreCase("-password")) {
        if (++i >= args.length) {
          usage();
        }
        password = args[i];
      } else {
        usage();
      }
    }
    if (password.length() == 0) {
      usage();
    }

    try {
      CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));

      // Set the application ID and set to open
      CryptokiEx.CA_SetApplicationID(majorID, minorID);
      CryptokiEx.CA_OpenApplicationID(slotID, majorID, minorID);

      CryptokiEx.C_OpenSession(slotID, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null, session);
      CryptokiEx.C_Login(session, CKU.USER, password.getBytes(), password.length());

      CryptokiEx.C_GetSessionInfo(session, info);
      if (info.state.equals(CKS.RW_USER_FUNCTIONS)) {
        System.out.println("Parent:: Logged in to slot  " + info.slotID);
      }

      // Close the session but leave the application ID open
      Cryptoki.C_CloseSession(session);
      Cryptoki.C_Finalize(null);

      System.out.println("Parent:: Logged out (application ID session open)");

      callChild(slotID, majorID, minorID);

      // Cleanup by closing application id
      CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));
      CryptokiEx.CA_CloseApplicationID(slotID, majorID, minorID);

      System.out.println("Parent:: Application ID session closed");
      Cryptoki.C_Finalize(null);
      callChild(slotID, majorID, minorID);
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }
}
