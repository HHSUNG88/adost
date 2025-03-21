package sample;

import com.safenetinc.jcprov.*;
import com.safenetinc.jcprov.constants.*;

/**
 * The class demonstrates the retrieval of Slot and Token Information.
 * <p>
 * Usage : java ...GetInfo (-slot, -token) [&lt;slotId&gt;]
 * <li>-info            retrieve the General information
 * <li>-slot            retrieve the Slot Information of the specified slot
 * <li>-token           retrieve the Token Information of the token in the specified slot
 * <li><i>slotId</i>    the related slot Id of the slot or token information to retrieve, default (all)
 */
public class GetInfo
{
    final static String fileVersion = "FileVersion: $Source: src/com/safenetinc/jcprov/sample/GetInfo.java $ $Revision: 1.1.1.2 $";

    /** easy access to System.out.println */
    static public void println(String s)
    {
        System.out.println(s);
    }

    /** display runtime usage of the class */
    public static void usage()
    {
        println("java ...GetInfo (-info, -slot, -token) [<slotId>]");
        println("");
        println("-info          get the General information");
        println("-slot          get the Slot Information of the specified slot");
        println("-token         get the Token Information of the token in the specified slot");
        println("<slotId>       related slot Id of the slot or token information to retrieve, default (all)");
        println("");

        System.exit(1);
    }

    /** main execution method */
    public static void main(String[] args)
    {
        long slotId = -1;
        boolean bGetGeneralInfo = false;
        boolean bGetSlotInfo = false;
        boolean bGetTokenInfo = false;

        /*
         * process command line arguments
         */

        for (int i = 0; i < args.length; ++i)
        {
            if (args[i].equalsIgnoreCase("-info"))
            {
                bGetGeneralInfo = true;
            }
            else if (args[i].equalsIgnoreCase("-slot"))
            {
                bGetSlotInfo = true;
            }
            else if (args[i].equalsIgnoreCase("-token"))
            {
                bGetTokenInfo = true;
            }
            else if(args[i].startsWith("-"))
            {
                usage();
            }
            else
            {
                /* assume that we have the slot id */

                try
                {
                    slotId = Integer.parseInt(args[i]);
                }
                catch (Exception ex)
                {
                    println("Invalid slotid :" + args[i]);
                    println("");
                    usage();
                }
            }
        }

        /* no work to do - error */
        if (!bGetGeneralInfo && !bGetSlotInfo && !bGetTokenInfo)
        {
            usage();
        }
        try
        {
            /*
             * Initialize Cryptoki so that the library takes care
             * of multithread locking
             */
            CK_RV rv = Cryptoki.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));
            if (bGetGeneralInfo)
            {
                DisplayGeneralInformation();
            }
            if (slotId == -1)
            {
                /* display information for all slots */
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
                    if (bGetSlotInfo)
                    {
                        DisplaySlotInformation(slotList[i]);
                    }

                    if (bGetTokenInfo)
                    {
                        DisplayTokenInformation(slotList[i]);
                    }
                }
            }
            else
            {
                if (bGetSlotInfo)
                {
                    DisplaySlotInformation(slotId);
                }

                if (bGetTokenInfo)
                {
                    DisplayTokenInformation(slotId);
                }
            }
        }
        catch (CKR_Exception ex)
        {
            /*
             * A Cryptoki related exception was thrown
             */
            ex.printStackTrace();
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
        finally
        {
            /*
             * All done with Cryptoki
             *
             * Note that we are not using CryptokiEx and we are not checking the
             * return value. This is because if we did not call C_Initialize successfully
             * then an error will be reported - and we don't really care because we are
             * shutting down.
             */
    		Cryptoki.C_Finalize(null);
        }
    }

    static String versionString(CK_VERSION version)
    {
        if (version.minor < 10)
            return version.major + ".0" + version.minor;
        else
            return version.major + "." + version.minor;
    }

    static void DisplayGeneralInformation()
    {
        CK_INFO info = new CK_INFO();

        println("General Info");

        CryptokiEx.C_GetInfo(info);

        println("   Cryptoki Version   :" + versionString(info.cryptokiVersion));
        println("   Manufacturer       :" + new String(info.manufacturerID));
        println("   Library Description:" + new String(info.libraryDescription));
        println("   Library Version    :" + versionString(info.libraryVersion));
    }

    static void DisplaySlotInformation(long slotId)
    {
        CK_SLOT_INFO info = new CK_SLOT_INFO();
        String flagString = "";

        println("Slot ID " + slotId);

        CryptokiEx.C_GetSlotInfo(slotId, info);

        println("   Description     :" + new String(info.slotDescription));
        println("   Manufacturer    :" + new String(info.manufacturerID));
        println("   Hardware Version:" + versionString(info.hardwareVersion));
        println("   Firmware Version:" + versionString(info.firmwareVersion));

        if ((info.flags & CKF.TOKEN_PRESENT) > 0)
            flagString = "TokenPresent ";

        if ((info.flags & CKF.REMOVABLE_DEVICE) > 0)
            flagString += "RemovableDevice ";

        if ((info.flags & CKF.HW_SLOT) > 0)
            flagString += "Hardware";

        if (flagString.length() == 0)
            println("   Flags           :<none>");
        else
            println("   Flags           :" + flagString);

        println("");
    }

    static void DisplayTokenInformation(long slotId)
    {
        CK_TOKEN_INFO info = new CK_TOKEN_INFO();
        String flagString = "";

        println("Token for Slot ID " + slotId);

        CryptokiEx.C_GetTokenInfo(slotId, info);

        println("   Label           :" + new String(info.label));
        println("   Manufacturer    :" + new String(info.manufacturerID));
        println("   Model           :" + new String(info.model));
        println("   Serial Number   :" + new String(info.serialNumber));
        println("   Hardware Version:" + versionString(info.hardwareVersion));
        println("   Firmware Version:" + versionString(info.firmwareVersion));
        println("   Clock (GMT)     :" + new String(info.utcTime));
        println("   Sessions        :" + info.sessionCount + " out of " + info.maxSessionCount);
        println("   RW Sessions     :" + info.rwSessionCount + " out of " + info.maxRwSessionCount);
        println("   PIN Length      :" + info.minPinLen + " to " + info.maxPinLen);
        println("   Public Memory   :" + info.freePublicMemory + " free, " + info.totalPublicMemory + " total");
        println("   Private Memory  :" + info.freePrivateMemory + " free, " + info.totalPrivateMemory + " total");

        if ((info.flags & CKF.TOKEN_INITIALIZED) > 0)
            flagString += "TokenInitialised ";

        if ((info.flags & CKF.RNG) > 0)
            flagString += "RNG ";

        if ((info.flags & CKF.WRITE_PROTECTED) > 0)
            flagString += "WriteProtected ";

        if ((info.flags & CKF.LOGIN_REQUIRED) > 0)
            flagString += "LoginRequired ";

        if ((info.flags & CKF.USER_PIN_INITIALIZED) > 0)
            flagString += "UserPINInitialised ";

        /* and so on ... */

        if (flagString.length() == 0)
            println("   Flags           :<none> (and maybe more)");
        else
            println("   Flags           :" + flagString + " (and maybe more)");

        println("");
    }
}
