package sample;

import com.safenetinc.jcprov.*;
import com.safenetinc.jcprov.constants.*;

/**
 * The class demonstrates the retrieval of the full firmware version.
 * <p>
 * Usage : java ...GetFirmwareVersion [-slot &lt;slotId&gt;]
 *
 * <li><i>slotId</i>   slot containing the token.
 */
public class GetFirmwareVersion
{
    /** easy access to System.out.println */
    static public void println(String s)
    {
        System.out.println(s);
    }

    /** display runtime usage of the class */
    public static void usage()
    {
        println("java ...GetFirmwareVersion -slot <slotId>\n");
        println("");

        System.exit(1);
    }

    /** main execution method */
    public static void main(String[] args)
    {
        long slotId = -1;

        /*
         * process command line arguments
         */

        for (int i = 0; i < args.length; ++i)
        {
            if(args[i].equalsIgnoreCase("-slot"))
            {
                if (++i >= args.length)
                    usage();

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
            else
            {
                usage();
            }
        }

        try
        {
            /*
             * Initialize Cryptoki so that the library takes care
             * of multithread locking
             */
            CK_RV rv = CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));

            if (slotId == -1)
            {
                /* display firmware version for all available slots */
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
                    // Retrieve and display full firmware version
                    DisplayFullFirmwareVersion(slotList[i]);
                }
            }
            else {
                // Retrieve and display full firmware version
                DisplayFullFirmwareVersion(slotId);
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
    
    // **********************************************
    // Retrieve and display full firmware version
    // **********************************************

    static void DisplayFullFirmwareVersion(long slotId)
    {

        LongRef major = new LongRef();
        LongRef minor = new LongRef();
        LongRef subminor = new LongRef();

        // Use the extended API to get full firmware version.
        CryptokiEx.CA_GetFirmwareVersion(slotId, major, minor, subminor);
        // Display them.
        println("Full Firmware Version:" + (int)major.value + "." + (int)minor.value + "." + (int)subminor.value);
    }

}
