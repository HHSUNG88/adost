
import com.safenetinc.jcprov.*;
import com.safenetinc.jcprov.constants.*;

/**
 * Sample program to show use of different ways to handle multi-threading.
 * <p>
 * This progam initialises the Cryptoki library according to the specified locking
 * model. Then a shared handle to the specified key is created. The specified number
 * of threads are started, where each thread opens a session and then enters a loop which
 * does a triple DES encryption operation using the shared key handle.
 * <p>
 * It is assumed that the key exists and is a Public Token object.
 * <p>
 * Usage : java ...Threading -numThreads &lt;numthreads&gt; -keyName &lt;keyname&gt; -locking &lt;lockingmodel&gt;
 *                           -duration &gt;duration&lt; -password &gt;userpin&lt; -slot &gt;slotId&lt; [-v]
 *
 * <li><i>numthreads</i>    number of threads to start
 * <li><i>keyname</i>       name of the Triple DES key to use for encryption operation
 * <li><i>lockingmodel</i>  locking model, one of : none, OS, functions
 * <li><i>duration</i>      execution time, in seconds
 * <li><i>slotId</i>        slot containing the token.
 * <li><i>password</i>      user password of the slot.
 * <li>-v                   verbose mode
 */
public class Threading implements Runnable
{
    /** shared slot id of the key to use */
    static long _slotId = 0;

    /** shared key handle */
    static CK_OBJECT_HANDLE _hKey;

    /** flag to indicate termination of tests */
    static boolean _die;

    /** flag to indicate verbose mode of operation */
    static boolean _bVerbose;

    /** flag to indicate that the user pin has been provided */
    static boolean _bLogin;

    /** easy access to System.out.println */
    static public void println(String s)
    {
        System.out.println(s);
    }

    /**
     * Simple little re-entrant Mutex for testing purposes - not to be used in production code.
     *
     * Note the user supplied Mutex MUST BE re-entrant - otherwise the application will lock up.
     *
     * Re-entrant means that a thread may acquire the lock several times - it must also
     * releases the lock an equivalent number of times.
     */
    static class Mutex
    {
        /** thread which has the mutex locked */
        protected Thread m_owner = null;

        /** number of times the mutex is locked */
        protected long m_holds = 0;

        /**
         * Lock the mutex.
         */
        public void lock() throws InterruptedException
        {
            if (Thread.interrupted())
            {
                throw new InterruptedException();
            }

            Thread caller = Thread.currentThread();

            synchronized(this)
            {
                if (caller == m_owner)
                {
                    ++m_holds;
                }
                else
                {
                    try
                    {
                        while (m_owner != null)
                        {
                            wait();
                        }

                        m_owner = caller;
                        m_holds = 1;
                    }
                    catch (InterruptedException ex)
                    {
                        notify();
                        throw ex;
                    }
                }
            }
        }

        /**
         * Unlock the mutex.
         */
        public synchronized void unlock()
        {
            if (Thread.currentThread() != m_owner)
            {
                throw new Error("Illegal Lock usage");
            }

            if (--m_holds == 0)
            {
                m_owner = null;
                notify();
            }
        }
    }

    /**
     * Class to provide the CreateMutex function
     */
    static class CreateMutex implements CK_C_INITIALIZE_ARGS.CK_CREATEMUTEX
    {
        public Object CreateMutex()
        {
            return new Mutex();
        }
    }

    /**
     * Class to provide the DestroyMutex function
     */
    static class DestroyMutex implements CK_C_INITIALIZE_ARGS.CK_DESTROYMUTEX
    {
        public long DestroyMutex(Object mutex)
        {
            return CKR.OK.longValue();
        }
    }

    /**
     * Class to provide the LockMutex function
     */
    static class LockMutex implements CK_C_INITIALIZE_ARGS.CK_LOCKMUTEX
    {
        public long LockMutex(Object mutex)
        {
            CK_RV rv = CKR.OK;

            try
            {
                Mutex m = (Mutex)mutex;

                m.lock();
            }
            catch (Exception ex)
            {
                rv = CKR.CANT_LOCK;
            }
            finally
            {
                return rv.longValue();
            }
        }
    }

    /**
     * Class to provide the UnlockMutex function
     */
    static class UnlockMutex implements CK_C_INITIALIZE_ARGS.CK_UNLOCKMUTEX
    {
        public long UnlockMutex(Object mutex)
        {
            Mutex m = (Mutex)mutex;

            m.unlock();

            return CKR.OK.longValue();
        }
    }

    /** display runtime usage of the class */
    public static void usage()
    {
        println("java ...Threading -numThreads <numthreads> -keyName <keyname> -locking <lockingmodel> -duration <duration> -password <password> -slot <slotId> [-v]");
        println("");
        println("<numthreads>   number of threads to start");
        println("<keyname>      name of the Triple DES key to use");
        println("<lockingmodel> locking model, one of none, OS, functions");
        println("<duration>     execution time, in seconds");
        println("<password>      the user pin for the slot");
        println("<slotId>       the slot id to use");
        println("-v             verbose mode");
        println("");

        System.exit(1);
    }

    /** main execution method */
    public static void main(String[] args)
    {
        int numThreads = 0;
        String userPin = "";
        String keyName = "";
        boolean bNone = false;
        boolean bOSLocking = false;
        boolean bFunctions = false;
        CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();

        /*
         * process command line arguments
         */

        int duration = -1;

        for (int i = 0; i < args.length; ++i)
        {
            if (args[i].equalsIgnoreCase("-numThreads"))
            {
                if (++i >= args.length)
                    usage();

                numThreads = Integer.parseInt(args[i]);
            }
            else if (args[i].equalsIgnoreCase("-password"))
            {
                if (++i >= args.length)
                    usage();

                userPin = args[i];

                _bLogin = true;
            }
            else if (args[i].equalsIgnoreCase("-keyName"))
            {
                if (++i >= args.length)
                    usage();

                keyName = args[i];
            }
            else if(args[i].equalsIgnoreCase("-locking"))
            {
                if (++i >= args.length)
                    usage();

                if (args[i].equalsIgnoreCase("none"))
                    bNone = true;
                if (args[i].equalsIgnoreCase("OS"))
                    bOSLocking = true;
                if (args[i].equalsIgnoreCase("functions"))
                    bFunctions = true;
            }
            else if (args[i].equalsIgnoreCase("-duration"))
            {
                if (++i >= args.length)
                    usage();

                duration = Integer.parseInt(args[i]);
            }
            else if (args[i].equalsIgnoreCase("-slot"))
            {
                if (++i >= args.length)
                    usage();

                _slotId = Long.parseLong(args[i]);
            }
            else if(args[i].equalsIgnoreCase("-v"))
            {
                _bVerbose = true;
            }
            else
            {
                usage();
            }
        }

        if (numThreads == 0 || keyName.length() == 0)
            usage();

        try
        {
            if (bNone)
            {
                /* initialise Cryptoki to do no locking */
                CryptokiEx.C_Initialize(null);
            }
            else if (bOSLocking)
            {
                /* initialise Cryptoki to provide it's own locking */
                CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));
            }
            else if (bFunctions)
            {
                /* initialise Cryptoki to use the provided locking mechanism */
                CryptokiEx.C_Initialize(
                        new CK_C_INITIALIZE_ARGS(new CreateMutex(),
                                                 new DestroyMutex(),
                                                 new LockMutex(),
                                                 new UnlockMutex())
                );
            }
            else
            {
                usage();
            }

            /* Open a session */
            CryptokiEx.C_OpenSession(_slotId, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null, session);

            /* Login to the session if a user pin has been provided */
            if (_bLogin)
            {
                CryptokiEx.C_Login(session, CKU.USER, userPin.getBytes(), userPin.length());
            }

            /* Locate the key to use */
            _hKey = findKey(session, keyName);

            /*
             * Start the threads
             */

            /* let threads live */
            _die = false;

            Thread[] threads = new Thread[numThreads];

            println("Starting " + numThreads + " threads");

            /* Create and start the thread objects */
            for (int i = 0; i < numThreads; ++i)
            {
                threads[i] = new Thread(new Threading());
                threads[i].start();
            }

            if (duration < 0)
            {
                println("Press enter key to end.");

                /* wait for the enter key */
                int ch = System.in.read();
            }
            else
            {
                if (duration != 1)
                {
                    println("Running for " + duration + " seconds.");
                }
                else
                {
                    println("Running for one second.");
                }

                /* Block for the specified duration. */
                Thread.sleep(1000*duration);
            }

            /* tell threads to end */
            _die = true;

            println("Waiting for threads to terminate");

            /* wait for threads to die */
            for (int i = 0; i < numThreads; ++i)
            {
                threads[i].join();
            }

            /* all done */
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
        finally
        {
            /*
             * Close the session.
             *
             * Note that we are not using CryptokiEx and we are not checking the
             * return value. This is because if the session is not currently open then an
             * error will be reported - and we don't really care because we are shutting down.
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


    /**
     * The Thread.
     * <p>
     * Each thread should have it's own session, so that the cipher state of the session
     * is not corrupted by other threads.
     * <p>
     */
    public void run()
    {
        String name = Thread.currentThread().getName();

        CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
        CK_MECHANISM mechanism = new CK_MECHANISM(CKM.DES3_ECB);

        byte[] data = "This is 16 Bytes".getBytes();
        byte[] cipher = null;
        LongRef lRef = new LongRef();

        try
        {
            if (_bVerbose) println(name + " openSession");
            CryptokiEx.C_OpenSession(_slotId, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null, session);

            while (!_die)
            {
                if (_bVerbose) println(name + " encryptInit");

                CryptokiEx.C_EncryptInit(session, mechanism, _hKey);

                /* do a length prediction */
                lRef.value = 0;

                CryptokiEx.C_Encrypt(session, data, data.length, null, lRef);

                /* allocate space */
                cipher = new byte[(int)lRef.value];

                /* do the encryption */
                if (_bVerbose) println(name + " encrypt");

                CryptokiEx.C_Encrypt(session, data, data.length, cipher, lRef);

                /* we don't actually want to do anything with the result */
                cipher = null;
            }
        }
        catch(CKR_Exception ex)
        {
            ex.printStackTrace();
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
        finally
        {
            /*
             * Close the session.
             *
             * Note that we are not using CryptokiEx and we are not checking the
             * return value. This is because if the session is not currently open then an
             * error will be reported - and we don't really care because we are shutting down.
             */
            Cryptoki.C_CloseSession(session);
        }

        println(name + " terminated");
    }

    /**
     * find a key given the label
     */
    static CK_OBJECT_HANDLE findKey(CK_SESSION_HANDLE session, String keyName)
    {
        CK_ATTRIBUTE[] tpl =
        {
            new CK_ATTRIBUTE(CKA.LABEL, keyName.getBytes())
        };

        CK_OBJECT_HANDLE[] hObjects = {new CK_OBJECT_HANDLE()};
        LongRef objectCount = new LongRef();

        CryptokiEx.C_FindObjectsInit(session, tpl, tpl.length);

        CryptokiEx.C_FindObjects(session, hObjects, hObjects.length, objectCount);

        CryptokiEx.C_FindObjectsFinal(session);

        if (objectCount.value == 1)
        {
            return hObjects[0];
        }
        else
        {
            return new CK_OBJECT_HANDLE();
        }
    }
}
