/*
 * Copyright (c) 2018 SafeNet. All rights reserved.
 *
 * This file contains information that is proprietary to SafeNet and may not be
 * distributed or copied without written consent from SafeNet.
 */

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
import com.safenetinc.jcprov.constants.CKM;
import com.safenetinc.jcprov.constants.CKO;
import com.safenetinc.jcprov.constants.CKU;

/**
 * This class demonstrates the performance of the Jcprov interface.
 *
 * It 1. Caches the 3DES Key 2. Performs a SHA1 Hash to generate the IV 3. Runs multiple threads
 */
public class PerformanceTest implements Runnable {

    static public void println(String s) {
        System.out.println(s);
    }

    public static void usage() {
        println("java PerformanceTest [-slot <slotId>] [-password <password>]"
            + " [-keyName <keyname>] [-numThreads <numThreads>] [-v]");
        println("");
        println("<slotId>   slot containing the token with the key to use - " +
            "default (1)");
        println("<password> user password of the slot. If specified, a " +
            "private key is used.");
        println("<keyname>      name of key to use (default 'des3Key')");
        println("<numthreads>   number of threads to start (default 1)");
        println("-v             verbose mode");

        System.exit(1);
    }

    /**
     * verbose flag
     */
    static boolean _verbose;

    /**
     * Shared Slot to work on.
     */
    static long _slot;

    /**
     * Shared Session handle - should not be used by threads for cipher or digest operations.
     */
    static CK_SESSION_HANDLE _session;

    /**
     * Shared Key handle - for performance reasons.
     *
     * Each thread should create it's own session to use with the key
     */
    static CK_OBJECT_HANDLE _key;

    /**
     * Crypto User password for the slot.
     */
    static String password = "";

    public static void main(String[] args) {
        int numThreads = 1;
        String keyName = "des3Key";
        _slot = 1;
        _verbose = false;

        /*
         * process command line arguments
         */

        for (int i = 0; i < args.length; ++i) {
            if (args[i].equalsIgnoreCase("-keyName")) {
                if (++i >= args.length) {
                    usage();
                }

                keyName = args[i];
            } else if (args[i].equalsIgnoreCase("-numThreads")) {
                if (++i >= args.length) {
                    usage();
                }

                numThreads = Integer.parseInt(args[i]);
            } else if (args[i].equalsIgnoreCase("-v")) {
                _verbose = true;
            } else if (args[i].equalsIgnoreCase("-slot")) {
                if (++i >= args.length) {
                    usage();
                }

                _slot = Integer.parseInt(args[i]);
            } else if (args[i].equalsIgnoreCase("-password")) {
                if (++i >= args.length) {
                    usage();
                }

                password = args[i];
            } else {
                usage();
            }
        }

        try {
            /*
             * Initialize jcprov
             */
            CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));

            /*
             * Set up the global shared Session.
             *
             * This session should not be used by threads for cipher or
             * digest operations - as the session maintains the state.
             */
            _session = new CK_SESSION_HANDLE();

            CryptokiEx.C_OpenSession(_slot, CKF.RW_SESSION | CKF.SERIAL_SESSION,
                null, null, _session);
            CryptokiEx.C_Login(_session, CKU.USER, password.getBytes(), password.length());

            /*
             * Set up the global shared Key.
             *
             * This is a time saver, but every thread must create it's own session
             * to use with the key, as the session maintains the cipher state.
             */
            _key = findKey(_session, keyName);

            /*
             * No key found, create a new one.
             */
            if (!_key.isValidHandle()) {
                _key = createKey(_session, keyName);
            }

            /*
             * do a test call to make sure everything works
             */
            doTest();

            /*
             * create and start the threads
             */

            println("starting " + numThreads + " thread(s)");

            Thread[] threads = new Thread[numThreads];

            for (int i = 0; i < numThreads; ++i) {
                threads[i] = new Thread(new PerformanceTest());
            }

            long startTime = System.currentTimeMillis();

            for (int i = 0; i < numThreads; ++i) {
                threads[i].start();
            }

            /*
             * wait for the threads to terminate
             */

            for (int i = 0; i < numThreads; ++i) {
                threads[i].join();
            }

            long elapsedTime = System.currentTimeMillis() - startTime;
            double avgThreadTime = (double) elapsedTime / numThreads;

            println("Application Execution Time: " + elapsedTime
                + " gives avgThreadTime: " + avgThreadTime);
        } catch (CKR_Exception ex) {
            ex.printStackTrace();
        } catch (Exception ex) {
            ex.printStackTrace();
        } finally {
            /*
             * all done with jcprov
             */
            Cryptoki.C_CloseSession(_session);
            Cryptoki.C_Finalize(null);
        }
    }

    /**
     * Create a new key.
     */
    static CK_OBJECT_HANDLE createKey(CK_SESSION_HANDLE session, String keyName) {
        CK_OBJECT_HANDLE newKey = new CK_OBJECT_HANDLE();

        CK_ATTRIBUTE[] template = {
            new CK_ATTRIBUTE(CKA.LABEL, keyName.getBytes()),
            new CK_ATTRIBUTE(CKA.TOKEN, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.CLASS, CKO.SECRET_KEY),
            new CK_ATTRIBUTE(CKA.DERIVE, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.EXTRACTABLE, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.ENCRYPT, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.DECRYPT, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.SIGN, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.VERIFY, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.WRAP, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.UNWRAP, CK_BBOOL.TRUE)
        };

        CryptokiEx.C_GenerateKey(session, new CK_MECHANISM(CKM.DES3_KEY_GEN),
            template, template.length, newKey);

        return newKey;
    }

    /**
     * find a key given the label
     */
    static CK_OBJECT_HANDLE findKey(CK_SESSION_HANDLE session, String keyName) {
        CK_ATTRIBUTE[] tpl =
            {
                new CK_ATTRIBUTE(CKA.LABEL, keyName.getBytes())
            };

        CK_OBJECT_HANDLE[] hObjects = {new CK_OBJECT_HANDLE()};
        LongRef objectCount = new LongRef();

        CryptokiEx.C_FindObjectsInit(session, tpl, tpl.length);

        CryptokiEx.C_FindObjects(session, hObjects, hObjects.length, objectCount);

        CryptokiEx.C_FindObjectsFinal(session);

        if (objectCount.value == 1) {
            return hObjects[0];
        } else {
            return new CK_OBJECT_HANDLE();
        }
    }

    /**
     * the actual test
     *
     * a SHA512 hash followed by a 3DES Encryption
     */
    static void doTest() throws Exception {
        CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
        LongRef lRef = new LongRef();

        /*
         * Open a session on the slot.
         *
         * This is a thread based object because it maintains the cipher and
         * digest state relevant to this thread
         */

        CryptokiEx.C_OpenSession(_slot, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null, session);

        /*
         * do a SHA hash to get the IV
         */

        CK_MECHANISM shaMech = new CK_MECHANISM(CKM.SHA512);

        String strToDigest = "They call me the Count, because I love to count.";
        byte[] digestIn = strToDigest.getBytes();

        byte[] digest = new byte[64];

        CryptokiEx.C_DigestInit(session, shaMech);

        lRef.value = digest.length;
        CryptokiEx.C_Digest(session, digestIn, digestIn.length, digest, lRef);

        /*
         * set up the cipher => Luna only allows digest block of size 8
         */
        CK_MECHANISM desMech = new CK_MECHANISM(CKM.DES3_CBC_PAD, digest, 8/*lRef.value*/);

        CryptokiEx.C_EncryptInit(session, desMech, _key);

        /*
         * do it
         */

        String strData = "f:fn_b,some_flag:false,u:jane";
        byte[] inData = strData.getBytes();
        byte[] outData = new byte[inData.length * 2];

        lRef.value = outData.length;
        CryptokiEx.C_Encrypt(session, inData, inData.length, outData, lRef);
    }

    /**
     * the actual worker thread
     *
     * this thread does a hash and then an encrypt
     */
    public void run() {
        String name = Thread.currentThread().getName();

        long startTime = System.currentTimeMillis();

        try {
            /*
             * run the test
             */
            doTest();
        } catch (Exception ex) {
            println(name + " Exception:" + ex);
        } finally {
            long elapsedTime = System.currentTimeMillis() - startTime;

            if (_verbose) {
                println(name + " execution time :" + elapsedTime);
            }
        }
    }
}
