package sample;

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
import com.safenetinc.jcprov.constants.CKG;
import com.safenetinc.jcprov.constants.CKK;
import com.safenetinc.jcprov.constants.CKM;
import com.safenetinc.jcprov.constants.CKO;
import com.safenetinc.jcprov.constants.CKU;
import com.safenetinc.jcprov.params.CK_BIP32_CHILD_DERIVE_PARAMS;
import com.safenetinc.jcprov.params.CK_BIP32_MASTER_DERIVE_PARAMS;

import java.util.Arrays;
import java.util.Random;

public class BIP32KeyDeriveSample
{
    private class Bip32KeyPair
    {
        Bip32KeyPair( CK_BIP32_MASTER_DERIVE_PARAMS params )
        {
            this.publicKey = params.hPublicKey;
            this.privateKey = params.hPrivateKey;
        }

        Bip32KeyPair( CK_BIP32_CHILD_DERIVE_PARAMS params )
        {
            this.publicKey = params.hPublicKey;
            this.privateKey = params.hPrivateKey;
            this.errorCode = params.ulPathErrorIndex;
        }

        CK_OBJECT_HANDLE publicKey;
        CK_OBJECT_HANDLE privateKey;
        int errorCode;
    }

    /**
     * display runtime usage of the class
     */
    public static void usage()
    {
        System.out.println( "java ...BIP32KeyDeriveSample -slot <slotId> -password <password>%n" );
        System.out.println();
        System.exit( 1 );
    }

    private CK_OBJECT_HANDLE hAESKey = new CK_OBJECT_HANDLE();
    private CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
    private static long slotId = 4;
    private static String password = "userpin";

    // ===================================================================

    public static byte[] hexStringToByteArray( String s )
    {
        int len = s.length();
        byte[] data = new byte[ len / 2 ];
        for ( int i = 0; i < len; i += 2 )
        {
            data[ i / 2 ] = ( byte ) ( ( Character.digit( s.charAt( i ), 16 ) << 4 )
                                       + Character.digit( s.charAt( i + 1 ), 16 ) );
        }
        return data;
    }

    private void openLoginSession()
    {
        /*
         * Initialize Cryptoki so that the library takes care of multithread
         * locking
         */
        CryptokiEx.C_Initialize( new CK_C_INITIALIZE_ARGS( CKF.OS_LOCKING_OK ) );

        /*
         * Open a session
         */
        CryptokiEx.C_OpenSession( slotId, CKF.RW_SESSION | CKF.SERIAL_SESSION,
                                  null, null, session );

        /*
         * Login - if we have a password
         */
        if ( password.length() > 0 )
        {
            CryptokiEx.C_Login( session, CKU.USER, password.getBytes(),
                                password.length() );
        }

    }

    private void closeLogoutSession()
    {
        /*
         * Logout in case we logged in.
         *
         * Note that we are not using CryptokiEx and we are not checking the
         * return value. This is because if we did not log in then an error will
         * be reported - and we don't really care because we are shutting down.
         */
        Cryptoki.C_Logout( session );

        /*
         * Close the session.
         *
         * Note that we are not using CryptokiEx.
         */
        Cryptoki.C_CloseSession( session );

        /*
         * All done with Cryptoki
         *
         * Note that we are not using CryptokiEx.
         */
        Cryptoki.C_Finalize( null );

    }

    // Inject the seed (secret key, used to derive the master keypair) into the HSM.
    private CK_OBJECT_HANDLE injectSeed()
    {
        // KAT seed for test vector 1.
        String seed = "000102030405060708090a0b0c0d0e0f";
        byte[] seedBytes = hexStringToByteArray( seed );

        // ****************************
        // Setup mechanisms.

        // Generate random IV
        Random r = new Random();
        byte[] iv = new byte[ 8 ];//AES_KW
        r.nextBytes( iv );

        CK_MECHANISM keyGenMech = new CK_MECHANISM( CKM.AES_KEY_GEN );
        CK_MECHANISM mechanism = new CK_MECHANISM( CKM.AES_KW, iv );

        // ****************************
        // Generate AES Encrypt/Unwrap key.
        String label = "AES Seed Inject Key";

        CK_ATTRIBUTE[] template = {
            new CK_ATTRIBUTE( CKA.CLASS, CKO.SECRET_KEY )
            , new CK_ATTRIBUTE( CKA.TOKEN, CK_BBOOL.FALSE )
            , new CK_ATTRIBUTE( CKA.KEY_TYPE, CKK.AES )
            , new CK_ATTRIBUTE( CKA.SENSITIVE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.LABEL, label.getBytes() )
            , new CK_ATTRIBUTE( CKA.PRIVATE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.ENCRYPT, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.DECRYPT, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.WRAP, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.UNWRAP, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.VALUE_LEN, 16 )
        };

        CryptokiEx.C_GenerateKey( session, keyGenMech, template, template.length, hAESKey );

        // ****************************
        // Encrypt the seed.
        LongRef lRefEnc = new LongRef();

        CryptokiEx.C_EncryptInit( session, mechanism, hAESKey );

        // Apparently, this mechanism has no need for calls to EncryptUpdate to fill in an output buffer...
        // but it also will not work without a call with a valid buffer. Will get:
        // C_EncryptFinal rv=0x21 - CKR_DATA_LEN_RANGE
        //CryptokiEx.C_EncryptUpdate( session, mechanism, seedBytes, seedBytes.length, null, lRefEnc );
        byte[] dummy = new byte[ 1 ];
        CryptokiEx.C_EncryptUpdate( session, mechanism, seedBytes, seedBytes.length, dummy, lRefEnc );

        // First call to get the required size of the output buffer.
        CryptokiEx.C_EncryptFinal( session, mechanism, null, lRefEnc );

        // Alloc required space for encrypted seed.
        byte[] encSeed = new byte[ ( int ) lRefEnc.value ];

        // Second call to populate the buffer.
        CryptokiEx.C_EncryptFinal( session, mechanism, encSeed, lRefEnc );

        // ****************************
        // Unwrap the seed.
        CK_OBJECT_HANDLE hSeed = new CK_OBJECT_HANDLE();
        label = "BIP32 Seed";
        CK_ATTRIBUTE[] seedTemplate = {
            new CK_ATTRIBUTE( CKA.TOKEN, CK_BBOOL.FALSE )
            , new CK_ATTRIBUTE( CKA.CLASS, CKO.SECRET_KEY )
            , new CK_ATTRIBUTE( CKA.KEY_TYPE, CKK.GENERIC_SECRET )
            , new CK_ATTRIBUTE( CKA.PRIVATE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.SENSITIVE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.LABEL, label.getBytes() )
            , new CK_ATTRIBUTE( CKA.DERIVE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.EXTRACTABLE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.MODIFIABLE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.VALUE_LEN, encSeed.length )
        };

        CryptokiEx.C_UnwrapKey( session, mechanism, hAESKey, encSeed, encSeed.length,
                                seedTemplate, seedTemplate.length, hSeed );

        return hSeed;
    }

    private Bip32KeyPair deriveMasterKeypair( CK_OBJECT_HANDLE hSeed )
    {
        // Public and private key labels.
        String pubLeyLabel = "Derived Key: BIP32 Master Public Key";
        String privKeyLabel = "Derived Key: BIP32 Master Private Key";

        // Public Key template
        CK_ATTRIBUTE BIP32PubTemplate[] = {
            new CK_ATTRIBUTE( CKA.TOKEN, CK_BBOOL.FALSE )
            , new CK_ATTRIBUTE( CKA.PRIVATE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.DERIVE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.MODIFIABLE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.LABEL, pubLeyLabel.getBytes() )
        };

        // Private Key template
        CK_ATTRIBUTE BIP32PriTemplate[] = {
            new CK_ATTRIBUTE( CKA.TOKEN, CK_BBOOL.FALSE )
            , new CK_ATTRIBUTE( CKA.PRIVATE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.SENSITIVE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.DERIVE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.EXTRACTABLE, CK_BBOOL.FALSE )
            , new CK_ATTRIBUTE( CKA.MODIFIABLE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.LABEL, privKeyLabel.getBytes() )
        };

        try
        {
            // BIP32 derive params
            CK_BIP32_MASTER_DERIVE_PARAMS params = new CK_BIP32_MASTER_DERIVE_PARAMS(
                BIP32PubTemplate,
                BIP32PubTemplate.length,
                BIP32PriTemplate,
                BIP32PriTemplate.length,
                new CK_OBJECT_HANDLE( 0 ),
                new CK_OBJECT_HANDLE( 0 )
            );

            CK_MECHANISM mech = new CK_MECHANISM( CKM.BIP32_MASTER_DERIVE, params );

            // Derive the master keypair
            CryptokiEx.C_DeriveKey( session, mech, hSeed, null, 0, null );

            // Generate return value (key pair);
            return new Bip32KeyPair( params );
        }
        catch ( Exception ex )
        {
            ex.printStackTrace();
        }

        return null;
    }

    private Bip32KeyPair deriveChildKeypair( Bip32KeyPair masterKeyPair )
    {
        // KAT chain (last chain of test vector 1): "m/0'/1/2'/2/1000000000"
        // When setting the hardened bit, one needs to perform some width conversion dance therapy
        // to properly access the 32bits.
        int[] path = {
              ( int ) ( ( 0L | CKF.BIP32_HARDENED ) & 0xFFFFFFFFL )  // 0'
            , 1                                                      // 1
            , ( int ) ( ( 2L | CKF.BIP32_HARDENED ) & 0xFFFFFFFFL )  // 2'
            , 2                                                      // 2
            , 1000000000                                             // 1000000000
        };

        // Public and private key labels.
        String pubLeyLabel = "Derived Key: BIP32 Child Public Key";
        String privKeyLabel = "Derived Key: BIP32 Child Private Key";

        // Public Key template
        CK_ATTRIBUTE BIP32PubTemplate[] = {
              new CK_ATTRIBUTE( CKA.TOKEN, CK_BBOOL.FALSE )
            , new CK_ATTRIBUTE( CKA.PRIVATE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.DERIVE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.ENCRYPT, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.VERIFY, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.MODIFIABLE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.LABEL, pubLeyLabel.getBytes() )
        };

        // Private Key template
        CK_ATTRIBUTE BIP32PriTemplate[] = {
              new CK_ATTRIBUTE( CKA.TOKEN, CK_BBOOL.FALSE )
            , new CK_ATTRIBUTE( CKA.PRIVATE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.SENSITIVE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.DERIVE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.EXTRACTABLE, CK_BBOOL.FALSE )
            , new CK_ATTRIBUTE( CKA.DECRYPT, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.SIGN, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.MODIFIABLE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.LABEL, privKeyLabel.getBytes() )
        };

        try
        {
            // BIP32 derive params
            CK_BIP32_CHILD_DERIVE_PARAMS params = new CK_BIP32_CHILD_DERIVE_PARAMS(
                BIP32PubTemplate,
                BIP32PubTemplate.length,
                BIP32PriTemplate,
                BIP32PriTemplate.length,
                path,
                path.length,
                new CK_OBJECT_HANDLE( 0 ),
                new CK_OBJECT_HANDLE( 0 ),
                0
            );

            CK_MECHANISM mech = new CK_MECHANISM( CKM.BIP32_CHILD_DERIVE, params );

            // Derive the master keypair
            CryptokiEx.C_DeriveKey( session, mech, masterKeyPair.privateKey,
                                    null, 0, null );

            // Generate return value set.
            return new Bip32KeyPair( params );
        }
        catch ( Exception ex )
        {
            ex.printStackTrace();
        }

        return null;
    }

    private void verifyPublicKey( CK_OBJECT_HANDLE pubKeyHandle, byte[] matchBytes )
    {
        System.out.println( "Bytes to match:      " + new String( matchBytes ) );

        /*
         * Retrieve the public key.
         */

        byte[] pubKeyBytes = new byte[ ( int ) CKG.BIP32_MAX_SERIALIZED_LEN ];

        CryptokiEx.CA_Bip32ExportPublicKey( session, pubKeyHandle, pubKeyBytes );

        int i = pubKeyBytes.length - 1;
        while ( pubKeyBytes[ i ] == '\0' ) {i--;}
        pubKeyBytes = Arrays.copyOfRange( pubKeyBytes, 0, i + 1 );

        System.out.println( "Retrieved key bytes: " + new String( pubKeyBytes ) );

        try
        {
            // Activate via '-ea'
            assert ( Arrays.equals( matchBytes, pubKeyBytes ) );
            System.out.println( "Public key bytes match KAT value." );
        }
        catch ( AssertionError e )
        {
            System.out.println( "Public key bytes DO NOT match KAT value." );
        }
    }

    private CK_OBJECT_HANDLE importPublicKey( byte[] pubChildBytes )
    {
        CK_OBJECT_HANDLE newPubKeyHnd = new CK_OBJECT_HANDLE();
        CryptokiEx.CA_Bip32ImportPublicKey( session, pubChildBytes, newPubKeyHnd );
        return newPubKeyHnd;
    }

    private void deriveChildKeypairBIP44 ( Bip32KeyPair masterKeyPair )
    {

        // Public and private key labels.
        String pubLeyLabel = "Derived Key: BIP32 Child Public Key";
        String privKeyLabel = "Derived Key: BIP32 Child Private Key";

        // Public Key template
        CK_ATTRIBUTE BIP32PubTemplate[] = {
              new CK_ATTRIBUTE( CKA.TOKEN, CK_BBOOL.FALSE )
            , new CK_ATTRIBUTE( CKA.PRIVATE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.DERIVE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.ENCRYPT, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.VERIFY, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.MODIFIABLE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.LABEL, pubLeyLabel.getBytes() )
        };

        // Private Key template
        CK_ATTRIBUTE BIP32PriTemplate[] = {
              new CK_ATTRIBUTE( CKA.TOKEN, CK_BBOOL.FALSE )
            , new CK_ATTRIBUTE( CKA.PRIVATE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.SENSITIVE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.DERIVE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.EXTRACTABLE, CK_BBOOL.FALSE )
            , new CK_ATTRIBUTE( CKA.DECRYPT, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.SIGN, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.MODIFIABLE, CK_BBOOL.TRUE )
            , new CK_ATTRIBUTE( CKA.LABEL, privKeyLabel.getBytes() )
        };

        for (int i = 0; i < 101; i++) {
          try
          {
              // BIP44 derivation path = "m/44'/0'/0'/0'/i"
              int[] path = {
                  ( int ) ( ( CKG.BIP44_PURPOSE | CKF.BIP32_HARDENED ) & 0xFFFFFFFFL )       // 44'
                , ( int ) ( ( CKG.BIP44_COIN_TYPE_BTC | CKF.BIP32_HARDENED ) & 0xFFFFFFFFL ) // 0'
                , ( int ) ( ( 0 | CKF.BIP32_HARDENED ) & 0xFFFFFFFFL )                       // 0'
                , ( int ) ( ( 0 | CKF.BIP32_HARDENED ) & 0xFFFFFFFFL )                       // 0'
                , i                                                                          // i
              };

              // BIP32 derive params
              CK_BIP32_CHILD_DERIVE_PARAMS params = new CK_BIP32_CHILD_DERIVE_PARAMS(
                  BIP32PubTemplate,
                  BIP32PubTemplate.length,
                  BIP32PriTemplate,
                  BIP32PriTemplate.length,
                  path,
                  path.length,
                  new CK_OBJECT_HANDLE( 0 ),
                  new CK_OBJECT_HANDLE( 0 ),
                  0
              );

              CK_MECHANISM mech = new CK_MECHANISM( CKM.BIP32_CHILD_DERIVE, params );

              // Derive the child keypair
              CryptokiEx.C_DeriveKey( session, mech, masterKeyPair.privateKey,
                                      null, 0, null );

          }
          catch ( Exception ex )
          {
              ex.printStackTrace();
          }
        }

    }

    /**
     * Main method to run the tests.
     */
    public void runTests()
    {
        openLoginSession();

        // Inject the master key pair derivation seed.
        CK_OBJECT_HANDLE hSeed = injectSeed();

        // Derive the master key pair.
        Bip32KeyPair masterKeyPair = deriveMasterKeypair( hSeed );
        if (masterKeyPair == null)
        {
            return;
        }

        // Derive a child key pair.
        Bip32KeyPair childKeyPair = deriveChildKeypair( masterKeyPair );
        if (childKeyPair == null)
        {
            return;
        }

        System.out.format( "Seed handle               : 0x%x%n", hSeed.longValue() );
        System.out.format( "Master public key handle  : 0x%x%n", masterKeyPair.publicKey.longValue() );
        System.out.format( "Master private key handle : 0x%x%n", masterKeyPair.privateKey.longValue() );
        System.out.format( "Child public key handle   : 0x%x%n", childKeyPair.publicKey.longValue() );
        System.out.format( "Child private key handle  : 0x%x%n", childKeyPair.privateKey.longValue() );

        /*
         Verify Master public key was derived properly.
         */

        // KAT public key bytes for the master key pair.
        byte[] pubKeyBytes =
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
                .getBytes();
        System.out.format( "%nVerify Master Public key was derived properly.%n" );
        verifyPublicKey( masterKeyPair.publicKey, pubKeyBytes );

        /*
         Verify the child public key was derived properly, by verifying it against the KAT value.
         */

        // KAT public key bytes for the corresponding keyPath.
        pubKeyBytes =
            "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
                .getBytes();
        System.out.format( "%nVerify Child Public key was derived properly.%n" );
        verifyPublicKey( childKeyPair.publicKey, pubKeyBytes );

        /*
         Import an arbitrarily chosen KAT public key from test vector 2, then export it and verify
         the bytes match, proving a successful import.
         */

        // KAT public key for chain m/0/2147483647' (test vector 2).
        pubKeyBytes =
            "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"
                .getBytes();
        CK_OBJECT_HANDLE newHndPubKey = importPublicKey( pubKeyBytes );
        System.out.format( "%nVerify Imported Public key can be properly retrieved.%n" );
        verifyPublicKey( newHndPubKey, pubKeyBytes );

        // Derive a BIP44 child key pair.
        deriveChildKeypairBIP44( masterKeyPair );

        closeLogoutSession();
    }

    /**
     * main execution method - process commandline args, setup object and run the tests.
     */
    public static void main( String[] args )
    {

        /*
         * process command line arguments
         */
        for ( int i = 0; i < args.length; ++i )
        {

            if ( args[ i ].equalsIgnoreCase( "-slot" ) )
            {
                if ( ++i >= args.length )
                { usage(); }

                slotId = Integer.parseInt( args[ i ] );
            }
            else if ( args[ i ].equalsIgnoreCase( "-password" ) )
            {
                if ( ++i >= args.length )
                { usage(); }

                password = args[ i ];
            }
            else
            {
                usage();
            }
        }

        // Create object and run tests.
        BIP32KeyDeriveSample aSample = new BIP32KeyDeriveSample();
        aSample.runTests();
    }
}
