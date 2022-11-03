/*****************************************************************************/
/* Triangle MicroWorks, Inc.                         Copyright (c) 1997-2020 */
/*****************************************************************************/
/*                                                                           */
/* This file is the property of:                                             */
/*                                                                           */
/*                       Triangle MicroWorks, Inc.                           */
/*                      Raleigh, North Carolina USA                          */
/*                       www.TriangleMicroWorks.com                          */
/*                          (919) 870-6615                                   */
/*                                                                           */
/* This Source Code and the associated Documentation contain proprietary     */
/* information of Triangle MicroWorks, Inc. and may not be copied or         */
/* distributed in any form without the written permission of Triangle        */
/* MicroWorks, Inc.  Copies of the source code may be made only for backup   */
/* purposes.                                                                 */
/*                                                                           */
/* Your License agreement may limit the installation of this source code to  */
/* specific products.  Before installing this source code on a new           */
/* application, check your license agreement to ensure it allows use on the  */
/* product in question.  Contact Triangle MicroWorks for information about   */
/* extending the number of products that may use this source code library or */
/* obtaining the newest revision.                                            */
/*                                                                           */
/*****************************************************************************/

// DNPSlave.cpp : Sample DNP Slave console application.
//

#if defined(TMW_WTK_TARGET)
#include "StdAfx.h"
#endif

extern "C" {
#include "tmwscl/utils/tmwdb.h"
#include "tmwscl/utils/tmwpltmr.h"
#include "tmwscl/utils/tmwtarg.h"

#include "tmwscl/dnp/dnpchnl.h"
#include "tmwscl/dnp/sdnpsesn.h"
#if TMWCNFG_USE_SIMULATED_DB
#include "tmwscl/dnp/sdnpsim.h"
#endif
#include "tmwscl/dnp/sdnpo032.h"
#include "tmwscl/dnp/sdnputil.h"

#include "tmwtargio.h"
}

/* The USE_POLLED_MODE constant is used here to demonstrate how the library
 * can be used to configure the target layer to support polled mode vs.
 * event driven. The Linux and Windows target layers shipped with the SCL
 * support both. If porting the library, only one configuration is required.
 */
#define USE_POLLED_MODE TMWDEFS_FALSE
#define USE_TLS         TMWDEFS_FALSE

/* Open a second channel and outstation session */
TMWTYPES_BOOL   openSecondConnection = TMWDEFS_FALSE;

#if DNPCNFG_SUPPORT_AUTHENTICATION
/* It is possible to start an SAV5 session with no users and have them added by
 * the Authority/Master using a remote key change mehthod for user number 1 "Common".
 */
TMWTYPES_BOOL     noUserAtStartup = TMWDEFS_FALSE;
#endif



#if !TMWCNFG_MULTIPLE_TIMER_QS
/* forward references */
void myPutDiagString(const TMWDIAG_ANLZ_ID *pAnlzId, const TMWTYPES_CHAR *pString);

#if DNPCNFG_SUPPORT_AUTHENTICATION
void              myInitSecureAuthentication(SDNPSESN_CONFIG *pSesnConfig);
TMWTYPES_BOOL     myAddAuthUsers(SDNPSESN *pSDNPSession, TMWTYPES_BOOL operateInV2Mode);

/* These are the default user keys the test harness uses for testing 
 * DO NOT USE THESE IN A REAL DEVICE
 */
static TMWTYPES_UCHAR defaultUserKey1[] = {
  0x49, 0xC8, 0x7D, 0x5D, 0x90, 0x21, 0x7A, 0xAF, 
  0xEC, 0x80, 0x74, 0xeb, 0x71, 0x52, 0xfd, 0xb5
};
static TMWTYPES_UCHAR defaultUserKeyOther[] = {
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
}; 

/* This one is used by the Authority and the Outstation.
 */
static TMWTYPES_UCHAR  authoritySymCertKey[] = {
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
  0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
  0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06
};
#endif

/* Main entry point */
int main(int argc, char* argv[])
{
  TMWAPPL *pApplContext;
  TMWCHNL *pSclChannel;
  TMWSESN *pSclSession;
  DNPCHNL_CONFIG DNPConfig;
  DNPTPRT_CONFIG tprtConfig;
  TMWTARG_CONFIG targConfig;
  TMWPHYS_CONFIG physConfig;
  DNPLINK_CONFIG linkConfig;
  SDNPSESN_CONFIG sesnConfig;
  TMWTARGIO_CONFIG IOCnfg;
  bool useSerial = false;
  int addEventCtr = 0;
  int anlgInPointNum = 0;
  
  TMWTARG_UNUSED_PARAM(argc);
  TMWTARG_UNUSED_PARAM(argv);

#if TMWCNFG_SUPPORT_DIAG 
  /* Register function to display diagnostic strings to console 
   * This is only necessary if using the WinIOTarg target layer.
   * If implementing a new target layer, tmwtarg_putDiagString()
   * should be modified if diagnostic output is desired.
   */
  tmwtargp_registerPutDiagStringFunc(myPutDiagString);
#endif

  /*
  * Initialize the source code library.
  */
  tmwappl_initSCL();

  /*
   * Initialize SDNP SCL. This includes:
   *  - initialize polled timer
   *  - initialize application context 
   */
  tmwtimer_initialize();
  pApplContext = tmwappl_initApplication();

  /* Initialize channel configuration to defaults */
  tmwtarg_initConfig(&targConfig);
  dnpchnl_initConfig(&DNPConfig, &tprtConfig, &linkConfig, &physConfig);
  linkConfig.networkType = DNPLINK_NETWORK_TCP_UDP;
 
  /* Initialize IO Config Structure
   * Call tmwtargio_initConfig to initialize default values, then overwrite
   * specific values as needed.
   *
   * This example configures the Slave for a TCP/IP session using the
   * Loopback address and default Session values. This configuration
   * is compatible with the example scripts that ship with the
   * Communication Protocol Test Harness.
   */
  tmwtargio_initConfig(&IOCnfg);


  if(useSerial)
  {
    IOCnfg.type = TMWTARGIO_TYPE_232;

    /* Name displayed in analyzer window */
    strcpy(IOCnfg.targ232.chnlName, "Slave");

    strcpy(IOCnfg.targ232.baudRate, "9600");
    IOCnfg.targ232.numDataBits = TMWTARG232_DATA_BITS_8;
    IOCnfg.targ232.numStopBits = TMWTARG232_STOP_BITS_1;
    IOCnfg.targ232.parity      = TMWTARG232_PARITY_NONE;
    IOCnfg.targ232.portMode    = TMWTARG232_MODE_NONE;
    IOCnfg.targ232.polledMode  = USE_POLLED_MODE;

#if defined(TMW_WTK_TARGET)
    /* COM port to open */
    strcpy(IOCnfg.targ232.portName, "COM2");
#endif

#if defined(TMW_LINUX_TARGET) 
    /* port to open */
    strcpy(IOCnfg.targ232.portName, "/dev/ttyS1");
#endif
  }
  else
  { 
    IOCnfg.type = TMWTARGIO_TYPE_TCP;

    /* Name displayed in analyzer window */
    strcpy(IOCnfg.targTCP.chnlName, "Slave");

    /* TCP/IP address of remote device  
     * 127.0.0.1 is the loopback address and will accept connections from this computer
     * Use *.*.*.* to allow connections from any ip address
     */
#if defined(TMW_WTK_TARGET)
    strcpy(IOCnfg.targTCP.ipAddress, "127.0.0.1");
#endif
#if defined(TMW_LINUX_TARGET)
    strcpy(IOCnfg.targTCP.ipAddress, "*.*.*.*");
#endif

    /* port to listen on */
    IOCnfg.targTCP.ipPort = 20000;
    IOCnfg.targTCP.polledMode = USE_POLLED_MODE;

    /* listen, do not initiate the connection */
    IOCnfg.targTCP.mode = TMWTARGTCP_MODE_SERVER;
 
    /* There are certain rules for an outstation in IP Networking */
    IOCnfg.targTCP.role = TMWTARGTCP_ROLE_OUTSTATION;
    IOCnfg.targTCP.disconnectOnNewSyn = TMWDEFS_FALSE;
      
    IOCnfg.targTCP.localUDPPort = 20000; /* TMWTARG_UDP_PORT_NONE */
    IOCnfg.targTCP.validateUDPAddress = TMWDEFS_FALSE;

    /* TLS Configuration */
    IOCnfg.targTCP.useTLS = USE_TLS;
#if TMWTARG_SUPPORT_TLS
    if (USE_TLS)
    {
      /* The default TMW configuration sets up the client's certificate files.
       * Because the file names are the same length but the values for
       * Linux and Windows differ, this sample application simply updates
       * the path to the server's certificates.
       */
      char *clientPtr;
      char serverString[] = "server";
      clientPtr = strstr(IOCnfg.targTCP.tlsRsaCertificateId, "client");
      if (clientPtr)
      {
        /* Copy without NULL terminator */
        memcpy(clientPtr, serverString, sizeof(serverString)-1);
      }
      clientPtr = strstr(IOCnfg.targTCP.tlsRsaPrivateKeyFile, "client");
      if (clientPtr)
      {
        /* Copy without NULL terminator */
        memcpy(clientPtr, serverString, sizeof(serverString)-1);
      }
    }
#endif

    /* Some other outstation configurations */
    bool dualEndPoint = false;
    bool udpOnly = false;
    if(dualEndPoint)
    { 
      /* This code will configure the channel for Dual End Point mode 
       * ie. Client AND Server
       * It will both listen and try to connect to the remote end when
       * it has data to send. This mode should be used on both ends.
       */
      IOCnfg.targTCP.mode = TMWTARGTCP_MODE_DUAL_ENDPOINT;

      /* if dual end point, the ip address of the master must be specified */
      strcpy(IOCnfg.targTCP.ipAddress, "127.0.0.1");

      /* This is the port to send connect request to when the outstation initiates the connection */
      IOCnfg.targTCP.dualEndPointIpPort = 20000;
    }
    else if(udpOnly)
    {
      /* This code will configure the channel for UDP only.
       */
      
      IOCnfg.targTCP.mode = TMWTARGTCP_MODE_UDP;
      linkConfig.networkType = DNPLINK_NETWORK_UDP_ONLY;

      /* if UDP ONLY, the IP address of the master must be specified */
      strcpy(IOCnfg.targTCP.ipAddress, "127.0.0.1");
      
      /* Choose the local UDP port to send and receive on */
      IOCnfg.targTCP.localUDPPort = 20000;

      /* Send responses to the port the master sends from, Normally this would be configured to use 20000. */
      IOCnfg.targTCP.destUDPPort =  TMWTARG_UDP_PORT_SRC; //20000;

      /* Send the initial Null unsolicited response to this port on the master */
#if defined(TMW_WTK_TARGET)
      IOCnfg.targTCP.initUnsolUDPPort = 20001;
#endif
#if defined(TMW_LINUX_TARGET)
      IOCnfg.targTCP.initUnsolUDPPort = 20000;
#endif
    }
  }
 
  /* Open DNP channel */
  pSclChannel = dnpchnl_openChannel(pApplContext, &DNPConfig, &tprtConfig, 
    &linkConfig, &physConfig, &IOCnfg, &targConfig);

  if(pSclChannel == TMWDEFS_NULL)
  {
    /* Failed to open */
    printf("Failed to open channel, exiting program \n");
    
    /* Sleep for 10 seconds before exiting */
    tmwtarg_sleep(10000);
    return (1);
  }

  /* Initialize and open DNP slave session */
  sdnpsesn_initConfig(&sesnConfig);
  
  // If using TCP the DNP Spec requires keep alives to be configured in order to detect disconnects.
  if(!useSerial)
    sesnConfig.linkStatusPeriod = 30000;
  
#if DNPCNFG_SUPPORT_AUTHENTICATION
  /* Set this to true to enable DNP3 Secure Authentication support */
  bool myUseAuthentication = true; 

  /* If Secure Authentication is to be enabled */
  if(myUseAuthentication)
    myInitSecureAuthentication(&sesnConfig);
#endif

  pSclSession = (TMWSESN *)sdnpsesn_openSession(pSclChannel, &sesnConfig, 
    TMWDEFS_NULL);

  if(pSclSession == TMWDEFS_NULL)
  {
    /* Failed to open */
    printf("Failed to open session, exiting program \n");
    
    /* Sleep for 10 seconds before exiting */
    tmwtarg_sleep(10000);
    return (1);
  }

  if(pSclSession == TMWDEFS_NULL)
  {
    /* Failed to open session */
    printf("Failed to open Session, exiting program \n");
  
    /* Sleep for 10 seconds before exiting */
    tmwtarg_sleep(10000);
    return (1);
  } 

#if DNPCNFG_SUPPORT_AUTHENTICATION
  if (myUseAuthentication)
  {
    if (!myAddAuthUsers((SDNPSESN*)pSclSession, sesnConfig.authConfig.operateInV2Mode))
    {
      /* Sleep for 10 seconds before exiting */
      tmwtarg_sleep(10000);
      return (1);
    }
  }
#endif 

  /* This code will open a second channel and outstation session */ 
  if(openSecondConnection)
  {
    TMWCHNL *pSclChannel2;
    TMWSESN *pSclSession2;
    strcpy(IOCnfg.targTCP.chnlName, "Second"); 
    IOCnfg.targTCP.ipPort = 20001;
    IOCnfg.targTCP.polledMode = USE_POLLED_MODE;

    /* Open Second DNP channel */
    pSclChannel2 = dnpchnl_openChannel(pApplContext, &DNPConfig, &tprtConfig,
                                     &linkConfig, &physConfig, &IOCnfg, &targConfig);

    if(pSclChannel2 == TMWDEFS_NULL)
    {
      /* Failed to open */
      printf("Failed to open second channel, exiting program \n");
    
      /* Sleep for 10 seconds before exiting */
      tmwtarg_sleep(10000);
      return (1);
    }

    pSclSession2 = (TMWSESN *)sdnpsesn_openSession(pSclChannel2, &sesnConfig,
                 TMWDEFS_NULL);

    if(pSclSession2 == TMWDEFS_NULL)
    {
      /* Failed to open */
      printf("Failed to open second session, exiting program \n");
    
      /* Sleep for 10 seconds before exiting */
      tmwtarg_sleep(10000);
      return (1);
    }

#if DNPCNFG_SUPPORT_AUTHENTICATION
    if (myUseAuthentication)
    {
      if (!myAddAuthUsers((SDNPSESN*)pSclSession2, sesnConfig.authConfig.operateInV2Mode))
      {
        /* Sleep for 10 seconds before exiting */
        tmwtarg_sleep(10000);
        return (1);
      }
    }
#endif 
  }


  /* Begin the main loop.
   * This example uses the Source Code Library in Polled mode.
   * In Polled mode, you must periodically:
   *  - check the timer
   *  - check for (and process) any received data
   */
  while(1)
  {
    tmwpltmr_checkTimer(); 

    /* If the target layer is configured to be event driven, there
     * is no need for the application to check for received data.
     */
    if (USE_POLLED_MODE)
    {
      tmwappl_checkForInput(pApplContext);
    }

    /* Sleep for 50 milliseconds */
    tmwtarg_sleep(50);

    /* Begin addEvent example.
     *  This code demonstrates how to use the xxx_addEvent function to
     *  inform the library that a data change has occurred instead of
     *  relying on SCL scanning. 
     *  The period (once every 100 iterations) and the point count (10)
     *  are aribtrary, but demonstrate how the 1st 10 analog values are
     *  updated periodially and the slave will send unsolicited updates
     *  to the master if enabled to do so.
     * NOTE: Setting analogInputScanPeriod to a non-zero value will result
     *       in this value being updated by the SCL scan.
     */
    addEventCtr++;
    if ((addEventCtr % 100) == 0)
    {
      TMWTYPES_ANALOG_VALUE analogValue;
      TMWDTIME timeStamp;
      sdnputil_getDateTime(pSclSession, &timeStamp);
      analogValue.value.dval = rand();
      analogValue.type = TMWTYPES_ANALOG_TYPE_DOUBLE;

      sdnpo032_addEvent(pSclSession, anlgInPointNum,
        &analogValue, DNPDEFS_DBAS_FLAG_ON_LINE,
        &timeStamp);
      anlgInPointNum++;
      if (anlgInPointNum == 10)
      {
        anlgInPointNum = 0;
      }
    }
    /* End addEvent example. */
  }
 
  return 0;
}
 

#if DNPCNFG_SUPPORT_AUTHENTICATION
void myInitSecureAuthentication(SDNPSESN_CONFIG *pSesnConfig)
{
  /* set this to TMWDEFS_TRUE to use SAv2 implementation */
  TMWTYPES_BOOL myUseSAv2 = TMWDEFS_FALSE;

#if !SDNPCNFG_SUPPORT_SA_VERSION5
  /* If SAv5 is not supported, use SAv2 */
  myUseSAv2 = TMWDEFS_TRUE;
#endif

  printf( "Using SAv%c\n", myUseSAv2?'2':'5');
  
  /* Enable DNP3 Secure Authentication support */
  pSesnConfig->authenticationEnabled = TMWDEFS_TRUE;
  
  /* NOTE: Secure Authentication Version 2 (SAv2) will not function properly without implementing 
   * the functions sdnpdata_authxxx() in sdnpdata.c
   * SAv5 also requires utils/tmwcrypto which uses OpenSSL as a sample implementation.
   */

  /* For SAv2 configure the same user numbers and update keys for each user 
   * number on both master and outstation devices. These must be configured before the 
   * session is opened.
   * SAv5 allows User Update Keys to also be sent to the outstation over DNP.
   */ 

#if SDNPCNFG_SUPPORT_SA_VERSION2 
  /* Use Secure Authentication Version 2 */
  if(myUseSAv2)
  {
    pSesnConfig->authConfig.operateInV2Mode = TMWDEFS_TRUE;
    pSesnConfig->authConfig.maxErrorCount = 2;

    /* Configure user numbers */
    /* Spec says default user number 1 provides a user number for the device or "any" user */
    pSesnConfig->authConfig.authUsers[0].userNumber = DNPAUTH_DEFAULT_USERNUMBER;
  }
#endif
  /* Example configuration. Some of these may be the default values,
   * but are shown here as an example of what can be set.
   */
  pSesnConfig->authConfig.extraDiags = TMWDEFS_TRUE;
  pSesnConfig->authConfig.aggressiveModeSupport = TMWDEFS_TRUE;
  pSesnConfig->authConfig.maxKeyChangeCount = 1000; 
  // 120 seconds is very short for demonstration purposes only.
  pSesnConfig->authConfig.keyChangeInterval = 120000;  
  pSesnConfig->authConfig.assocId = 0;
}

TMWTYPES_BOOL myAddAuthUsers(SDNPSESN *pSDNPSession, TMWTYPES_BOOL operateInV2Mode)
{

#if SDNPCNFG_SUPPORT_SA_VERSION2 && TMWCNFG_SUPPORT_CRYPTO
  /* If SAv2 and using optional TMWCRYPTO interface set the crypto database*/
  if (operateInV2Mode)
  {
    TMWTYPES_USHORT userNumber = 1;

    /* If using simulated database in tmwcrypto, add the User Update Key for the default user (1) to it.
     * This key should really should be in YOUR crypto database not the simulated one in tmwcrypto.c.
     * You would not normally need to call tmwcrypto_configSimKey to add it to your own database.
     * For SAv2 the handle used to look up keys in the sim database is the SDNP DB handle.
     */
    if (!tmwcrypto_configSimKey(pSDNPSession->pDbHandle, TMWCRYPTO_USER_UPDATE_KEY, userNumber, defaultUserKey1, 16, TMWDEFS_NULL, 0))
    {
      /* Failed to add key */
      printf("Failed to add key, exiting program \n");
      return (TMWDEFS_FALSE);
    }

    /* DNP3 Technical Bulletin TB2019-001 indicates that the next version of SA
     * will remove support for support multiple users per Master-Outstation Association
     * and it is recommended that SAV5 should be used with only a single user per Association.
     * While the MDNP SAv2 and SAv5 implementations support multiple users this example
     * will not show that as it would violate that recommendation and not be allowed in the future.
     */
  }
#endif
#if SDNPCNFG_SUPPORT_SA_VERSION5
  /* In SAv5 we no longer use an array of user configuration, instead you can add one user at a time.
   * The Authority can also tell the master to add a user using a globally unique user name
   * and instruct the master to send the update key and role (permissions) for that user over DNP to the outstation.
   */
  if (!operateInV2Mode)
  {
    const TMWTYPES_CHAR *pKey;
    TMWTYPES_USHORT keyLength;
    TMWTYPES_USHORT userNumber = 1;

    /* It is possible to start an SAV5 session with no users and have them added from the Authority/Master using a remote key change mehthod for user number 1 "Common" */
    if (!noUserAtStartup)
    {
      /* If using simulated database in tmwcrypto, add the User Update Key for the default user (1) to it.
       * This key should really should be in YOUR crypto database not the simulated one in tmwcrypto.c.
       * You would not normally need to call tmwcrypto_configSimKey to add it to your own database.
       */
      if (!tmwcrypto_configSimKey(pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_USER_UPDATE_KEY, userNumber, defaultUserKey1, 16, TMWDEFS_NULL, 0))
      {
        /* Failed to add key */
        printf("Failed to add key, exiting program \n");
        return (TMWDEFS_FALSE);
      }

      /* For SAv5 add the user to the sdnp library */
      sdnpsesn_addAuthUser((TMWSESN*)pSDNPSession, userNumber);

      /* Also add this to the SDNP simulated database to support ptional remote key change methods */
      sdnpsim_authConfigUser(pSDNPSession->pDbHandle, "Common", 6, 1, DNPAUTH_USER_ROLE_SINGLEUSER, 100);
    

      /* DNP3 Technical Bulletin TB2019-001 indicates that the next version of SA
       * will remove support for support multiple users per Master-Outstation Association
       * and it is recommended that SAV5 should be used with only a single user per Association.
       * While the MDNP SAv2 and SAv5 implementations support multiple users this example
       * will not show that as it would violate that recommendation and not be allowed in the future.
       */
    }

    /* Configure other values in YOUR crypto database to allow remote user key and role update from Master.*/

    /* This sample uses the same values that the Test Harness Outstation uses by default */

    /* Outstation name must be configured in both Master and Outstation.
     * This is already set in sdnpsim database
     * OutstationName = "SDNP Outstation";
     */

    /* If using simulated database in tmwcrypto, configure the Authority Certification Symmetric Key to it.
      * This key really should be in YOUR crypto database not the simulated one in tmwcrypto.c.
      * You would not normally need to call tmwcrypto_configSimKey to add it to your own database.
      * This key is used by the Central Authority and configured on the Outstation.
      */
    if (!tmwcrypto_configSimKey(pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_AUTH_CERT_SYM_KEY, 0, (TMWTYPES_UCHAR *)&authoritySymCertKey, 32, TMWDEFS_NULL, 0))
    {
      /* Failed to add key */
      printf("Failed to add key, exiting program \n");
      return (TMWDEFS_FALSE);
    }

    /* If using simulated database in tmwcrypto, configure Outstation Private Key when Asymmetric Key Update is supported.
     * This really should be in YOUR crypto database not the simulated one.
     * You would not normally need to call tmwcrypto_configSimKey to add it to your own database.
     */
    pKey = "TMWTestOSRsa2048PrvKey.pem";
    keyLength = (TMWTYPES_USHORT)strlen(pKey);
    if (!tmwcrypto_configSimKey(pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_OS_ASYM_PRV_KEY, 0, (TMWTYPES_UCHAR *)pKey, keyLength, (TMWTYPES_UCHAR *)"triangle", 8))
    {
      /* Failed to add key */
      printf("Failed to add key, exiting program \n");
      return (TMWDEFS_FALSE);
    }

    /* If using simulated database in tmwcrypto, configure Authority Public Key when Asymmetric Key Update is supported
     * This really should be in YOUR crypto database not the simulated one.
     * You would not normally need to call tmwcrypto_configSimKey to add it to your own database.
     */   
    /* One symmetric and one asymmetric key change algorithm is configured to work at a time.*/
    TMWTYPES_UCHAR keyChangeMethod = DNPAUTH_KEYCH_ASYM_RSA2048_SHA256;
    switch (keyChangeMethod)
     {
     case DNPAUTH_KEYCH_ASYM_RSA1024_SHA1:
       pKey = "TMWTestAuthorityDsa1024PubKey.pem";
       break;

     case DNPAUTH_KEYCH_ASYM_RSA2048_SHA256:
       pKey = "TMWTestAuthorityDsa2048PubKey.pem";
       break;

     case DNPAUTH_KEYCH_ASYM_RSA3072_SHA256:
       pKey = "TMWTestAuthorityDsa3072PubKey.pem";
       break;

       // New key change methods from TB2016-002
     case DNPAUTH_KEYCH_ASYM_RSA1024_RSA_SHA1:
       pKey = "TMWTestAuthorityRsa1024PubKey.pem";
       break;

     case DNPAUTH_KEYCH_ASYM_RSA2048_RSA_SHA256:
       pKey = "TMWTestAuthorityRsa2048PubKey.pem";
       break;

     case DNPAUTH_KEYCH_ASYM_RSA3072_RSA_SHA256:
       pKey = "TMWTestAuthorityRsa3072PubKey.pem";
       break;

     default:
       printf("FAILED, keys not configured for this key change method\n");
       return (TMWDEFS_FALSE);
     }

    keyLength = (TMWTYPES_USHORT)strlen(pKey);
    if (!tmwcrypto_configSimKey(pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_AUTH_ASYM_PUB_KEY, 0, (TMWTYPES_UCHAR *)pKey, keyLength, TMWDEFS_NULL, 0))
    {
      /* Failed to add key */
      printf("Failed to add key, exiting program \n");
      return (TMWDEFS_FALSE);
    }

    /* add security statistics points to database */
    for (int i = 0; i < DNPAUTH_NUMBER_STATISTICS; i++)
      sdnpsim_addAuthSecStat(pSDNPSession->pDbHandle, i, TMWDEFS_CLASS_MASK_THREE, 0x01, 0);  /* spec says it SHALL be in an event class */
  }
#endif
  return (TMWDEFS_TRUE);
}

#endif

/* The following functions are called by the SCL */

#if TMWCNFG_SUPPORT_DIAG
/* Simple diagnostic output function, registered with the Source Code Library */
void myPutDiagString(const TMWDIAG_ANLZ_ID *pAnlzId,const TMWTYPES_CHAR *pString)
{
  TMWDIAG_ID id = pAnlzId->sourceId;

  if((TMWDIAG_ID_ERROR & id) 
    ||(TMWDIAG_ID_APPL & id)
    ||(TMWDIAG_ID_USER & id)
    ||(TMWDIAG_ID_SECURITY_DATA & id)
    ||(TMWDIAG_ID_SECURITY_HDRS & id)
    )
  {
    printf( "%s", (char *)pString);  
    return;
  }

  /* Comment this out to turn off verbose diagnostics */
  /* For now print everything */
  /* printf((char *)pString); */
}
#endif
#endif
