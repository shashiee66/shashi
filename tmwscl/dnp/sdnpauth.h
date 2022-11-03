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

/* file: sdnpauth.h
 * description: This file is intended for internal SCL use only.
 *   DNP Slave functionality for Secure Authentication
 */
#ifndef SDNPAUTH_DEFINED
#define SDNPAUTH_DEFINED

#include "tmwscl/dnp/dnpauth.h"


#include "tmwscl/dnp/dnputil.h"
#include "tmwscl/dnp/sdnpsesp.h"

/* Size of buffer used at sdnpdata_authxxx interface 
 * for concatenating data to be encrypted 
 */
#define SDNPAUTH_BUFFERSIZE DNPCNFG_MAX_RX_FRAGMENT_LENGTH

/* Size of buffer used to hold last key status message sent to master 
 * Status message is saved starting with KSQ, but not including MAC data.
 * TB2016-002 suggests limiting challenge data size portion of status message to 64.
 * If that rule is followed, the max required would be 75.
 */
#define SDNPAUTH_KEYSTATUSMAXSIZE   75

/* Size of buffer used to hold last key change message received from master */
#define SDNPAUTH_KEYCHANGEMAXSIZE   ((DNPAUTH_MAX_KEY_LENGTH*2)+SDNPAUTH_KEYSTATUSMAXSIZE+32)

/* Size of buffer used to hold last challenge received from master 
 * TB2016-002 limits challenge data size portion of status message to 64.
 * This is enforced to comply with DNP SA Conformance Tests.
 * If that rule is followed, this SHALL be set to 80
 */
#define SDNPAUTH_RXCHALLENGEMAXSIZE 80

/* Size of buffer used to hold last challenge transmitted to master 
 * Since a "preChallenge" can be included in any response with the CON bit 
 * set, this challenge message can be as large as the max fragment size 
 */
#define SDNPAUTH_TXCHALLENGEMAXSIZE DNPCNFG_MAX_TX_FRAGMENT_LENGTH

/* Maximum size of "preChallenge" object  */
#define SDNPAUTH_PRECHALLENGEPAD          80

/* Maximum size of g120v9 aggressive mode object */
#define SDNPAUTH_AGGRMODEPAD              22
 
/* slave state machine states from figure 8 */
#define SDNPAUTH_STATE_INIT                0
#define SDNPAUTH_STATE_IDLE                1
#define SDNPAUTH_STATE_WAITFORREPLY        2

/* events */
#define SDNPAUTH_EVT_MSG_RECEIVED          0  /* message received from outstation    */
#define SDNPAUTH_EVT_CHALLENGE             1  /* challenge received                  */
#define SDNPAUTH_EVT_CHALLENGE_REPLY       2  /* challenge reply response received   */
#define SDNPAUTH_EVT_KEYSTATUSREQ          3  /* key status request message received */
#define SDNPAUTH_EVT_KEYCHANGEREQ          4  /* key change request message received */
#define SDNPAUTH_EVT_ERRORREQ              5  /* error message received              */
#define SDNPAUTH_EVT_AGGRESSIVE_MODE       6  /* aggressive mode object received     */
#define SDNPAUTH_EVT_CRITICAL_RCVD         7  /* critical msg received               */
#define SDNPAUTH_EVT_NONCRITICAL_RCVD      8  /* noncritical msg received            */
#define SDNPAUTH_EVT_EXPECTEDKEYTIMEOUT    9  /* expected key change timeout occurred*/
#define SDNPAUTH_EVT_REPLYTIMEOUT         10  /* reply timeout occurred              */
#define SDNPAUTH_EVT_COMMFAILUREDETECTED  11  /* communications has failed */
#define SDNPAUTH_EVT_MAXINVALIDREPLIES    12  /* max number of invalid replies received */
#define SDNPAUTH_EVT_MAXAUTHENTFAILURES   13  /* max authentication failures exeeded */

#define SDNPAUTH_EVT_USERCERT_RCVD        20  /* g120v8 User Certificate received */
#define SDNPAUTH_EVT_USERSTATUS_RCVD      21  /* g120v10 User Status Change received */
#define SDNPAUTH_EVT_UPDKEYCHGREQ_RCVD    22  /* g120v11 Update Key Change Request received */
#define SDNPAUTH_EVT_UPDKEYCHG_RCVD       23  /* g120v13 Update Key Change received */ 
  
/* local defines to allow for additional action when a certain 4 statistics "exceed" the 
 * max value instead of reach the threshold.
 */
#define SDNPAUTH_AUTHENT_FAIL_MAX_INDEX     0
#define SDNPAUTH_REPLY_TIMEOUT_MAX_INDEX    1
#define SDNPAUTH_REKEY_DUETOFAIL_MAX_INDEX  2
#define SDNPAUTH_ERROR_MSG_SENT_MAX_INDEX   3
/* Max Rekeys Due to Restarts only applies to master */

/* testConfig bits */
/* Do not require SCS to increment in g120v8 requests  */
#define SDNPAUTH_TEST_ALLOW_V8_SCS             1
/* Do not require SCS to increment in g120v10 requests */
#define SDNPAUTH_TEST_ALLOW_V10_SCS            2

/* Define SDNP AuthenticationContext */
typedef struct SDNPAuthenticationContext { 
  
#if SDNPCNFG_SUPPORT_SA_VERSION5
  /* List Member, must be first entry */
  TMWDLIST_MEMBER listMember;

  /* control direction session key */
  TMWCRYPTO_KEY controlSessionKey;
  /* monitor direction session key */
  TMWCRYPTO_KEY monitorSessionKey; 
  TMWTYPES_BOOL monitorSessionKeyExists;
#endif
  
#if SDNPCNFG_SUPPORT_SA_VERSION2
  /* control direction session key */
  DNPDATA_AUTH_KEY controlSessionKeyV2;
  /* monitor direction session key */
  DNPDATA_AUTH_KEY monitorSessionKeyV2; 
  
  /* key change sequence number */
  TMWTYPES_ULONG   keyChangeSequenceNumber;
#endif

  /* User number */
  TMWTYPES_USHORT  userNumber;

  /* The User Update Key must "match" the algorithm.
   *  AES128 uses a 16 octet key
   *  AES256 uses a 32 octet key
   *  proprietary values require whatever they require 
   */
  TMWTYPES_UCHAR keyWrapAlgorithm;
  
  /* current status of session keys */
  TMWTYPES_UCHAR   keyStatus;
  
  /* When this timer expires, session keys should be invalidated */
  TMWTIMER         expectedSessionKeyTimer; 

  /* When this count of ASDUs transmitted or received exceeds max, session keys should be invalidated */
  TMWTYPES_USHORT  keyChangeCount; 
  
  /* Number of session key status requests received during expected key change interval 
   * This will generate an error if too many are received during Expected Key Change Interval
   */
  TMWTYPES_USHORT sessionKeyStatusCount;

  /* last key status message sent to master for this user */
  TMWTYPES_UCHAR   lastKeyStatus[SDNPAUTH_KEYSTATUSMAXSIZE];
  TMWTYPES_USHORT  lastKeyStatusLength;
  
  /* last key change message received from master for this user */
  TMWTYPES_UCHAR   lastKeyChange[SDNPAUTH_KEYCHANGEMAXSIZE];
  TMWTYPES_USHORT  lastKeyChangeLength;
  
  struct SDNPAuthenticationInfo *pAuthInfo;

} SDNPAUTH_USER;

typedef struct SDNPAuthenticationInfo {
 
#if SDNPCNFG_SUPPORT_SA_VERSION5
  /* Length of random challenge data to send in g120v1 challenge and g120v5 key status */
  TMWTYPES_USHORT randomChallengeDataLength;

  /* Maximum number of key status requests during expected session key change interval
   * before notifying human and sending a g120v7 error message on other associations. 
   */
  TMWTYPES_USHORT  maxSessionKeyStatusCount;

  /* These 4 maximum values are in addition to the thresholds for the individual statistics
   * The fifth one maxKeysDueToRestarts is on master.
   * This is made clear in the Secure Authentication Test Procedures. 
   * The outstation will take special actions when a statistic exceeds these Max Values. 
   */
  TMWTYPES_USHORT  maxAuthenticationFailures;
  TMWTYPES_USHORT  maxReplyTimeouts;
  TMWTYPES_USHORT  maxAuthenticationRekeys;
  TMWTYPES_USHORT  maxErrorMessagesSent;

  /* Last key change sequence number KSQ sent by outstation */
  TMWTYPES_ULONG  keyChangeSequenceNumber;
#endif

  /* configuration information */
  TMWSESN        *pSession; 

  /* Agressive mode is enabled */
  TMWTYPES_BOOL   aggressiveModeSupport;

  /* Version 5 requires ability to disallow SHA1 */
  TMWTYPES_BOOL   disallowSHA1;

  /* MAC algorithm to use */
  TMWTYPES_UCHAR  MACAlgorithm;

  /* Number of consecutive application confirm timeouts before declaring a
   * Communications Failure Event. A successful application confirm will clear
   * the counter. You may choose to set this to the same value as maxErrorCount
   * SAv2 or Max Reply Timeout statistic in SAv5, 
   * but this is separately configured and counted.
   */
  TMWTYPES_UCHAR  maxApplTimeoutCount;

  /* Expected session key interval and max count*/
  TMWTYPES_ULONG  keyChangeInterval;
  TMWTYPES_USHORT maxKeyChangeCount;

  /* Sent in error message to master. When error message is sent on link
   * where error did not occur, this identifies which link it occurred on.
   */
  TMWTYPES_USHORT assocId;

  /* how long to wait for any authentication reply */
  TMWTYPES_ULONG  replyTimeout;
  
  /* Count of application layer timeouts before COMM_FAIL event */
  TMWTYPES_USHORT applTimeoutCount;

  /* Extra diagnostics including plain key data before it is encrypted or after it is decrypted */
  TMWTYPES_BOOL   extraDiags;


  /* Device State information */ 
 
  /* State of slave according to Table 6 in Secure Authentication spec.
   * Since only 1 user can be in state other than idle, this state is for currentUserNumber
   */
  TMWTYPES_UCHAR  state;

  /* User number that is in a state other than idle, currently waiting for a reply */
  TMWTYPES_USHORT currentUserNumber;

  /* Received at least one valid challenge response, making aggressive mode OK */
  TMWTYPES_BOOL   rcvdAtLeastOneChallengeResponse;
 
  /* Timer waiting for a reply from master */
  TMWTIMER        replyTimer;
 
  /* per device challenge sequence number, incremented for each challenge sent */
  TMWTYPES_ULONG  challengeSequenceNumber;
  
  /* MAC algorithm specified in last challenge received */
  TMWTYPES_UCHAR  MACAlgorithmRcvd;
  
  /* This contains the last received challenge sequence number plus the number 
   * of aggressive modes requests transmitted 
   */
  TMWTYPES_ULONG  aggressiveModeTxSequence;

  /* contains the number of aggressiveMode requests received since last challenge was sent */
  TMWTYPES_ULONG  aggressiveModeRcvd;

  /* Copy of data from last challenge request sent to master. */ 
  TMWTYPES_UCHAR  lastChallengeSent[SDNPAUTH_TXCHALLENGEMAXSIZE];
  TMWTYPES_USHORT lastChallengeSentLength;

#if SDNPCNFG_SUPPORT_SA_VERSION5
  TMWTYPES_ULONG  lastCSQSent;
  TMWTYPES_UCHAR  lastUnsolChallengeSent[SDNPAUTH_TXCHALLENGEMAXSIZE];
  TMWTYPES_USHORT lastUnsolChallengeSentLength;
  TMWTYPES_ULONG  lastUnsolCSQSent;
  /* This buffer is used at the interface between the SCL and sdnpdata functions */
  TMWTYPES_UCHAR  dataIfBuffer2[SDNPAUTH_BUFFERSIZE];
  /* List of user contexts, one context per user number */
  TMWDLIST        authContexts;

#if DNPCNFG_SUPPORT_AUTHKEYUPDATE
  TMWTYPES_UCHAR  keyChangeMethod;

  /* Status Change Sequence */
  TMWTYPES_ULONG  lastSCS;

  /* Copy of data from last challenge data received from master in g120v11. */ 
  TMWTYPES_UCHAR  masterChallengeData[DNPCNFG_MAX_RX_FRAGMENT_LENGTH];
  TMWTYPES_USHORT masterChallengeDataLength;

  /* Copy of data from last challenge data sent to master in g120v12. */ 
  TMWTYPES_UCHAR  outstationChallengeData[DNPCNFG_MAX_RX_FRAGMENT_LENGTH];
  TMWTYPES_USHORT outstationChallengeDataLength;
 
  TMWTYPES_UCHAR  username[DNPCNFG_AUTH_MAX_USERNAME_LENGTH];
  TMWTYPES_USHORT userNameLength;

  TMWTYPES_CHAR   outstationName[DNPCNFG_AUTH_MAX_OSNAME_LENGTH];
  TMWTYPES_USHORT outstationNameLength;

#if DNPCNFG_SUPPORT_AUTHKEYUPDASYM 
  TMWTYPES_UCHAR *pEncryptedUpdateKeyData;
  TMWTYPES_USHORT encryptedUpdateKeyLength;
#endif
#endif

  /* maximums or threshold values, indexes define statistics */
  TMWTYPES_ULONG statsThreshold[DNPAUTH_NUMBER_STATISTICS]; 
  TMWTYPES_ULONG statistic[DNPAUTH_NUMBER_STATISTICS];  

  /* If this is false, the persistent statistics values still need to be read from database */
  TMWTYPES_BOOL statsLoaded;

  /* This is for the 4 special statistics values that require
   * additional behavior on the outstation when they exceed
   * the max value.
   */
  TMWTYPES_ULONG statsMaxValue[4]; 

#if TMW_PRIVATE_AUTHTEST
  void                 *pTestInfo;
#endif

#endif

  /* Copy of data from last challenge request received from master. */ 
  TMWTYPES_UCHAR  lastChallengeRcvd[SDNPAUTH_RXCHALLENGEMAXSIZE];
  TMWTYPES_USHORT lastChallengeRcvdLength;

  /* Outstanding Request waiting for authentication reply from master */
  TMWSESN_RX_DATA pendingRequest;
  TMWTYPES_UCHAR  pendingData[DNPCNFG_MAX_RX_FRAGMENT_LENGTH];
  TMWTYPES_UCHAR  pendingRequestFc;
  TMWTYPES_UCHAR  applSequenceNumber;
  
  /* This buffer is used at the interface between the SCL and sdnpdata functions */
  TMWTYPES_UCHAR  dataIfBuffer[SDNPAUTH_BUFFERSIZE];

  /* Configuration bitMask to assist in authentication testing.
   * See  defines
   */
  TMWTYPES_ULONG testConfig;

#if SDNPCNFG_SUPPORT_SA_VERSION2
  /* Number of errors messages to be sent before disabling, 0-10 defaults to 2 */
  TMWTYPES_UCHAR  maxErrorCount;

  /* Current number of errors.
   * Spec implies keeping this per user, but since only 1 user is in state 
   * other than idle, this much simpler. For example, with a count per user, 
   * if an event is received for an unexpected user, you need to determine 
   * for which user to increment the error count.
   */
  TMWTYPES_USHORT errorCount;

  /* Array of user contexts for authentication, one context per user number */
  SDNPAUTH_USER authenticationContexts[DNPCNFG_AUTHV2_MAX_NUMBER_USERS];

#ifdef TMW_PRIVATE_AUTHTEST
  /* Force a secure authentication error message to be sent, for test purposes */
  TMWTYPES_BOOL forceErrorMessage;
#endif
#endif

} SDNPAUTH_INFO;

/* Structure to hold info about received message */
typedef struct SDNPAuthRxMsgStruct {
  TMWTYPES_UCHAR *pMsgBuf;
  TMWTYPES_ULONG offset;
  TMWTYPES_USHORT msgLength;
  TMWTYPES_USHORT rxAddress;
  TMWTYPES_UCHAR ac;
  TMWTYPES_UCHAR fc; 
} SDNPAUTH_RX_MSG;


#ifdef __cplusplus
extern "C" {
#endif

/* function: sdnpauth_initConfig
 * purpose:  
 * arguments:  
 * returns:  
 */
void TMWDEFS_GLOBAL sdnpauth_initConfig(
  SDNPSESN_AUTH_CONFIG *pConfig);

/* function: sdnpauth_getConfig
 * purpose:  
 * arguments:  
 * returns:  
 */
void TMWDEFS_GLOBAL sdnpauth_getConfig(
  SDNPSESN *pSDNPSession,
  SDNPSESN_AUTH_CONFIG *pConfig);

/* function: sdnpauth_setConfig
 * purpose:  
 * arguments:  
 * returns:  
 */
void TMWDEFS_GLOBAL sdnpauth_setConfig( 
  SDNPSESN *pSDNPSession,
  const SDNPSESN_AUTH_CONFIG *pConfig);

/* function: sdnpauth_init
 * purpose:  
 * arguments:  
 * returns:  
 */
SDNPAUTH_INFO * TMWDEFS_GLOBAL sdnpauth_init(
  SDNPSESN *pSDNPSession,
  const SDNPSESN_AUTH_CONFIG *pConfig);

/* function: sdnpauth_close
 * purpose:  
 * arguments:  
 * returns:  
 */
void TMWDEFS_GLOBAL sdnpauth_close(
  SDNPSESN *pSDNPSession);

/* function: sdnpauth_applTimeout
 * purpose: 
 * arguments:    
 * returns:    
 *  void
 */  
void TMWDEFS_GLOBAL sdnpauth_applTimeout(
  SDNPSESN *pSDNPSession);

/* function: sdnpauth_applConfirm
 * purpose: 
 * arguments:    
 * returns:    
 *  void
 */  
void TMWDEFS_GLOBAL sdnpauth_applConfirm(
  SDNPSESN *pSDNPSession);

/* function: sdnpauth_processing
 * purpose: Perform secure authentication processing on received message
 *  or event such as timeout, according to Secure Authentication specification.
 * arguments: 
 *  pSession - session 
 *  event - event to be processed. 
 *    SDNPAUTH_EVT_MSG_RECEIVED if pRxFragment is not TMWDEFS_NULL
 *  pRxFragment - pointer to structure containing received fragment or
 *    TMWDEFS_NULL if a timeout event is to be processed.
 * returns:
 *  transmit data structure to be processed by rest of SCL
 *  or TMWDEFS_NULL if there is no message to be processed
 */
TMWSESN_RX_DATA *sdnpauth_processing(
  TMWSESN *pSession,
  TMWTYPES_ULONG event,
  TMWTYPES_USHORT userNumber,
  TMWSESN_RX_DATA *pRxFragment);

/* function: sdnpauth_addPreChallengeV1
 * purpose: add g120v1 challenge to end of message containing events with CON
 *  bit set. This will tell the master to send the application confirm in an
 *  aggressive mode request.
 * arguments:    
 *   pResponse - pointer to transmit data structure 
 * returns:    
 *  void
 */  
 void TMWDEFS_GLOBAL sdnpauth_addPreChallengeV1(
  SDNPSESN *pSDNPSession,
  TMWSESN_TX_DATA *pResponse);

/* function: sdnpauth_addAggrModeStart
 * purpose: add aggressive mode object group 120 v3 to start of message
 * arguments:   
 *   pResponse - pointer to transmit data structure to contain response
 * returns:   
 *  TMWDEFS_TRUE if successful
 */  
TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpauth_addAggrModeStart( 
  SDNPSESN *pSDNPSession,
  TMWSESN_TX_DATA *pResponse);

/* function: sdnpauth_addAggrModeEnd
 * purpose: add aggressive mode object group 120 v9 to end of message
 * arguments:   
 *   pResponse - pointer to transmit data structure containing response
 * returns:   
 *  TMWDEFS_TRUE if successful
 */    
TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpauth_addAggrModeEnd( 
  SDNPSESN *pSDNPSession,
  TMWSESN_TX_DATA *pResponse);

/* function: sdnpauth_aggrDelay
 * purpose:  update delay value, recalculate hash value for g120v9, and ask
   *   link layer to rechecksum. This is called when a time delay response is
   *   sent to the master using aggressive mode.
   * arguments:
   *   pResponse - pointer to transmit data structure containing response
   *   pDelayBuf - 2 byte delay time to update in message.
 * arguments:    
 * returns:
 *  void
 */    
void TMWDEFS_GLOBAL sdnpauth_aggrDelay(
  TMWSESN_TX_DATA *pResponse,
  TMWTYPES_UCHAR *pDelayBuf);

/* function: sdnpauth_OKToSend
 * purpose:  
 * arguments:    
 * returns:   
 *  TMWDEFS_TRUE if successful
 */    
TMWTYPES_BOOL TMWDEFS_CALLBACK sdnpauth_OKToSend(
  TMWSESN *pSession);

/* function: sdnpauth_saveLastChallenge
 * purpose:  
 * arguments:    
 * returns:   
 *  void
 */    
void TMWDEFS_CALLBACK sdnpauth_saveLastChallenge(
  TMWSESN_TX_DATA *pTxData);
 
/* function: sdnpauth_getKeyStatus 
 * purpose: Get the status of the key for the specified user
 * arguments:   
 *  pSession - pointer to session structure returned by sdnpsesn_openSession()
 *  userNumber - Secure Authentication User number to get key status for
 * returns:    
 *  status of key
 */  
TMWTYPES_UCHAR TMWDEFS_GLOBAL sdnpauth_getKeyStatus(
  TMWSESN *pSession,
  TMWTYPES_USHORT userNumber);

/* function: sdnpauth_resetLastSCS
 * purpose:  
 * arguments:    
 * returns:   
 *  TMWDEFS_TRUE if successful
 */    
TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpauth_resetLastSCS(
   TMWSESN *pSession);

/* function: sdnpauth_forceSessionKeyTimeout
 * purpose: Force the expected session key change timer to expire for test purposes. 
 * arguments:   
 *  pSession - pointer to session structure returned by sdnpsesn_openSession()
 *  userNumber - Secure Authentication User number to force timeout on.
 * returns:   
 *  TMWDEFS_TRUE if successful
 *  TMWDEFS_FALSE otherwise
 */  
TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpauth_forceSessionKeyTimeout( 
  TMWSESN *pSession,
  TMWTYPES_USHORT userNumber);


#ifdef __cplusplus
}
#endif
#endif
