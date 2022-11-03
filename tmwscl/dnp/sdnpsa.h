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

/* file: sdnpsa.h
 * description: This file is intended for internal SCL use only.
 *   DNP Slave functionality for Secure Authentication
 */
#ifndef SDNPSA_DEFINED
#define SDNPSA_DEFINED

#include "tmwscl/dnp/sdnpauth.h"
#include "tmwscl/dnp/sdnpcnfg.h"
#include "tmwscl/dnp/dnputil.h"
#include "tmwscl/dnp/sdnpsesp.h" 

 
#ifdef __cplusplus
extern "C" {
#endif

/* function: sdnpsa_addUser
 * purpose:  
 *  NOTE: this is not called by user application
 * arguments:  
 * returns:  
 */
TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpsa_addUser( 
  SDNPAUTH_INFO *pInfo,
  TMWTYPES_USHORT userNumber);

/* function: sdnpsa_getUser
 * purpose:  
 *  NOTE: this is not called by user application
 * arguments:  
 * returns:  
 */
TMWTYPES_USHORT TMWDEFS_GLOBAL sdnpsa_getUser( 
  SDNPAUTH_INFO  *pAuthInfo,
  TMWTYPES_USHORT index);
 
/* function: sdnpsa_removeUser
 * purpose:  
 *  NOTE: this is not called by user application
 * arguments:  
 * returns:  
 */
TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpsa_removeUser( 
  SDNPAUTH_INFO *pInfo,
  TMWTYPES_USHORT userNumber);

/* function: sdnpsa_getConfig
 * purpose:  
 *  NOTE: this is not called by user application
 * arguments:  
 * returns:  
 */
void TMWDEFS_GLOBAL sdnpsa_getConfig(
  void *pInfo,
  SDNPSESN_AUTH_CONFIG *pConfig);

/* function: sdnpsa_setConfig
 * purpose:  
 *  NOTE: this is not called by user application
 * arguments:  
 * returns:  
 */
void TMWDEFS_GLOBAL sdnpsa_setConfig( 
  void *pInfo,
  const SDNPSESN_AUTH_CONFIG *pConfig);

/* function: sdnpsa_init
 * purpose:  
 *  NOTE: this is not called by user application
 * arguments:  
 * returns:  
 */
SDNPAUTH_INFO * TMWDEFS_GLOBAL sdnpsa_init(
  SDNPSESN *pSDNPSession,
  const SDNPSESN_AUTH_CONFIG *pConfig);

/* function: sdnpsa_close
 * purpose:  
 *  NOTE: this is not called by user application
 * arguments:  
 * returns:  
 */
void TMWDEFS_GLOBAL sdnpsa_close(
  void *pInfo);

/* function: sdnpsa_getKeyStatus */
TMWTYPES_UCHAR TMWDEFS_GLOBAL sdnpsa_getKeyStatus(
  TMWSESN *pSession,
  TMWTYPES_USHORT userNumber);

/* function: sdnpsa_resetLastSCS
 * purpose:   
 * arguments:  
 * returns:  
 */
TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpsa_resetLastSCS(
   TMWSESN *pSession);
 
/* function: sdnpsa_applTimeout
 * purpose:  
 * arguments:  
 * returns:  
 */
void TMWDEFS_GLOBAL sdnpsa_applTimeout(
  SDNPSESN *pSDNPSession);

/* function: sdnpsa_applConfirm
 * purpose:  
 * arguments:  
 * returns:  
 */
void TMWDEFS_GLOBAL sdnpsa_applConfirm(
  SDNPSESN *pSDNPSession);

/* function: sdnpsa_processing
 * purpose: Perform secure authentication processing on received message
 *  or event such as timeout, according to Secure Authentication specification.
 *  NOTE: this is not called by user application
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
TMWSESN_RX_DATA * TMWDEFS_GLOBAL sdnpsa_processing(
  TMWSESN *pSession,
  TMWTYPES_ULONG event,
  TMWTYPES_USHORT userNumber,
  TMWSESN_RX_DATA *pRxFragment);

/* function: sdnpsa_addPreChallengeV1
 * purpose: add g120v1 challenge to end of message containing events with CON
 *  bit set. This will tell the master to send the application confirm in an
 *  aggressive mode request.
 *  NOTE: this is not called by user application
 * arguments:    
 * returns:    
 *  void
 */  
 void TMWDEFS_GLOBAL sdnpsa_addPreChallengeV1(
  SDNPSESN *pSDNPSession,
  TMWSESN_TX_DATA *pResponse);

/* function: sdnpsa_addAggrModeStart
 * purpose: add aggressive mode object group 120 v3 to start of message
 *  NOTE: this is not called by user application
 * arguments:   
 * returns:   
 *  TMWDEFS_TRUE if successful
 */  
TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpsa_addAggrModeStart( 
  SDNPSESN *pSDNPSession,
  TMWSESN_TX_DATA *pResponse);

/* function: sdnpsa_addAggrModeEnd
 * purpose: add aggressive mode object group 120 v9 to end of message
 *  NOTE: this is not called by user application
 * arguments:    
 * returns:   
 *  TMWDEFS_TRUE if successful
 */    
TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpsa_addAggrModeEnd( 
  SDNPSESN *pSDNPSession,
  TMWSESN_TX_DATA *pResponse);

/* function: sdnpsa_aggrDelay
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
void TMWDEFS_GLOBAL sdnpsa_aggrDelay(
  TMWSESN_TX_DATA *pResponse,
  TMWTYPES_UCHAR *pDelayBuf);

/* function: sdnpsa_OKToSend
 * purpose:  
 *  NOTE: this is not called by user application
 * arguments:    
 * returns:   
 *  TMWDEFS_TRUE if successful
 */    
TMWTYPES_BOOL TMWDEFS_CALLBACK sdnpsa_OKToSend(
  TMWSESN *pSession);

/* function: sdnpsa_saveLastChallenge
 * purpose:  
 *  NOTE: this is not called by user application
 * arguments:    
 * returns:   
 *  void
 */    
void TMWDEFS_CALLBACK sdnpsa_saveLastChallenge(
  TMWSESN_TX_DATA *pTxData);

/* function: sdnpsa_sendErrorResponseV7
 * purpose:   
 * arguments:    
 * returns:   
 *  void
 */    
void TMWDEFS_GLOBAL sdnpsa_sendErrorResponseV7(
  SDNPSESN *pSDNPSession,
  TMWTYPES_USHORT rxAddress,
  TMWTYPES_ULONG sequenceNumber,
  TMWTYPES_USHORT userNumber,
  TMWTYPES_UCHAR errorCode,
  TMWTYPES_CHAR *pErrorText,
  TMWTYPES_USHORT errorTextLength);

/* function: sdnpsa_msgSent  
 * purpose: Indicate that a message has been sent so that statistic
 *   can be incremented.  
 * arguments:
 *  pSession - identifies session 
 * returns:
 *  void
 */
void TMWDEFS_GLOBAL sdnpsa_msgSent(
  TMWSESN *pSession);

/* function: sdnpsa_forceSessionKeyTimeout
 * purpose: Force the expected session key change timer to expire for test purposes. 
 *  NOTE: this is called FOR TEST PURPOSES ONLY
 * arguments:   
 *  pSession - pointer to session structure returned by sdnpsesn_openSession()
 *  userNumber - Secure Authentication User number to force timeout on.
 * returns:   
 *  TMWDEFS_TRUE if successful
 *  TMWDEFS_FALSE otherwise
 */  
TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpsa_forceSessionKeyTimeout( 
  TMWSESN *pSession,
  TMWTYPES_USHORT userNumber);

#ifdef __cplusplus
}
#endif

#endif /* SDNPSA_DEFINED */
