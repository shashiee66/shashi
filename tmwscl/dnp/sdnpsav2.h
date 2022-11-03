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

/* file: sdnpsav2.h
 * description: This file is intended for internal SCL use only.
 *   DNP Slave functionality for Secure Authentication Version 2.0
 */
#ifndef SDNPSAV2_DEFINED
#define SDNPSAV2_DEFINED 

#include "tmwscl/dnp/sdnpauth.h"
#include "tmwscl/dnp/dnputil.h"
#include "tmwscl/dnp/sdnpsesp.h"
  
#ifdef __cplusplus
extern "C" {
#endif

/* function: sdnpsav2_initConfig
 * purpose:  
 * arguments:  
 * returns:  
 */
void TMWDEFS_GLOBAL sdnpsav2_initConfig(
  SDNPSESN_AUTH_CONFIG *pConfig);

/* function: sdnpsav2_getConfig
 * purpose:  
 * arguments:  
 * returns:  
 */
void TMWDEFS_GLOBAL sdnpsav2_getConfig(
  void *pInfo,
  SDNPSESN_AUTH_CONFIG *pConfig);

/* function: sdnpsav2_setConfig
 * purpose:  
 * arguments:  
 * returns:  
 */
void TMWDEFS_GLOBAL sdnpsav2_setConfig( 
  void *pInfo,
  const SDNPSESN_AUTH_CONFIG *pConfig);

/* function: sdnpsav2_init
 * purpose:  
 * arguments:  
 * returns:  
 */
SDNPAUTH_INFO * TMWDEFS_GLOBAL sdnpsav2_init(
  SDNPSESN *pSDNPSession,
  const SDNPSESN_AUTH_CONFIG *pConfig);

/* function: sdnpsav2_close
 * purpose:  
 * arguments:  
 * returns:  
 */
void TMWDEFS_GLOBAL sdnpsav2_close(
  void *pInfo);

/* function: sdnpsav2_getKeyStatus 
 * purpose:  
 * arguments:  
 * returns:  
 */
TMWTYPES_UCHAR TMWDEFS_GLOBAL sdnpsav2_getKeyStatus(
  TMWSESN *pSession,
  TMWTYPES_USHORT userNumber);

/* function: sdnpsav2_applTimeout
 * purpose:  
 * arguments:  
 * returns:  
 */
void TMWDEFS_GLOBAL sdnpsav2_applTimeout(
  SDNPSESN *pSDNPSession);

/* function: sdnpsav2_applConfirm
 * purpose:  
 * arguments:  
 * returns:  
 */
void TMWDEFS_GLOBAL sdnpsav2_applConfirm(
  SDNPSESN *pSDNPSession);

/* function: sdnpsav2_processing
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
TMWSESN_RX_DATA *sdnpsav2_processing(
  TMWSESN *pSession,
  TMWTYPES_ULONG event,
  TMWTYPES_USHORT userNumber,
  TMWSESN_RX_DATA *pRxFragment);

/* function: sdnpsav2_addPreChallengeV1
 * purpose: add g120v1 challenge to end of message containing events with CON
 *  bit set. This will tell the master to send the application confirm in an
 *  aggressive mode request.
 * arguments:    
 * returns:    
 *  void
 */  
 void TMWDEFS_GLOBAL sdnpsav2_addPreChallengeV1(
  SDNPSESN *pSDNPSession,
  TMWSESN_TX_DATA *pResponse);

/* function: sdnpsav2_addAggrModeStart
 * purpose: add aggressive mode object group 120 v3 to start of message
 * arguments:   
 * returns:   
 *  TMWDEFS_TRUE if successful
 */  
TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpsav2_addAggrModeStart( 
  SDNPSESN *pSDNPSession,
  TMWSESN_TX_DATA *pResponse);

/* function: sdnpsav2_addAggrModeEnd
 * purpose: add aggressive mode object group 120 v9 to end of message
 * arguments:    
 * returns:   
 *  TMWDEFS_TRUE if successful
 */    
TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpsav2_addAggrModeEnd( 
  SDNPSESN *pSDNPSession,
  TMWSESN_TX_DATA *pResponse);

/* function: sdnpsav2_aggrDelay
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
void TMWDEFS_GLOBAL sdnpsav2_aggrDelay(
  TMWSESN_TX_DATA *pResponse,
  TMWTYPES_UCHAR *pDelayBuf);

/* function: sdnpsav2_OKToSend
 * purpose:  
 * arguments:    
 * returns:   
 *  TMWDEFS_TRUE if successful
 */    
TMWTYPES_BOOL TMWDEFS_CALLBACK sdnpsav2_OKToSend(
  TMWSESN *pSession);

/* function: sdnpsav2_saveLastChallenge
 * purpose:  
 * arguments:    
 * returns:   
 *  void
 */    
void TMWDEFS_CALLBACK sdnpsav2_saveLastChallenge(
  TMWSESN_TX_DATA *pTxData);
 
/* function: sdnpsav2_forceSessionKeyTimeout
 * purpose: Force the expected session key change timer to expire for test purposes. 
 * arguments:   
 *  pSession - pointer to session structure returned by sdnpsesn_openSession()
 *  userNumber - Secure Authentication User number to force timeout on.
 * returns:   
 *  TMWDEFS_TRUE if successful
 *  TMWDEFS_FALSE otherwise
 */  
TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpsav2_forceSessionKeyTimeout( 
  TMWSESN *pSession,
  TMWTYPES_USHORT userNumber);

/* function: sdnpsav2_forceErrorMessage
 * purpose: Force outstation to send an error message in response to next request.
 *  This is for test purposes only.
 * arguments:   
 *  pSession - pointer to session structure returned by sdnpsesn_openSession()
 * returns:   
 *  TMWDEFS_TRUE if successful
 *  TMWDEFS_FALSE otherwise
 */  
TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpsav2_forceErrorMessage(
  TMWSESN *pSession);


#ifdef __cplusplus
}
#endif
#endif /* SDNPSAV2_DEFINED */
