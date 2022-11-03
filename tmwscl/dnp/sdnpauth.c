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

/* file: sdnpauth.c
 * description: Implement methods used to create and send Master DNP3 
 * secure authentication requests.
 */
#include "tmwscl/dnp/dnpdiag.h"
#include "tmwscl/dnp/dnpstat.h"
#include "tmwscl/dnp/dnpdtime.h" 
#include "tmwscl/dnp/sdnpcnfg.h"
#include "tmwscl/dnp/sdnpdiag.h"
#include "tmwscl/dnp/sdnpdata.h" 
#include "tmwscl/dnp/sdnpauth.h"
#include "tmwscl/dnp/sdnpunsl.h"
#include "tmwscl/dnp/sdnputil.h"
    
#if DNPCNFG_SUPPORT_AUTHENTICATION
#if SDNPCNFG_SUPPORT_SA_VERSION5
#include "tmwscl/dnp/sdnpsa.h"
#endif
#if SDNPCNFG_SUPPORT_SA_VERSION2
#include "tmwscl/dnp/sdnpsav2.h"
#endif 

/* function: sdnpauth_initConfig */
void TMWDEFS_GLOBAL sdnpauth_initConfig(
  SDNPSESN_AUTH_CONFIG *pConfig)
{ 
  pConfig->assocId = 0;
  pConfig->replyTimeout = TMWDEFS_SECONDS(2);  
  pConfig->maxApplTimeoutCount = 0;
  pConfig->keyChangeInterval = TMWDEFS_MINUTES(30);  
  pConfig->maxKeyChangeCount = 2000;
  pConfig->aggressiveModeSupport = TMWDEFS_TRUE;
  pConfig->extraDiags = TMWDEFS_FALSE;
  pConfig->testConfig = 0;
  pConfig->operateInV2Mode = TMWDEFS_FALSE;

  /* These were modes set by functions. Now they are also part of the configuration */
  pConfig->authSendAggrResp = TMWDEFS_FALSE;
  pConfig->authSendAggrUnsol = TMWDEFS_FALSE;
  pConfig->preChallengeApplConf = TMWDEFS_FALSE;

#if SDNPCNFG_SUPPORT_SA_VERSION2  
  {
    int i;
    pConfig->operateInV2Mode = TMWDEFS_TRUE;
    pConfig->maxErrorCount = 2;
    pConfig->MACAlgorithm = DNPAUTH_MAC_SHA1_10OCTET;
  
    for(i=1; i<DNPCNFG_AUTHV2_MAX_NUMBER_USERS; i++)
    { 
      pConfig->authUsers[i].userNumber=0;
    }

    /* Make the first user the default user number (1) */
    pConfig->authUsers[0].userNumber = DNPAUTH_DEFAULT_USERNUMBER;
  }
#endif

#if SDNPCNFG_SUPPORT_SA_VERSION5 
  pConfig->randomChallengeDataLength = DNPAUTH_MIN_CHALLENGE_DATA;
  pConfig->maxSessionKeyStatusCount = 5;

  pConfig->maxAuthenticationFailures = 5;
  pConfig->maxReplyTimeouts = 3;
  pConfig->maxAuthenticationRekeys = 3;
  pConfig->maxErrorMessagesSent = 2;

  pConfig->operateInV2Mode = TMWDEFS_FALSE;
  pConfig->MACAlgorithm = DNPAUTH_MAC_SHA256_16OCTET;
  pConfig->disallowSHA1 = TMWDEFS_FALSE;
#endif
}

void TMWDEFS_GLOBAL sdnpauth_getConfig(
  SDNPSESN *pSDNPSession,
  SDNPSESN_AUTH_CONFIG *pConfig)
{
  if(pSDNPSession->pAuthenticationInfo != TMWDEFS_NULL)
  {
#if SDNPCNFG_SUPPORT_SA_VERSION2 
    if(pSDNPSession->dnp.operateInV2Mode)
    {
      sdnpsav2_getConfig(pSDNPSession->pAuthenticationInfo, pConfig);
      return;
    }
#endif  

#if SDNPCNFG_SUPPORT_SA_VERSION5
    sdnpsa_getConfig(pSDNPSession->pAuthenticationInfo, pConfig);
    return;
#endif  
  }
  else
  {
    sdnpauth_initConfig(pConfig);
  }
} 

void TMWDEFS_GLOBAL sdnpauth_setConfig( 
  SDNPSESN *pSDNPSession,
  const SDNPSESN_AUTH_CONFIG *pConfig)
{ 
#if SDNPCNFG_SUPPORT_SA_VERSION2 
  if(pConfig->operateInV2Mode)
  {
    sdnpsav2_setConfig(pSDNPSession->pAuthenticationInfo, pConfig);
    return;
  }
#endif  

#if SDNPCNFG_SUPPORT_SA_VERSION5
    sdnpsa_setConfig(pSDNPSession->pAuthenticationInfo, pConfig);
#endif  
}

void TMWDEFS_GLOBAL sdnpauth_addPreChallengeV1(
  SDNPSESN *pSDNPSession,
  TMWSESN_TX_DATA *pResponse)
{
#if SDNPCNFG_SUPPORT_SA_VERSION2 
  if(pSDNPSession->dnp.operateInV2Mode)
  {
    sdnpsav2_addPreChallengeV1(pSDNPSession, pResponse);
    return;
  }
#endif  

#if SDNPCNFG_SUPPORT_SA_VERSION5
    sdnpsa_addPreChallengeV1(pSDNPSession, pResponse);
#endif  
}
 
/* function: sdnpauth_addAggressiveMode
 * purpose: add aggressive mode object group 120 v3 to start of message
 * arguments:    
 * returns:   
 *  TMWDEFS_TRUE if successful
 */    
TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpauth_addAggrModeStart( 
  SDNPSESN *pSDNPSession,
  TMWSESN_TX_DATA *pResponse)
{ 
#if SDNPCNFG_SUPPORT_SA_VERSION2 
  if(pSDNPSession->dnp.operateInV2Mode)
  {
    return sdnpsav2_addAggrModeStart(pSDNPSession, pResponse);
  }
#endif  

#if SDNPCNFG_SUPPORT_SA_VERSION5
  return sdnpsa_addAggrModeStart(pSDNPSession, pResponse);
#else
  return TMWDEFS_FALSE;
#endif  
}    

/* function: sdnpauth_addAggrModeEnd
 * purpose: add aggressive mode object group 120 v9 to end of message
 * arguments:    
 * returns:   
 *  TMWDEFS_TRUE if successful
 */    
TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpauth_addAggrModeEnd( 
  SDNPSESN *pSDNPSession,
  TMWSESN_TX_DATA *pResponse)
{ 
#if SDNPCNFG_SUPPORT_SA_VERSION2 
  if(pSDNPSession->dnp.operateInV2Mode)
  {
    return sdnpsav2_addAggrModeEnd(pSDNPSession, pResponse);
  }
#endif  

#if SDNPCNFG_SUPPORT_SA_VERSION5
  return sdnpsa_addAggrModeEnd(pSDNPSession, pResponse);
#else
  return TMWDEFS_FALSE;
#endif
}    
  
/* function: sdnpauth_aggrDelay */
/* update time and recalculate hash value, then ask link layer to rechecksum request */
void TMWDEFS_GLOBAL sdnpauth_aggrDelay(
  TMWSESN_TX_DATA *pResponse,
  TMWTYPES_UCHAR *pDelayBuf)
{
#if SDNPCNFG_SUPPORT_SA_VERSION2
  SDNPSESN *pSDNPSession = (SDNPSESN*)pResponse->pSession;
  if(pSDNPSession->dnp.operateInV2Mode)
  {
    sdnpsav2_aggrDelay(pResponse, pDelayBuf);
    return;
  } 
#endif  

#if SDNPCNFG_SUPPORT_SA_VERSION5
  sdnpsa_aggrDelay(pResponse, pDelayBuf);
#endif 
}

/* function: sdnpauth_init */
SDNPAUTH_INFO * TMWDEFS_GLOBAL sdnpauth_init(
  SDNPSESN *pSDNPSession,
  const SDNPSESN_AUTH_CONFIG *pConfig)
{  
#if SDNPCNFG_SUPPORT_SA_VERSION2  
  if(pSDNPSession->dnp.operateInV2Mode)
  {
    return sdnpsav2_init(pSDNPSession, pConfig);
  }
#endif  

#if SDNPCNFG_SUPPORT_SA_VERSION5
  return sdnpsa_init(pSDNPSession, pConfig);
#else
  return TMWDEFS_NULL;
#endif  
}

/* function: sdnpauth_close */
void TMWDEFS_GLOBAL sdnpauth_close(
  SDNPSESN *pSDNPSession)
{  
#if SDNPCNFG_SUPPORT_SA_VERSION2  
  if(pSDNPSession->dnp.operateInV2Mode)
  {
    sdnpsav2_close(pSDNPSession->pAuthenticationInfo);
    return;
  }
#endif  

#if SDNPCNFG_SUPPORT_SA_VERSION5
    sdnpsa_close(pSDNPSession->pAuthenticationInfo);
#endif  
}   
  
/* This returns TMWDEFS_NULL if processing of this message is complete  
 * (a challenge request might have been sent back to master)
 * and the request queued for later processing.
 */
TMWSESN_RX_DATA *sdnpauth_processing(
  TMWSESN *pSession,
  TMWTYPES_ULONG event,
  TMWTYPES_USHORT userNumber,
  TMWSESN_RX_DATA *pRxFragment)
{
#if SDNPCNFG_SUPPORT_SA_VERSION2 
  SDNPSESN *pSDNPSession = (SDNPSESN*)pSession;
  if(pSDNPSession->dnp.operateInV2Mode)
  {
    return sdnpsav2_processing(pSession, event, userNumber, pRxFragment);
  }
#endif  

#if SDNPCNFG_SUPPORT_SA_VERSION5
  return sdnpsa_processing(pSession, event, userNumber, pRxFragment);
#else
  return TMWDEFS_NULL;    
#endif    
}

void TMWDEFS_GLOBAL sdnpauth_applTimeout(
  SDNPSESN *pSDNPSession)
{
#if SDNPCNFG_SUPPORT_SA_VERSION2  
  if(pSDNPSession->dnp.operateInV2Mode)
  {
    sdnpsav2_applTimeout(pSDNPSession);
    return;
  }
#endif  

#if SDNPCNFG_SUPPORT_SA_VERSION5
   sdnpsa_applTimeout(pSDNPSession);
#endif  
}

/* function: sdnpauth_applConfirm */
void TMWDEFS_GLOBAL sdnpauth_applConfirm(
  SDNPSESN *pSDNPSession)
{
#if SDNPCNFG_SUPPORT_SA_VERSION2  
  if(pSDNPSession->dnp.operateInV2Mode)
  {
    sdnpsav2_applConfirm(pSDNPSession);
    return;
  }
#endif  

#if SDNPCNFG_SUPPORT_SA_VERSION5
   sdnpsa_applConfirm(pSDNPSession);
#endif  
}

TMWTYPES_BOOL TMWDEFS_CALLBACK sdnpauth_OKToSend(
  TMWSESN *pSession)
{ 
#if SDNPCNFG_SUPPORT_SA_VERSION2 
  SDNPSESN *pSDNPSession = (SDNPSESN*)pSession;
  if(pSDNPSession->dnp.operateInV2Mode)
  {
    return sdnpsav2_OKToSend(pSession);
  }
#endif  

#if SDNPCNFG_SUPPORT_SA_VERSION5
    return sdnpsa_OKToSend(pSession);
#else
  return TMWDEFS_TRUE;
#endif   
}

void TMWDEFS_CALLBACK sdnpauth_saveLastChallenge(
  TMWSESN_TX_DATA *pTxData)
{
#if SDNPCNFG_SUPPORT_SA_VERSION2 
  SDNPSESN *pSDNPSession = (SDNPSESN*)pTxData->pSession;
  if(pSDNPSession->dnp.operateInV2Mode)
  {
     sdnpsav2_saveLastChallenge(pTxData);
     return;
  }
#endif  

#if SDNPCNFG_SUPPORT_SA_VERSION5
   sdnpsa_saveLastChallenge(pTxData);
#endif  
}

/* function: sdnpauth_getKeyStatus */
TMWTYPES_UCHAR TMWDEFS_GLOBAL sdnpauth_getKeyStatus(
  TMWSESN *pSession,
  TMWTYPES_USHORT userNumber)
{
#if SDNPCNFG_SUPPORT_SA_VERSION2 
  SDNPSESN *pSDNPSession = (SDNPSESN*)pSession;
  if (pSDNPSession->dnp.operateInV2Mode)
  {
    return sdnpsav2_getKeyStatus(pSession, userNumber);
  }
#endif  

#if SDNPCNFG_SUPPORT_SA_VERSION5
  return sdnpsa_getKeyStatus(pSession, userNumber);
#else   
  return DNPAUTH_KEY_NOTINIT;
#endif  
}

TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpauth_resetLastSCS(
   TMWSESN *pSession)
{
#if SDNPCNFG_SUPPORT_SA_VERSION5
  return sdnpsa_resetLastSCS(pSession);
#else
  TMWTARG_UNUSED_PARAM(pSession);
  return TMWDEFS_FALSE;
#endif
}
#ifdef TMW_PRIVATE_AUTHTEST

TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpauth_forceSessionKeyTimeout( 
  TMWSESN *pSession,
  TMWTYPES_USHORT userNumber)
{
#if SDNPCNFG_SUPPORT_SA_VERSION2 
  SDNPSESN *pSDNPSession = (SDNPSESN*)pSession;
  if(pSDNPSession->dnp.operateInV2Mode)
  {
    return sdnpsav2_forceSessionKeyTimeout(pSession, userNumber);
  }
#endif  

#if SDNPCNFG_SUPPORT_SA_VERSION5 && TMW_PRIVATE_AUTHTEST
  return sdnpsa_forceSessionKeyTimeout(pSession, userNumber);
#else   
  return TMWDEFS_FALSE;
#endif
}  
 
#endif

#endif /* DNPCNFG_SUPPORT_AUTHENTICATION */

