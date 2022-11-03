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
#include "tmwscl/dnp/sdnpunsl.h"
#include "tmwscl/dnp/sdnputil.h"
#include "tmwscl/dnp/sdnpo122.h"
#include "tmwscl/dnp/sdnpsa.h"

#if SDNPCNFG_SUPPORT_SA_VERSION5
#if SDNPDATA_SUPPORT_OBJ120 

#if TMW_PRIVATE_AUTHTEST   
#include "tmwscl/dnp/sdnpauthtest.h"
#endif


/* DNPCNFG_SUPPORT_AUTHENTICATION must be defined to support object 120
 */
#if !DNPCNFG_SUPPORT_AUTHENTICATION
#pragma message("*****DNPCNFG_SUPPORT_AUTHENTICATION must be TMWDEFS_TRUE to support SDNPDATA OBJ120")  
#endif 

/* function: _validateMsgLength 
 * Validate received message length 
 * returns: TMWDEFS_TRUE if message is long enough.
 */
static TMWTYPES_BOOL TMWDEFS_LOCAL _validateMsgLength(
  TMWSESN *pSession, 
  SDNPAUTH_RX_MSG *pRxFragment, 
  TMWTYPES_USHORT length)
{
  if((pRxFragment->offset+length) > pRxFragment->msgLength)
  {
    pRxFragment->offset = pRxFragment->msgLength;
    if(pSession != TMWDEFS_NULL)
    {
      DNPDIAG_ERROR(pSession->pChannel, pSession, DNPDIAG_INVALID_SIZE);
    }
    else
    {
      DNPDIAG_ERROR(TMWDEFS_NULL, TMWDEFS_NULL, DNPDIAG_INVALID_SIZE);
    }

    return TMWDEFS_FALSE;
  }
  return TMWDEFS_TRUE;
}

/* function: _macLength  
 * purpose: return the length of the mac data based on the algorithm enum specified
 * arguments: algorithm enumeration
 * returns: length of mac data
 */
static TMWTYPES_UCHAR TMWDEFS_LOCAL _macLength(TMWTYPES_UCHAR algorithm)
{
  if(algorithm == DNPAUTH_MAC_SHA1_10OCTET)
  {
    return 10;
  }
  else if(algorithm == DNPAUTH_MAC_SHA256_16OCTET)
  {
    return 16;
  } 
  else if((algorithm == DNPAUTH_MAC_SHA256_8OCTET) || (algorithm == DNPAUTH_MAC_SHA1_8OCTET))
  {
    return 8;
  } 
  else if(algorithm == DNPAUTH_MAC_AESGMAC_12OCTET)
  {
    return 12;
  } 
  else
  { 
    return 4;
  }
}
 
/* function: _getAuthInfo
 * purpose: Get pointer to authentication information for this session
 * arguments: session pointer 
 * returns: pointer to authentication info structure
 */ 
static SDNPAUTH_INFO * TMWDEFS_LOCAL _getAuthInfo(
  SDNPSESN *pSDNPSession)
{
  return((SDNPAUTH_INFO*)pSDNPSession->pAuthenticationInfo);
} 

/* function: _getKey */
static TMWTYPES_BOOL TMWDEFS_LOCAL _getKey(
    TMWSESN             *pSession,
    void                *cryptoHandle, 
    TMWCRYPTO_KEYTYPE    keyType,
    void *               keyHandle,
    TMWCRYPTO_KEY       *pKey)
  { 
    TMWTYPES_BOOL status = tmwcrypto_getKey(cryptoHandle, keyType, keyHandle, pKey);
    if(!status)
    { 
      DNPDIAG_ERROR(pSession->pChannel, pSession, DNPDIAG_AUTH_GETKEYFAIL);
    }
    return status;
}

/* function: _resetSecStatMaxValue
 * purpose: Reset security statistic max value
 * arguments: session pointer 
 *            index indicating which statistic max value
 * returns:   
 *  void
 */ 
static void TMWDEFS_LOCAL _resetSecStatMaxValue(
  SDNPSESN *pSDNPSession, 
  TMWTYPES_USHORT index)
{
  SDNPAUTH_INFO *pAuthInfo = _getAuthInfo(pSDNPSession);

  switch(index)
  {
  case SDNPAUTH_AUTHENT_FAIL_MAX_INDEX:
    pAuthInfo->statsMaxValue[index] = pAuthInfo->statistic[DNPAUTH_AUTHENT_FAIL_INDEX] + pAuthInfo->maxAuthenticationFailures;
    break;
  case SDNPAUTH_REPLY_TIMEOUT_MAX_INDEX:
    pAuthInfo->statsMaxValue[index] = pAuthInfo->statistic[DNPAUTH_REPLY_TIMEOUT_INDEX] + pAuthInfo->maxReplyTimeouts;
    break;
  case SDNPAUTH_REKEY_DUETOFAIL_MAX_INDEX:
    pAuthInfo->statsMaxValue[index] = pAuthInfo->statistic[DNPAUTH_REKEY_DUETOFAIL_INDEX] + pAuthInfo->maxAuthenticationRekeys;
    break;
  case SDNPAUTH_ERROR_MSG_SENT_MAX_INDEX:
    pAuthInfo->statsMaxValue[index] = pAuthInfo->statistic[DNPAUTH_ERROR_MSG_SENT_INDEX] + pAuthInfo->maxErrorMessagesSent;
    break;
  }
}

/* function: _adjustStatsAndThresholds
* purpose: Load the persistent statistics from the database if available and 
*           adjust the thresholds with these statistics as a base.
* arguments: pAuthInfo - pointer to auth info structure
* returns: void
*/
static void TMWDEFS_LOCAL _adjustStatsAndThresholds(SDNPAUTH_INFO *pAuthInfo)
{
  SDNPSESN *pSDNPSession;
  int i;

  pSDNPSession = (SDNPSESN *)pAuthInfo->pSession;

  /* Statistics should be loaded from database initially since they must be persistent over restarts! 
   * after that a local in memory copy will be used for performance
   */
  if (!pAuthInfo->statsLoaded)
  {
    for (i = 0; i < DNPAUTH_NUMBER_STATISTICS; i++)
    {
      void *pPoint;
      pPoint = sdnpdata_authSecStatGetPoint(pSDNPSession->pDbHandle, (TMWTYPES_USHORT)i);
      if (pPoint != TMWDEFS_NULL)
      {
        TMWTYPES_ULONG count = 0;
        TMWTYPES_UCHAR flags = 0;
        sdnpdata_authSecStatRead(pPoint, &count, &flags);
        pAuthInfo->statistic[i] = count;
        /* as long as one is successful the stats are in the database */
        pAuthInfo->statsLoaded = TMWDEFS_TRUE;
      }
    }
  } 

  /* set thresholds for statistics, relative to current statistic values */
  for (i = 0; i < DNPAUTH_NUMBER_STATISTICS; i++)
  {
    pAuthInfo->statsThreshold[i] = pAuthInfo->statistic[i] + sdnpdata_authSecStatThreshold(pSDNPSession->pDbHandle, (TMWTYPES_USHORT)i);
  }

  /* set 4 special max values, relative to current statistic values */
  pAuthInfo->statsMaxValue[SDNPAUTH_AUTHENT_FAIL_MAX_INDEX] = pAuthInfo->statistic[DNPAUTH_AUTHENT_FAIL_INDEX] + pAuthInfo->maxAuthenticationFailures;
  pAuthInfo->statsMaxValue[SDNPAUTH_REPLY_TIMEOUT_MAX_INDEX] = pAuthInfo->statistic[DNPAUTH_REPLY_TIMEOUT_INDEX] + pAuthInfo->maxReplyTimeouts;
  pAuthInfo->statsMaxValue[SDNPAUTH_REKEY_DUETOFAIL_MAX_INDEX] = pAuthInfo->statistic[DNPAUTH_REKEY_DUETOFAIL_INDEX] + pAuthInfo->maxAuthenticationRekeys;
  pAuthInfo->statsMaxValue[SDNPAUTH_ERROR_MSG_SENT_MAX_INDEX] = pAuthInfo->statistic[DNPAUTH_ERROR_MSG_SENT_INDEX] + pAuthInfo->maxErrorMessagesSent;
}

/* function: _authSecStatIncrement
 * purpose: Increment security statistic and if it exceeds threshold generate event
 * arguments: session pointer 
 *            index indicating which statistic
 * returns:  
 *  new statistic value
 */ 
static TMWTYPES_ULONG TMWDEFS_LOCAL _authSecStatIncrement(
  SDNPSESN *pSDNPSession, 
  TMWTYPES_USHORT index)
{
  void *pPoint; 
  SDNPAUTH_INFO *pAuthInfo;
  TMWTYPES_ULONG count;

  pAuthInfo = _getAuthInfo(pSDNPSession);

  if (!pAuthInfo->statsLoaded)
    _adjustStatsAndThresholds(pAuthInfo);

  count = ++pAuthInfo->statistic[index];
  
  pPoint = sdnpdata_authSecStatGetPoint(pSDNPSession->pDbHandle, index);
  if(pPoint != TMWDEFS_NULL)
    sdnpdata_authSecStatSet(pPoint, pAuthInfo->statistic[index]);

  if(count >= pAuthInfo->statsThreshold[index])
  {
    TMWTYPES_UCHAR flags;
    TMWDTIME timeStamp;
    sdnputil_getDateTime((TMWSESN*)pSDNPSession, &timeStamp);

    flags = 0x01;
    if(pPoint != TMWDEFS_NULL)
      sdnpdata_authSecStatRead(pPoint, &count, &flags);
    sdnpo122_addEvent((TMWSESN*)pSDNPSession, 0, index, count, flags, &timeStamp); 

    /* reset event report threshold for this statistic */
    pAuthInfo->statsThreshold[index] = pAuthInfo->statistic[index]
      + sdnpdata_authSecStatThreshold(pSDNPSession->pDbHandle, index);
  }

  return count;
}

/* function: _unexpectedMsgRcvd
 * purpose: Handle common error situation incrementing statistic and logging it.
 * returns:   
 *  void
 */ 
static void TMWDEFS_LOCAL _unexpectedMsgRcvd(
  SDNPSESN *pSDNPSession, 
  TMWTYPES_UCHAR state, 
  TMWTYPES_ULONG event, 
  TMWSESN_RX_DATA *pRxFragment)
{
  _authSecStatIncrement(pSDNPSession, DNPAUTH_UNEXPECTED_MSG_INDEX);
  _authSecStatIncrement(pSDNPSession, DNPAUTH_DISCARDED_MSG_INDEX); 
  sdnpdata_authLogUnexpectedMsg(pSDNPSession->pDbHandle, state, event, pRxFragment); 
}

/* function: _findUserContext
 * purpose: Get pointer to per user authentication context
 * arguments: pointer to authentication info structure 
 * returns: pointer to authentication user structure
 */ 
static SDNPAUTH_USER * TMWDEFS_LOCAL _findUserContext(
  SDNPAUTH_INFO *pAuthInfo, 
  TMWTYPES_USHORT userNumber)
{
  SDNPAUTH_USER *pUserContext = TMWDEFS_NULL;
  if(userNumber == 0)
    return TMWDEFS_NULL;

  while((pUserContext = (SDNPAUTH_USER *)tmwdlist_getAfter(
    &pAuthInfo->authContexts, (TMWDLIST_MEMBER *)pUserContext)) != TMWDEFS_NULL)
  {  
    if(userNumber == pUserContext->userNumber) 
    {
      return(pUserContext);
    }
  } 
  return TMWDEFS_NULL;
}

/* function: _verifyAndGetSessionKeys
 * purpose: Decrypt and verify the session keys for the specified authentication user
 * arguments:   
 * returns:  
 *  TMWDEFS_TRUE if successful
 *  TMWDEFS_FALSE otherwise
 */ 
static TMWTYPES_BOOL TMWDEFS_LOCAL _verifyAndGetSessionKeys(
  SDNPAUTH_INFO  *pAuthInfo,
  SDNPAUTH_USER  *pUserContext,
  TMWTYPES_UCHAR *pEncryptedValue,
  TMWTYPES_USHORT encryptedValueLength,
  TMWTYPES_USHORT *pKeyLength)
{
  TMWCRYPTO_KEY updateKey;
  TMWTYPES_UCHAR *pValue = pAuthInfo->dataIfBuffer;
  TMWTYPES_USHORT decryptedLength = SDNPAUTH_BUFFERSIZE;
  TMWTYPES_BOOL status = TMWDEFS_FALSE;
  SDNPSESN *pSDNPSession = (SDNPSESN *)pAuthInfo->pSession;

  /* Decrypt data from message using the Update Key in the database. */
  if(_getKey(pAuthInfo->pSession, pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_USER_UPDATE_KEY, (void*)pUserContext->userNumber, &updateKey)) 
  {
    if(tmwcrypto_decryptData(pSDNPSession->dnp.pCryptoHandle, dnpauth_keyWraptoTMWCryptoAlgo(pUserContext->keyWrapAlgorithm), 
      &updateKey, pEncryptedValue, encryptedValueLength, pValue, &decryptedLength))
    { 
      TMWTYPES_USHORT keyStatusOffset;
      TMWTYPES_USHORT keyLength = pValue[0];

#if TMWCNFG_SUPPORT_DIAG
      DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pSDNPSession, dataTypeKeyData, pEncryptedValue, encryptedValueLength, TMWDIAG_ID_RX);
      if(pAuthInfo->extraDiags)
      {
        DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pSDNPSession, dataTypeSessKeyData, pValue, decryptedLength, TMWDIAG_ID_RX);
      }
#endif

      if(keyLength > DNPAUTH_MAX_KEY_LENGTH)
      {
        DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_TOO_BIG);  
        return TMWDEFS_FALSE;
      }

      /* make sure keyStatusMsg matches, 
       * do not check length is exact, because of padding that might have been added. 
       * We could check this for AES Key Wrap, but not other proprietary algorithms.
       */ 
      keyStatusOffset = (keyLength*2) +2;
      if((decryptedLength >= keyStatusOffset+pUserContext->lastKeyStatusLength)
        && (!memcmp(&pValue[keyStatusOffset], 
        pUserContext->lastKeyStatus, pUserContext->lastKeyStatusLength)))
      {
        /* Set keys */
        tmwcrypto_setSessionKeyData(pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_USER_CONTROL_SESSION_KEY, &pValue[2], keyLength, &pUserContext->controlSessionKey);
        tmwcrypto_setSessionKeyData(pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_USER_MONITOR_SESSION_KEY, &pValue[keyLength+2], keyLength, &pUserContext->monitorSessionKey);
        *pKeyLength = keyLength;

        pUserContext->monitorSessionKeyExists = TMWDEFS_TRUE;
        status = TMWDEFS_TRUE;

#if TMW_PRIVATE_AUTHTEST
        /* Save the keys for testing purposes */
        tmwcrypto_setKeyData(pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_USER_CONTROL_SESSION_KEY, (void*)pUserContext->userNumber, &pValue[2], keyLength);
        tmwcrypto_setKeyData(pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_USER_MONITOR_SESSION_KEY, (void*)pUserContext->userNumber, &pValue[keyLength+2], keyLength);
#endif
      }
      else
      { 
        SDNPDIAG_AUTHSESKEYFAIL(pAuthInfo->pSession, decryptedLength, (TMWTYPES_USHORT)((keyLength*2) + 2 + pUserContext->lastKeyStatusLength));
      }
    }
    else
    {
      SDNPDIAG_AUTHSESDECRYPTFAIL(pAuthInfo->pSession, pUserContext->keyWrapAlgorithm);
    }
  }
  else
  {
    DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_BADUSER);
  }

  return status;
}
   
/* function: _determineMACValue
 * purpose: Calculate the MAC Value according to the MAC algorithm and key specified, 
 * including the challenge message and critical message (if not TMWDEFS_NULL).
 * Copy up to the number of bytes allowed by *pMACValueLength into *pMACValue
 * and set *pMACValueLength to the number of bytes copied.
 * arguments:   
 * returns:  
 *  TMWDEFS_TRUE if successful
 *  TMWDEFS_FALSE otherwise
 */ 
static TMWTYPES_BOOL TMWDEFS_LOCAL _determineMACValue(
  SDNPAUTH_INFO    *pAuthInfo,
  TMWTYPES_BOOL     received,
  TMWTYPES_UCHAR    algorithm,
  TMWCRYPTO_KEY    *pKey,
  TMWTYPES_UCHAR   *challengeMessage,
  TMWTYPES_USHORT   challengeMsgLength,
  TMWTYPES_UCHAR   *criticalMsg,
  TMWTYPES_USHORT   criticalMsgLength,
  TMWTYPES_UCHAR   *pMACValue,
  TMWTYPES_USHORT  *pMACValueLength)
{
  TMWTYPES_BOOL status;
  TMWTYPES_USHORT dataLength;
  SDNPSESN *pSDNPSession = (SDNPSESN *)pAuthInfo->pSession;
  TMWTYPES_UCHAR *pValue = pAuthInfo->dataIfBuffer;
  
#if !TMWCNFG_SUPPORT_DIAG
  TMWTARG_UNUSED_PARAM(received);
#endif

  /* Now use dataIfBuffer and dataLength for data to be MAC ed */
  /* concatenate challenge message and critical message if there is one */
  memcpy(pValue, challengeMessage, challengeMsgLength);
  dataLength = challengeMsgLength;
    
  if(criticalMsgLength > 0)
  {
    memcpy(pValue+dataLength, criticalMsg, criticalMsgLength);
    dataLength = (TMWTYPES_USHORT)(dataLength + criticalMsgLength);
  }
 

  status = TMWDEFS_FALSE;
  if(dnpauth_MACtoLength(algorithm) <= *pMACValueLength)
  {
    status = tmwcrypto_MACValue(pSDNPSession->dnp.pCryptoHandle, dnpauth_MACtoTMWCryptoAlgo(algorithm), 
      pKey, dnpauth_MACtoLength(algorithm), 
      pValue, (TMWTYPES_USHORT)dataLength, 
      pMACValue, pMACValueLength);

#if TMWCNFG_SUPPORT_DIAG
    DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pAuthInfo->pSession, dataTypePlainData, pValue, dataLength, (received) ? TMWDIAG_ID_RX : 0);
    DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pAuthInfo->pSession, dataTypeGenMAC, pMACValue, *pMACValueLength, (received) ? TMWDIAG_ID_RX : 0);
#endif
  }

  if(!status)
  {
    DNPDIAG_ERROR(pAuthInfo->pSession->pChannel, pAuthInfo->pSession, DNPDIAG_AUTH_MACFAIL); 
  }

  return(status);
}

/* function: _determineAggrMACValue
 * purpose: Calculate the MAC Value according to the MAC algorithm and key specified.
 * Copy up to the number of bytes allowed by *pMACValueLength into *pMACValue
 * and set *pMACValueLength to the number of bytes copied.
 *  This is called when building AND receiving an aggressive mode request
 * arguments:   
 * returns:  
 *  TMWDEFS_TRUE if successful
 *  TMWDEFS_FALSE otherwise
 */ 
static TMWTYPES_BOOL TMWDEFS_LOCAL _determineAggrMACValue(
  SDNPAUTH_INFO    *pAuthInfo,
  TMWTYPES_BOOL     received,
  TMWTYPES_UCHAR   *pMsgBuf,
  TMWTYPES_UCHAR    algorithm,
  TMWCRYPTO_KEY    *pKey,  
  TMWTYPES_UCHAR   *pLastChallengeMsg,
  TMWTYPES_USHORT   lastChallengeLength, 
  TMWTYPES_UCHAR   *dnpMsg,
  TMWTYPES_ULONG    dnpMsgLength,
  TMWTYPES_UCHAR   *pMACValue,
  TMWTYPES_USHORT  *pMACValueLength)
{
  TMWTYPES_BOOL status;
  TMWTYPES_USHORT dataLength;
  SDNPSESN *pSDNPSession = (SDNPSESN*)pAuthInfo->pSession;
  TMWTYPES_UCHAR *pValue = pAuthInfo->dataIfBuffer;

#if TMWCNFG_SUPPORT_CRYPTO_AESGMAC
  /* If AES-GMAC, set up init vector */
  if(algorithm == DNPAUTH_MAC_AESGMAC_12OCTET)
  { 
    /* 
      pSession->destAddress if received, srcAddress if sending
      usernumber from this message
      last ksq sent by OS
      csq from v3 part of this message.
    */
    TMWTYPES_UCHAR *pInitVector; 
    TMWTYPES_ULONG  csq; 
    TMWTYPES_USHORT vectorLength; 
    TMWTYPES_USHORT userNumber;

    pInitVector = pAuthInfo->dataIfBuffer2;  
    vectorLength = 0; 
    
    /* Get userNumber from ObjectGroup120V3 at start of message */
    tmwtarg_get16(&pMsgBuf[10], &userNumber); 

    /* Get csq from ObjectGroup120V3 at start of message */
    tmwtarg_get32(&pMsgBuf[6], &csq); 

    if(received)
      tmwtarg_store16(&pSDNPSession->dnp.tmw.destAddress, &pInitVector[vectorLength]);
    else
      tmwtarg_store16(&pSDNPSession->dnp.tmw.srcAddress, &pInitVector[vectorLength]);

    vectorLength += 2;

    tmwtarg_store16(&userNumber, &pInitVector[vectorLength]);
    vectorLength += 2;
    
    tmwtarg_store32(&pAuthInfo->keyChangeSequenceNumber, &pInitVector[vectorLength]);
    vectorLength += 4;
      
    tmwtarg_store32(&csq, &pInitVector[vectorLength]);
    vectorLength += 4;

#if TMWCNFG_SUPPORT_DIAG
    DNPDIAG_AUTH_INITVECTOR((TMWSESN*)pAuthInfo->pSession, pInitVector, vectorLength, (received) ? TMWDIAG_ID_RX : 0); 
#endif
 
    tmwcrypto_setIVector(pSDNPSession->dnp.pCryptoHandle, pKey, pInitVector, vectorLength); 
  }
#else
  TMWTARG_UNUSED_PARAM(pMsgBuf);
#endif

  /* Now use dataIfBuffer to hold data to be MACed */
  /* concatenate last challenge message, new CSQ, and dnp message */
  memcpy(pValue, pLastChallengeMsg, lastChallengeLength);
  dataLength = lastChallengeLength;
  
  memcpy(pValue+dataLength, dnpMsg, dnpMsgLength);
  dataLength = (TMWTYPES_USHORT)(dataLength + dnpMsgLength);
    
  status = TMWDEFS_FALSE;
  if(dnpauth_MACtoLength(algorithm) <= *pMACValueLength)
  {
    status = tmwcrypto_MACValue(pSDNPSession->dnp.pCryptoHandle, dnpauth_MACtoTMWCryptoAlgo(algorithm), 
      pKey, dnpauth_MACtoLength(algorithm),
      pValue, (TMWTYPES_USHORT)dataLength, 
      pMACValue, pMACValueLength);

#if TMWCNFG_SUPPORT_DIAG
    DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pAuthInfo->pSession, dataTypePlainData, pValue, dataLength, (received) ? TMWDIAG_ID_RX : 0);
    DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pAuthInfo->pSession, dataTypeGenMAC, pMACValue, *pMACValueLength, (received) ? TMWDIAG_ID_RX : 0);
#endif

#if TMWCNFG_SUPPORT_CRYPTO_AESGMAC
    if(algorithm == DNPAUTH_MAC_AESGMAC_12OCTET)
      /* Set the init vector back to empty */
      tmwcrypto_setIVector(pSDNPSession->dnp.pCryptoHandle, pKey, TMWDEFS_NULL, 0); 
#endif
  }

  if(status != TMWDEFS_TRUE)
  {
    DNPDIAG_ERROR(pAuthInfo->pSession->pChannel, pAuthInfo->pSession, DNPDIAG_AUTH_MACFAIL); 
  }
  
  return(status);
}

/* function: _validateChallengeReply
 * purpose: Verify that the challenge reply is valid  
 * arguments:  
 *  TMWDEFS_TRUE if successful
 *  TMWDEFS_FALSE otherwise
 */
static TMWTYPES_BOOL TMWDEFS_LOCAL _validateChallengeReply(
  SDNPSESN       *pSDNPSession,
  SDNPAUTH_USER  *pUserContext,
  TMWTYPES_UCHAR *pRcvdValue,
  TMWTYPES_USHORT rcvdValueLength,
  TMWTYPES_ULONG  rcvdSequenceNumber)
{
  TMWTYPES_UCHAR value[32];
  TMWTYPES_USHORT length = 32;
  TMWTYPES_BOOL status = TMWDEFS_FALSE;
  SDNPAUTH_INFO *pAuthInfo = _getAuthInfo(pSDNPSession);
  
  if(pUserContext->keyStatus != DNPAUTH_KEY_OK)
  {
    DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_KEYNOTOK); 
    return TMWDEFS_FALSE;
  }
 
  if(rcvdSequenceNumber != pAuthInfo->lastCSQSent) 
  {
    DNPDIAG_ERROR(pAuthInfo->pSession->pChannel, pAuthInfo->pSession, DNPDIAG_AUTH_RXBADSEQ); 
    return TMWDEFS_FALSE;
  }

#if TMWCNFG_SUPPORT_CRYPTO_AESGMAC
  /* If AES-GMAC, set up init vector */
  if(pAuthInfo->MACAlgorithm == DNPAUTH_MAC_AESGMAC_12OCTET)
  { 
    /* 
     pSession->destAddress;
     pUserContext->userNumber
     pAuthInfo->keyChangeSequenceNumber
     rcvdSequenceNumber
    */
    TMWTYPES_UCHAR *pInitVector = pAuthInfo->dataIfBuffer2;  
    TMWTYPES_USHORT vectorLength = 0;

    tmwtarg_store16(&pSDNPSession->dnp.tmw.destAddress, &pInitVector[vectorLength]);
    vectorLength += 2;

    tmwtarg_store16(&pUserContext->userNumber, &pInitVector[vectorLength]);
    vectorLength += 2;
    
    tmwtarg_store32(&pAuthInfo->keyChangeSequenceNumber, &pInitVector[vectorLength]);
    vectorLength += 4;
    
    tmwtarg_store32(&rcvdSequenceNumber, &pInitVector[vectorLength]);
    vectorLength += 4;

    DNPDIAG_AUTH_INITVECTOR((TMWSESN*)pAuthInfo->pSession, pInitVector, vectorLength, TMWDIAG_ID_RX); 

    tmwcrypto_setIVector(pSDNPSession->dnp.pCryptoHandle, &pUserContext->controlSessionKey, pInitVector, vectorLength); 
  }
#endif

  /* included in MAC Value calculation:
   *   challenge message that was sent
   *   if reasonChallengeSent == CRITICAL
   *     challenged ASDU that was received   
   *   padding data 
  */
  if((rcvdValueLength !=  _macLength(pAuthInfo->MACAlgorithm))
    ||(!_determineMACValue(pAuthInfo, TMWDEFS_TRUE,
    pAuthInfo->MACAlgorithm, &pUserContext->controlSessionKey,
    pAuthInfo->lastChallengeSent, pAuthInfo->lastChallengeSentLength, 
    pAuthInfo->pendingRequest.pMsgBuf, pAuthInfo->pendingRequest.msgLength,
    value, &length)))
  {
    status = TMWDEFS_FALSE;
  } 
  else if((length == rcvdValueLength)
    &&(!memcmp(pRcvdValue, value, rcvdValueLength)))
  {
    status = TMWDEFS_TRUE; 
  }

#if TMWCNFG_SUPPORT_CRYPTO_AESGMAC
  if(pAuthInfo->MACAlgorithm == DNPAUTH_MAC_AESGMAC_12OCTET)
    /* Set the init vector back to empty */
    tmwcrypto_setIVector(pSDNPSession->dnp.pCryptoHandle,  &pUserContext->controlSessionKey, TMWDEFS_NULL, 0); 
#endif

  if(!status)
  {
    DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_CHALLENGERPLY); 
  }
  return status;
} 
 
/* function: _validateAggressiveMode
 * purpose: Verify if this aggressive mode request is valid
 * arguments:   
 *  TMWDEFS_TRUE if successful
 *  TMWDEFS_FALSE otherwise
 */ 
static TMWTYPES_BOOL TMWDEFS_LOCAL _validateAggressiveMode(
  SDNPAUTH_INFO *pAuthInfo,
  SDNPAUTH_USER *pUserContext,
  TMWTYPES_ULONG sequenceNumber,
  TMWTYPES_ULONG expectedSequenceNumber, 
  SDNPAUTH_RX_MSG *pRxFragment,
  TMWTYPES_USHORT bytesInObject)
{
  TMWTYPES_BOOL status;
  TMWTYPES_UCHAR value[32];
  TMWTYPES_USHORT length = 32;

  status = TMWDEFS_FALSE;
  if(pUserContext != TMWDEFS_NULL)
  {
    if(pUserContext->keyStatus != DNPAUTH_KEY_OK)
    {
      DNPDIAG_ERROR(pAuthInfo->pSession->pChannel, pAuthInfo->pSession, DNPDIAG_AUTH_KEYNOTOK);
    }
    else if(bytesInObject == _macLength(pAuthInfo->MACAlgorithm))
    { 
      if(sequenceNumber != expectedSequenceNumber)
      {
        DNPDIAG_ERROR(pAuthInfo->pSession->pChannel, pAuthInfo->pSession, DNPDIAG_AUTH_RXBADSEQ);
        return TMWDEFS_FALSE;
      }

      if((pRxFragment->ac & DNPDEFS_AC_UNSOLICITED) != 0)
      { 
        if(_determineAggrMACValue(pAuthInfo, TMWDEFS_TRUE, pRxFragment->pMsgBuf,
          pAuthInfo->MACAlgorithm, &pUserContext->controlSessionKey,
          pAuthInfo->lastUnsolChallengeSent, pAuthInfo->lastUnsolChallengeSentLength,
          pRxFragment->pMsgBuf, pRxFragment->offset,
          value, &length))
        {
          if(!memcmp(value, &pRxFragment->pMsgBuf[pRxFragment->offset], bytesInObject))
          {
            status = TMWDEFS_TRUE;
          }
        }
      }
      else
      {
        if(_determineAggrMACValue(pAuthInfo, TMWDEFS_TRUE, pRxFragment->pMsgBuf,
          pAuthInfo->MACAlgorithm, &pUserContext->controlSessionKey,
          pAuthInfo->lastChallengeSent, pAuthInfo->lastChallengeSentLength,
          pRxFragment->pMsgBuf, pRxFragment->offset,
          value, &length))
        {
          if(!memcmp(value, &pRxFragment->pMsgBuf[pRxFragment->offset], bytesInObject))
          {
            status = TMWDEFS_TRUE;
          }
        }
      }
    }
  }

  return status;
}
 
/* function: _getUserAndSequence
 * purpose: Get user and sequence number from the received authentication request
 * arguments:   
 * returns:   
 *  TMWDEFS_FALSE if message is badly formatted
 */ 
static TMWTYPES_BOOL TMWDEFS_LOCAL _getUserAndSequence(
   SDNPAUTH_RX_MSG *pRxFragment, 
   TMWTYPES_UCHAR variation, 
   TMWTYPES_ULONG *pSequenceNumber, 
   TMWTYPES_USHORT *pUserNumber)
{
  TMWTYPES_ULONG offset = pRxFragment->offset;

  if(variation == 4)
  {
    /* Protect against badly formatted message */
    if(!_validateMsgLength(TMWDEFS_NULL, pRxFragment, 2))
    {
      return TMWDEFS_FALSE;
    }
    tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], pUserNumber);
    pRxFragment->offset += 2;
  }
  else if ((variation < 8) ||(variation == 13))
  {
    /* Skip number of bytes in object */
    if(variation != 3)
      offset += 2;
   
    /* Protect against badly formatted message */
    if(!_validateMsgLength(TMWDEFS_NULL, pRxFragment, 6))
    {
      return TMWDEFS_FALSE;
    }

    tmwtarg_get32(&pRxFragment->pMsgBuf[offset], pSequenceNumber);
    offset += 4;

    tmwtarg_get16(&pRxFragment->pMsgBuf[offset], pUserNumber);
  }
  return TMWDEFS_TRUE;
}  
  
/* function: _replyTimeout
 * purpose: process authentication reply timeout
 * arguments:   
 * returns:   
 *  void
 */ 
static void TMWDEFS_CALLBACK _replyTimeout(void *pParam)
{ 
  TMWSESN *pSession = (TMWSESN *)pParam;  
  SDNPAUTH_INFO *pAuthInfo = _getAuthInfo((SDNPSESN*)pSession);

  DNPSTAT_AUTH_RESP_TIMEOUT(pSession);
  sdnpsa_processing(pSession, SDNPAUTH_EVT_REPLYTIMEOUT, pAuthInfo->currentUserNumber, TMWDEFS_NULL); 
}

/* function: _expectedKeyChangeTimeout
 * purpose: process expected key change timeout. 
 *  When this expires it indicates the session keys have not been received in a timely fashion
 * arguments:  
 *   pParam - pointer to authentication user structure
 * returns:   
 *  void
 */ 
static void TMWDEFS_CALLBACK _expectedKeyChangeTimeout(void *pParam)
{ 
  SDNPAUTH_USER *pUserContext = (SDNPAUTH_USER*)pParam;
  TMWSESN *pSession = pUserContext->pAuthInfo->pSession;

  DNPSTAT_AUTH_KEY_CHANGE(pSession, pUserContext->userNumber); 
  sdnpsa_processing(pSession, SDNPAUTH_EVT_EXPECTEDKEYTIMEOUT, pUserContext->userNumber, TMWDEFS_NULL); 
} 
 
/* function: _startExpectedKeyChangeTimer
 * purpose:  
 * arguments:  
 * returns:   
 *  void
 */ 
static void TMWDEFS_LOCAL _startExpectedKeyChangeTimer(
  SDNPAUTH_INFO *pAuthInfo,
  TMWTYPES_USHORT userNumber,
  TMWTYPES_ULONG timeout) 
{
  SDNPAUTH_USER *pUserContext = _findUserContext(pAuthInfo, userNumber); 
  if(pUserContext != TMWDEFS_NULL)
  { 
    /* Reset this to zero.
     * TMW-We could keep a separate timer for counting excessive session key status requests
     * but resetting this count when a VALID key change received seems more appropriate.
     */
    pUserContext->sessionKeyStatusCount = 0;

    pUserContext->keyChangeCount = 0; 
    if(timeout > 0)
    {
      tmwtimer_start(&pUserContext->expectedSessionKeyTimer,
        timeout, pAuthInfo->pSession->pChannel, _expectedKeyChangeTimeout, pUserContext); 
    }
  }
}

/* function: _authMsgReceived
 * purpose:  
 * arguments:  
 * returns:   
 *  void
 */ 
static void TMWDEFS_LOCAL _authMsgReceived(
 SDNPAUTH_INFO *pAuthInfo,
 TMWTYPES_UCHAR variation,
 TMWTYPES_USHORT userNumber)
{ 
  SDNPAUTH_USER *pUserContext = _findUserContext(pAuthInfo, userNumber); 
  TMWTARG_UNUSED_PARAM(variation);
  DNPSTAT_AUTH_RCVD(pAuthInfo->pSession, variation);

  if(pUserContext != TMWDEFS_NULL)
  {
    pUserContext->keyChangeCount++;
    if(pUserContext->keyChangeCount >= pAuthInfo->maxKeyChangeCount)
    {  
      _startExpectedKeyChangeTimer(pAuthInfo, pUserContext->userNumber, 10); 
    }
  }
}

/* function: _msgSent
 * purpose:  
 * arguments:  
 * returns:   
 *  void
 */ 
static void TMWDEFS_LOCAL _msgSent(
 SDNPAUTH_INFO *pAuthInfo,
 TMWTYPES_UCHAR variation,
 TMWTYPES_USHORT userNumber)
{
  SDNPAUTH_USER *pUserContext = _findUserContext(pAuthInfo, userNumber); 
  TMWTARG_UNUSED_PARAM(variation);
  DNPSTAT_AUTH_SENT(pAuthInfo->pSession, variation); 

  if(pUserContext != TMWDEFS_NULL)
  { 
    pUserContext->keyChangeCount++;
    if(pUserContext->keyChangeCount > pAuthInfo->maxKeyChangeCount)
    {
      _startExpectedKeyChangeTimer(pAuthInfo, pUserContext->userNumber, 10); 
    }
  }
}

/* function: _initializeResponse
 * purpose: initialize an application layer reply
 * arguments:
 *  pSession - session to respond to
 *  pResponse - response data
 * returns:
 *  void
 */
static void TMWDEFS_LOCAL _initializeResponse(
  SDNPSESN *pSDNPSession,
  TMWSESN_TX_DATA *pResponse,
  TMWTYPES_UCHAR sequenceNumber,
  TMWTYPES_UCHAR fc)
{  
  /* Application Control */  
  pResponse->pMsgBuf[0] = sequenceNumber | DNPDEFS_AC_FIRST | DNPDEFS_AC_FINAL;

  /* Function Code */
  pResponse->pMsgBuf[1] = fc;

  /* IIN bits */
  pResponse->pMsgBuf[2] = (TMWTYPES_UCHAR)((pSDNPSession->iin & 0xff00) >> 8);
  pResponse->pMsgBuf[3] = (TMWTYPES_UCHAR)(pSDNPSession->iin & 0x00ff);

  /* Misc initialization */ 
  pResponse->txFlags = TMWSESN_TXFLAGS_NO_RESPONSE;
  ((DNPCHNL_TX_DATA*)pResponse)->priority = DNPCHNL_DEFAULT_AUTH_PRIORITY;

  /* Current message length */
  pResponse->msgLength = 4;
  
  DNPDIAG_BUILD_MESSAGE(pResponse->pChannel, (TMWSESN*)pSDNPSession, pResponse->pMsgDescription); 
}

/* function: _sendChallengeV1
 * purpose: send object group 120 v1 authentication challenge request to master
 * arguments:   
 * returns:   
 */  
static void TMWDEFS_LOCAL _sendChallengeV1(
  SDNPSESN *pSDNPSession,
  TMWTYPES_USHORT rxAddress,
  TMWTYPES_UCHAR reason)
{ 
  TMWSESN_TX_DATA *pResponse;
  TMWTYPES_USHORT length;
  TMWTYPES_USHORT lengthIndex;
  DNPCHNL *pDNPChannel = (DNPCHNL *)pSDNPSession->dnp.tmw.pChannel;
  SDNPAUTH_INFO *pAuthInfo = _getAuthInfo(pSDNPSession);  

  pResponse = dnpchnl_newTxData((TMWCHNL *)pDNPChannel,
    (TMWSESN*)pSDNPSession, pDNPChannel->txFragmentSize, rxAddress);

  if(pResponse == TMWDEFS_NULL)
  {
    return;
  } 
#if TMWCNFG_SUPPORT_DIAG
  pResponse->pMsgDescription = "Authentication Challenge";
#endif

  _initializeResponse(pSDNPSession, pResponse, pAuthInfo->applSequenceNumber, DNPDEFS_FC_AUTH_RESPONSE);
  pResponse->txFlags = 0;
   
  pResponse->pMsgBuf[pResponse->msgLength++] = DNPDEFS_OBJ_120_AUTHENTICATION;
  pResponse->pMsgBuf[pResponse->msgLength++] = 1;
  pResponse->pMsgBuf[pResponse->msgLength++] = DNPDEFS_QUAL_16BIT_FREE_FORMAT;
  pResponse->pMsgBuf[pResponse->msgLength++] = 1;
  
  DNPDIAG_SHOW_TX_OBJECT_HDR((TMWSESN*)pSDNPSession, DNPDEFS_OBJ_120_AUTHENTICATION, 1, DNPDEFS_QUAL_16BIT_FREE_FORMAT);
  
  /* Save index for where to put 2 byte length */
  lengthIndex = pResponse->msgLength;
  pResponse->msgLength += 2;

  /* Add object data */
  pAuthInfo->challengeSequenceNumber++;
  pAuthInfo->lastCSQSent = pAuthInfo->challengeSequenceNumber;

  tmwtarg_store32(&pAuthInfo->challengeSequenceNumber, pResponse->pMsgBuf + pResponse->msgLength);
  pResponse->msgLength += 4;

  /* 2 byte user number */
  pResponse->pMsgBuf[pResponse->msgLength++] = 0; /* Outstation always sends 0 for challenge */
  pResponse->pMsgBuf[pResponse->msgLength++] = 0; /* Outstation always sends 0 for challenge */ 

  pResponse->pMsgBuf[pResponse->msgLength++] = pAuthInfo->MACAlgorithm;
  pResponse->pMsgBuf[pResponse->msgLength++] = reason;

  /* Calculate how much room left in message */
  length = (pResponse->maxLength - pResponse->msgLength);
  if (length > DNPAUTH_MAX_CHALLENGE_DATA)
    length = DNPAUTH_MAX_CHALLENGE_DATA;

  if(!tmwcrypto_getRandomData(pSDNPSession->dnp.pCryptoHandle, pAuthInfo->randomChallengeDataLength,
    &pResponse->pMsgBuf[pResponse->msgLength], &length))
  {
    dnpchnl_freeTxData(pResponse);
    return;
  }

  DNPDIAG_SHOW_AUTH_CHALLENGE((TMWSESN*)pSDNPSession, 0, pAuthInfo->challengeSequenceNumber, pAuthInfo->MACAlgorithm, reason, 0);
  DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pSDNPSession, dataTypeGenChallData, &pResponse->pMsgBuf[pResponse->msgLength], length, 0);

  pResponse->msgLength = (TMWTYPES_USHORT)(pResponse->msgLength + length);
 
  /* Update the length in the object prefix. length of challenge data +8 */
  length = length +8;
  tmwtarg_store16(&length, pResponse->pMsgBuf + lengthIndex); 

  sdnpdata_authLogTx(pSDNPSession->pDbHandle, 1, 0, pAuthInfo->challengeSequenceNumber, pResponse->pMsgBuf, pResponse->msgLength);  

  /* Set flag so that this challenge will be saved in lastChallengeSent by beforeTxCallback */
  pResponse->txFlags |= (TMWSESN_TXFLAGS_NO_RESPONSE |TMWSESN_TXFLAGS_DNP_AUTH_CHALL);

  /* We do not know what user we are challenging */
  pAuthInfo->currentUserNumber = 0;
  
  pAuthInfo->aggressiveModeRcvd = 0;

  /* start reply timer */
  tmwtimer_start(&pAuthInfo->replyTimer,
    pAuthInfo->replyTimeout,
    pSDNPSession->dnp.tmw.pChannel, _replyTimeout, pSDNPSession);

  /* Send challenge to master*/ 
  if(!dnpchnl_sendFragment(pResponse))
  {
    dnpchnl_freeTxData(pResponse);
  }  
  
  _msgSent(pAuthInfo, 1, 0);
}  
 
void TMWDEFS_GLOBAL sdnpsa_addPreChallengeV1(
  SDNPSESN *pSDNPSession,
  TMWSESN_TX_DATA *pResponse)
{ 
  TMWTYPES_USHORT length;
  TMWTYPES_USHORT lengthIndex;
  SDNPAUTH_INFO *pAuthInfo = _getAuthInfo(pSDNPSession);

  if(pAuthInfo == TMWDEFS_NULL)
    return;

  if(pResponse->msgLength > pResponse->maxLength - SDNPAUTH_PRECHALLENGEPAD)
    return;

#if TMWCNFG_SUPPORT_DIAG
  pResponse->pMsgDescription = "Authentication Pre-Challenge of Application Confirm";
#endif
 
  pResponse->pMsgBuf[pResponse->msgLength++] = DNPDEFS_OBJ_120_AUTHENTICATION;
  pResponse->pMsgBuf[pResponse->msgLength++] = 1;
  pResponse->pMsgBuf[pResponse->msgLength++] = DNPDEFS_QUAL_16BIT_FREE_FORMAT;
  pResponse->pMsgBuf[pResponse->msgLength++] = 1;

  DNPDIAG_SHOW_TX_OBJECT_HDR((TMWSESN*)pSDNPSession, DNPDEFS_OBJ_120_AUTHENTICATION, 1, DNPDEFS_QUAL_16BIT_FREE_FORMAT);
  
  /* Save index for where to put 2 byte length */
  lengthIndex = pResponse->msgLength;
  pResponse->msgLength += 2;

  /* Add object data */
  pAuthInfo->challengeSequenceNumber++;

  tmwtarg_store32(&pAuthInfo->challengeSequenceNumber, pResponse->pMsgBuf + pResponse->msgLength);
  pResponse->msgLength += 4;

  /* 2 byte user number */
  pResponse->pMsgBuf[pResponse->msgLength++] = 0; /* Outstation always sends 0 for challenge */
  pResponse->pMsgBuf[pResponse->msgLength++] = 0; /* Outstation always sends 0 for challenge */ 

  pResponse->pMsgBuf[pResponse->msgLength++] = pAuthInfo->MACAlgorithm;
  pResponse->pMsgBuf[pResponse->msgLength++] = DNPAUTH_REASON_CRITICAL;

  /* Calculate how much room left in message */
  length = (pResponse->maxLength - pResponse->msgLength);
  if (length > DNPAUTH_MAX_CHALLENGE_DATA)
    length = DNPAUTH_MAX_CHALLENGE_DATA;

  if(!tmwcrypto_getRandomData(pSDNPSession->dnp.pCryptoHandle, pAuthInfo->randomChallengeDataLength,
    &pResponse->pMsgBuf[pResponse->msgLength], &length))
  {
    return;
  }

  DNPDIAG_SHOW_AUTH_CHALLENGE((TMWSESN*)pSDNPSession, 0, pAuthInfo->challengeSequenceNumber, pAuthInfo->MACAlgorithm, DNPAUTH_REASON_CRITICAL, 0);
  DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pSDNPSession, dataTypeGenChallData, &pResponse->pMsgBuf[pResponse->msgLength], length, 0);

  pResponse->msgLength = (TMWTYPES_USHORT)(pResponse->msgLength + length);
 
  /* Update the length in the object prefix. length of challenge data +8 */
  length = length +8;
  tmwtarg_store16(&length, pResponse->pMsgBuf + lengthIndex); 
  
  sdnpdata_authLogTx(pSDNPSession->pDbHandle, 1, 0, pAuthInfo->challengeSequenceNumber, pResponse->pMsgBuf, pResponse->msgLength);  

  /* Do not know what user we are challenging */
  pAuthInfo->currentUserNumber = 0;

  /* do not start reply timer, master will send application confirm with aggressive mode objects */ 
 
  /* Set flag so that this challenge will be saved in lastChallengeSent by beforeTxCallback */
  pResponse->txFlags |=  TMWSESN_TXFLAGS_DNP_AUTH_CHALL;
  
  _msgSent(pAuthInfo, 1, 0); 
   
  /* save it */
  if((pResponse->pMsgBuf[DNPDEFS_AH_INDEX_APPL_CTRL] & DNPDEFS_AC_UNSOLICITED) == DNPDEFS_AC_UNSOLICITED)
  {
    pAuthInfo->lastUnsolCSQSent = pAuthInfo->challengeSequenceNumber;
    /* Since master could have already sent a solicited aggressive mode
     * don't reset aggressiveModeRcvd till the confirm to this is received
     * Every solicited req before that will be using old CSQ plus number of aggressive reqs
     * Every solicited req after that will be using new CSQ plus number of aggressive reqs
     */
  }
  else
  {
    pAuthInfo->lastCSQSent = pAuthInfo->challengeSequenceNumber;
    /* When master gets this challenge it will start using this CSQ */
    pAuthInfo->aggressiveModeRcvd = 0;
  }
    
  /* This prechallenge makes the one challenge response unnecessary */
  pAuthInfo->rcvdAtLeastOneChallengeResponse = TMWDEFS_TRUE;
}  

/* function: _sendChallengeV1ReplyV2
 * purpose: send object group 120 v2 
 * arguments:   
 * returns:   
 */  
static void TMWDEFS_LOCAL _sendChallengeV1ReplyV2(
  SDNPSESN *pSDNPSession,
  TMWTYPES_ULONG rcvdChallengeSequenceNumber,
  TMWTYPES_USHORT userNumber,
  SDNPAUTH_RX_MSG *pRxFragment)
{ 
  TMWSESN_TX_DATA *pResponse;
  TMWTYPES_BOOL   status;
  TMWTYPES_USHORT length;
  TMWTYPES_USHORT lengthIndex; 
  DNPCHNL *pDNPChannel = (DNPCHNL *)pSDNPSession->dnp.tmw.pChannel;
  SDNPAUTH_INFO *pAuthInfo = _getAuthInfo(pSDNPSession);  
  SDNPAUTH_USER *pUserContext = _findUserContext(pAuthInfo, userNumber); 

  /* Protect against case where monitor key has not yet been received from master. */
  if (!pUserContext->monitorSessionKeyExists)
  {
    DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_KEYNOTOK);
    return;
  }

  pResponse = dnpchnl_newTxData((TMWCHNL *)pDNPChannel,
    (TMWSESN*)pSDNPSession, pDNPChannel->txFragmentSize, pRxFragment->rxAddress);

  if(pResponse == TMWDEFS_NULL)
  {
    return;
  } 

#if TMWCNFG_SUPPORT_DIAG
  pResponse->pMsgDescription = "Authentication Challenge Reply";
#endif

  _initializeResponse(pSDNPSession, pResponse, pAuthInfo->applSequenceNumber, DNPDEFS_FC_AUTH_RESPONSE);   
  
  pResponse->pMsgBuf[pResponse->msgLength++] = DNPDEFS_OBJ_120_AUTHENTICATION;
  pResponse->pMsgBuf[pResponse->msgLength++] = 2;
  pResponse->pMsgBuf[pResponse->msgLength++] = DNPDEFS_QUAL_16BIT_FREE_FORMAT;
  pResponse->pMsgBuf[pResponse->msgLength++] = 1;
  
  DNPDIAG_SHOW_TX_OBJECT_HDR((TMWSESN*)pSDNPSession, DNPDEFS_OBJ_120_AUTHENTICATION, 2, DNPDEFS_QUAL_16BIT_FREE_FORMAT);
   
  /* Save index for where to put 2 byte length */
  lengthIndex = pResponse->msgLength;
  pResponse->msgLength += 2;

  /* Add object data */ 
  tmwtarg_store32(&rcvdChallengeSequenceNumber, pResponse->pMsgBuf + pResponse->msgLength);
  pResponse->msgLength += 4;
 
  tmwtarg_store16(&userNumber, pResponse->pMsgBuf + pResponse->msgLength);
  pResponse->msgLength += 2;

  /* Calculate how much room left in message */
  length = (pResponse->maxLength - pResponse->msgLength);
    
#if TMWCNFG_SUPPORT_CRYPTO_AESGMAC
  /* If AES-GMAC set up init vector */
  if(pAuthInfo->MACAlgorithmRcvd == DNPAUTH_MAC_AESGMAC_12OCTET)
  { 
    /* 
     pSession->srcAddress;
     pUserContext->userNumber
     pAuthInfo->keyChangeSequenceNumber
     rcvdSequenceNumber
    */
    TMWTYPES_UCHAR *pInitVector = pAuthInfo->dataIfBuffer2;  
    TMWTYPES_USHORT vectorLength = 0;

    tmwtarg_store16(&pSDNPSession->dnp.tmw.srcAddress, &pInitVector[vectorLength]);
    vectorLength += 2;

    tmwtarg_store16(&pUserContext->userNumber, &pInitVector[vectorLength]);
    vectorLength += 2;
    
    tmwtarg_store32(&pAuthInfo->keyChangeSequenceNumber, &pInitVector[vectorLength]);
    vectorLength += 4;
    
    tmwtarg_store32(&rcvdChallengeSequenceNumber, &pInitVector[vectorLength]);
    vectorLength += 4;

    DNPDIAG_AUTH_INITVECTOR((TMWSESN*)pAuthInfo->pSession, pInitVector, vectorLength, 0); 

    tmwcrypto_setIVector(pSDNPSession->dnp.pCryptoHandle, &pUserContext->monitorSessionKey, pInitVector, vectorLength); 
  }
#endif

  /* MAC value based on challenge message received and last message sent */
  if(pAuthInfo->applSequenceNumber & DNPDEFS_AC_UNSOLICITED)
  {
    /* If this is AES-GMAC
     * IV contains link address, usernumber 0, lastKSQ, CSQ in this message.
     * key allows initvector to be specified! But I claimed library would not go into crypto_key!
     */
    status = _determineMACValue(pAuthInfo, TMWDEFS_FALSE,
      pAuthInfo->MACAlgorithmRcvd, &pUserContext->monitorSessionKey,
      pRxFragment->pMsgBuf, pRxFragment->msgLength,
#if DNPCNFG_MULTI_SESSION_REQUESTS
      pSDNPSession->lastUnsolTxFragment, pSDNPSession->lastUnsolTxFragmentLength,
#else
      pDNPChannel->lastUnsolTxFragment, pDNPChannel->lastUnsolTxFragmentLength,
#endif
      &pResponse->pMsgBuf[pResponse->msgLength], &length);
  }
  else
  {
    status = _determineMACValue(pAuthInfo, TMWDEFS_FALSE,
      pAuthInfo->MACAlgorithmRcvd, &pUserContext->monitorSessionKey,
      pRxFragment->pMsgBuf, pRxFragment->msgLength,
#if DNPCNFG_MULTI_SESSION_REQUESTS
      pSDNPSession->dnp.lastTxFragment, pSDNPSession->dnp.lastTxFragmentLength,
#else
      pDNPChannel->lastTxFragment, pDNPChannel->lastTxFragmentLength,
#endif
      &pResponse->pMsgBuf[pResponse->msgLength], &length);
  }
#if TMWCNFG_SUPPORT_CRYPTO_AESGMAC
  if(pAuthInfo->MACAlgorithmRcvd == DNPAUTH_MAC_AESGMAC_12OCTET)
    /* Set the init vector back to empty */
    tmwcrypto_setIVector(pSDNPSession->dnp.pCryptoHandle, &pUserContext->monitorSessionKey, TMWDEFS_NULL, 0);
#endif

  if(!status)
  {
    dnpchnl_freeTxData(pResponse);
    return;
  }

  DNPDIAG_SHOW_AUTH_REPLY((TMWSESN*)pSDNPSession, userNumber, rcvdChallengeSequenceNumber, TMWDEFS_TRUE, 0);
  /* MAC data is already displayed by _determineMACValue */

  pResponse->msgLength = (TMWTYPES_USHORT)(pResponse->msgLength + length);
 
  /* Update the length in the object prefix. length of MAC value data +6 */
  length = length +6;
  tmwtarg_store16(&length, pResponse->pMsgBuf + lengthIndex); 

  sdnpdata_authLogTx(pSDNPSession->pDbHandle, 2, userNumber, rcvdChallengeSequenceNumber, pResponse->pMsgBuf, pResponse->msgLength);
  
  /* Send reply to master*/ 
  if(!dnpchnl_sendFragment(pResponse))
  {
    dnpchnl_freeTxData(pResponse);
  }

  _msgSent(pAuthInfo, 2, userNumber); 
  return;
}
  
/* function: sdnpsa_addAggrModeStart
 * purpose: add aggressive mode object group 120 v3 to start of message
 * arguments:    
 * returns:   
 *  TMWDEFS_TRUE if successful
 */    
TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpsa_addAggrModeStart( 
  SDNPSESN *pSDNPSession,
  TMWSESN_TX_DATA *pResponse)
{ 
  SDNPAUTH_INFO *pAuthInfo = _getAuthInfo(pSDNPSession);   
  SDNPAUTH_USER *pUserContext = _findUserContext(pAuthInfo, DNPAUTH_DEFAULT_USERNUMBER);  
  
  /* if no such user or we have not received a challenge, 
   * we cannot send an aggressive mode request 
   */
  if((pUserContext == TMWDEFS_NULL)
    ||(pAuthInfo->lastChallengeRcvdLength == 0))
  {
    DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_AGGRTXFAIL);  
    /* Request will be sent without aggressive mode objects and may be challenged. */
    return TMWDEFS_TRUE;
  } 
   
  pResponse->pMsgBuf[pResponse->msgLength++] = DNPDEFS_OBJ_120_AUTHENTICATION;
  pResponse->pMsgBuf[pResponse->msgLength++] = 3;
  pResponse->pMsgBuf[pResponse->msgLength++] = DNPDEFS_QUAL_8BIT_LIMITED_QTY;
  pResponse->pMsgBuf[pResponse->msgLength++] = 1;
  
  DNPDIAG_SHOW_TX_OBJECT_HDR((TMWSESN*)pSDNPSession, DNPDEFS_OBJ_120_AUTHENTICATION, 3, DNPDEFS_QUAL_8BIT_LIMITED_QTY);
   
  /* This should be challengeSequenceNumber received in last challenge, + number of aggressive mode requests sent + 1(because of challenge reply)*/
  pAuthInfo->aggressiveModeTxSequence++;  
  
  /* Add object data */   
  tmwtarg_store32(&pAuthInfo->aggressiveModeTxSequence, pResponse->pMsgBuf + pResponse->msgLength);
  pResponse->msgLength += 4;
  
  tmwtarg_store16(&pUserContext->userNumber, pResponse->pMsgBuf + pResponse->msgLength);
  pResponse->msgLength += 2;

  _msgSent(pAuthInfo, 3, pUserContext->userNumber); 

  DNPDIAG_SHOW_AUTH_AGGRESSIVE((TMWSESN*)pSDNPSession, DNPAUTH_DEFAULT_USERNUMBER, pAuthInfo->aggressiveModeTxSequence, 0, TMWDEFS_TRUE, 0);
  sdnpdata_authLogTx(pSDNPSession->pDbHandle, 3, pUserContext->userNumber, pAuthInfo->aggressiveModeTxSequence, pResponse->pMsgBuf, pResponse->msgLength);  

  pResponse->txFlags |= TMWSESN_TXFLAGS_DNP_AUTH_AGGR;

  return(TMWDEFS_TRUE);
}    
 
/* function: sdnpsa_addAggrModeEnd
 * purpose: add aggressive mode object group 120 v9 to end of message
 * arguments:    
 * returns:   
 *  TMWDEFS_TRUE if successful
 */    
TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpsa_addAggrModeEnd( 
  SDNPSESN *pSDNPSession,
  TMWSESN_TX_DATA *pResponse)
{ 
  TMWTYPES_USHORT length;
  SDNPAUTH_USER *pUserContext;  
  SDNPAUTH_INFO *pAuthInfo = _getAuthInfo(pSDNPSession);
  DNPCHNL_TX_DATA *pDNPTxData = (DNPCHNL_TX_DATA*)pResponse;

  pUserContext = _findUserContext(pAuthInfo, DNPAUTH_DEFAULT_USERNUMBER);  
  if(pUserContext == TMWDEFS_NULL)
  {
    return TMWDEFS_FALSE;
  } 

  pResponse->pMsgBuf[pResponse->msgLength++] = DNPDEFS_OBJ_120_AUTHENTICATION;
  pResponse->pMsgBuf[pResponse->msgLength++] = 9;
  pResponse->pMsgBuf[pResponse->msgLength++] = DNPDEFS_QUAL_16BIT_FREE_FORMAT;
  pResponse->pMsgBuf[pResponse->msgLength++] = 1;

  DNPDIAG_SHOW_TX_OBJECT_HDR((TMWSESN*)pSDNPSession, DNPDEFS_OBJ_120_AUTHENTICATION, 9, DNPDEFS_QUAL_16BIT_FREE_FORMAT);
   
  length = _macLength(pAuthInfo->MACAlgorithmRcvd);
  tmwtarg_store16(&length, pResponse->pMsgBuf + pResponse->msgLength);
  pResponse->msgLength += 2;

  if(pResponse->txFlags & TMWSESN_TXFLAGS_STORE_DNP_DELAY)
  { 
    int i;
    /* If this is a write time request, do not bother to calculate hash value. 
     * Delay will be added right before transmitting and hash must be calculated then.
     */
    /* pad with 0x11s just for debugging */
    for(i=0; i<length;i++)
      pResponse->pMsgBuf[pResponse->msgLength+i]= 0x11;
  }
  else
  {

    /* MAC value based on last challenge message received, new key and this response so far, including the length field */
    if(!_determineAggrMACValue(pAuthInfo,  TMWDEFS_FALSE, 
      &pResponse->pMsgBuf[2], /*offset 2 into response, because of difference between request and response indexes */
      pAuthInfo->MACAlgorithmRcvd, &pUserContext->monitorSessionKey, 
      pAuthInfo->lastChallengeRcvd, pAuthInfo->lastChallengeRcvdLength,
      pResponse->pMsgBuf, pResponse->msgLength,
      &pResponse->pMsgBuf[pResponse->msgLength], &length))
    { 
      return TMWDEFS_FALSE;
    }
  }
    
  pResponse->msgLength = (TMWTYPES_USHORT)(pResponse->msgLength + length);

  /* Save this length for aggressive mode delay code */
  pDNPTxData->authAggrModeObjLength = (TMWTYPES_UCHAR)(length + 6);

  _msgSent(pAuthInfo, 9, DNPAUTH_DEFAULT_USERNUMBER); 

  _authSecStatIncrement(pSDNPSession, DNPAUTH_CRIT_MSG_SENT_INDEX);
  DNPDIAG_SHOW_AUTH_AGGRESSIVE((TMWSESN*)pSDNPSession, DNPAUTH_DEFAULT_USERNUMBER, pAuthInfo->aggressiveModeTxSequence, 0, TMWDEFS_TRUE, 0);
  return(TMWDEFS_TRUE);
}

/* function: sdnpsa_aggrDelay */
/* update time and recalculate hash value, then ask link layer to rechecksum request */
void TMWDEFS_GLOBAL sdnpsa_aggrDelay(
  TMWSESN_TX_DATA *pResponse,
  TMWTYPES_UCHAR *pDelayBuf)
{
  TMWTYPES_USHORT length;
  TMWTYPES_USHORT totalBytesToTx;
  TMWTYPES_USHORT offset;
  TMWTYPES_USHORT index;
  SDNPAUTH_USER *pUserContext;
  SDNPAUTH_INFO *pAuthInfo;
  DNPCHNL_TX_DATA *pDNPTxData;
  SDNPSESN *pSDNPSession;
  TMWPHYS_TX_DESCRIPTOR *pPhysTxDescriptor;
  TMWTYPES_UCHAR tempBuf[128];
  
  pSDNPSession = (SDNPSESN*)pResponse->pSession;
  pAuthInfo = _getAuthInfo(pSDNPSession);   
 
  pUserContext = _findUserContext(pAuthInfo, DNPAUTH_DEFAULT_USERNUMBER);
  if(pUserContext == TMWDEFS_NULL)
  {
    return;
  }

  pPhysTxDescriptor = &((DNPLINK_CONTEXT*)pResponse->pChannel->pLinkContext)->physTxDescriptor;

  /* copy delay into transmit buffer */
  memcpy(pPhysTxDescriptor->pTxBuffer + 31, pDelayBuf, 2);

  /* copy bytes from message without CRCs into temporary buffer to calculate the hash value */
  totalBytesToTx = pPhysTxDescriptor->numBytesToTx;
  offset = DNPDEFS_LINK_HDR_AND_CRC_SIZE;
  index = 0;
  while(offset < totalBytesToTx)
  {
    TMWTYPES_USHORT bytesLeft = (TMWTYPES_USHORT)(totalBytesToTx - offset);
    TMWTYPES_USHORT bytesToCopy = (TMWTYPES_USHORT)((bytesLeft>16) ? 16 : bytesLeft);
    memcpy(&tempBuf[index], pPhysTxDescriptor->pTxBuffer + offset, bytesToCopy);
    index = (TMWTYPES_USHORT)(index + bytesToCopy);
    offset += bytesToCopy+2;
  }

  pDNPTxData = (DNPCHNL_TX_DATA*)pResponse;
  length =  pDNPTxData->authAggrModeObjLength-6;
  
  /* MAC value based on last challenge message received, new key and this response so far, including the length field */
  if(!_determineAggrMACValue(pAuthInfo,  TMWDEFS_FALSE, 
    &pResponse->pMsgBuf[2], /*offset 2 into response, because of difference between request and response indexes */
    pAuthInfo->MACAlgorithmRcvd, &pUserContext->monitorSessionKey,
    pAuthInfo->lastChallengeRcvd, pAuthInfo->lastChallengeRcvdLength,
    &tempBuf[1], 26,
    &tempBuf[27], &length))
  { 
    return;
  }

  offset = DNPDEFS_LINK_HDR_AND_CRC_SIZE; 
  index = 0;
  while(offset < totalBytesToTx)
  {
    TMWTYPES_USHORT bytesLeft = (TMWTYPES_USHORT)(totalBytesToTx - offset);
    TMWTYPES_USHORT bytesToCopy = (TMWTYPES_USHORT)((bytesLeft>16) ? 16 : bytesLeft);

    memcpy(pPhysTxDescriptor->pTxBuffer + offset, &tempBuf[index], bytesToCopy);
    offset = (TMWTYPES_USHORT)(offset + bytesToCopy+2);
    index = (TMWTYPES_USHORT)(index + bytesToCopy);
  }

  dnplink_rechecksum(pPhysTxDescriptor);
}

/* function: _sendKeyStatusResponseV5
 * purpose: build and send key status response object group 120 v5 
 * arguments:   
 * returns:   
 */  
static void TMWDEFS_LOCAL _sendKeyStatusResponseV5(
  SDNPSESN *pSDNPSession,
  TMWTYPES_USHORT rxAddress,
  TMWTYPES_USHORT userNumber)
{
  TMWSESN_TX_DATA *pResponse;
  TMWTYPES_USHORT length;
  TMWTYPES_USHORT lengthIndex;
  TMWTYPES_USHORT challengeDataLength;
  TMWTYPES_USHORT challengeLengthIndex;
  TMWTYPES_USHORT macLength = 0;
  TMWTYPES_UCHAR macAlgorithm = 0;
  TMWSESN *pSession = (TMWSESN*)pSDNPSession;
  DNPCHNL *pDNPChannel = (DNPCHNL*)pSession->pChannel;
  SDNPAUTH_INFO *pAuthInfo = _getAuthInfo(pSDNPSession); 
  SDNPAUTH_USER *pUserContext = _findUserContext(pAuthInfo, userNumber);
  
  /* Even when there is no such user the key status should still be sent AUTH FAIL
   * 1815-2012 A.45.5.2.2 and TB 2016-002 3.1.2.3
   * Be careful of pUserContext==TMWDEFS_NULL below.
   */

  pResponse = dnpchnl_newTxData((TMWCHNL *)pDNPChannel,
    pSession, pDNPChannel->txFragmentSize, rxAddress);

  if(pResponse == TMWDEFS_NULL)
    return;

#if TMWCNFG_SUPPORT_DIAG
  pResponse->pMsgDescription = "Authentication Key Status";
#endif

  _initializeResponse(pSDNPSession, pResponse, pAuthInfo->applSequenceNumber, DNPDEFS_FC_AUTH_RESPONSE);
 
  pResponse->pMsgBuf[pResponse->msgLength++] = DNPDEFS_OBJ_120_AUTHENTICATION;
  pResponse->pMsgBuf[pResponse->msgLength++] = 5;
  pResponse->pMsgBuf[pResponse->msgLength++] = DNPDEFS_QUAL_16BIT_FREE_FORMAT;
  pResponse->pMsgBuf[pResponse->msgLength++] = 1;
  
  DNPDIAG_SHOW_TX_OBJECT_HDR((TMWSESN*)pSDNPSession, DNPDEFS_OBJ_120_AUTHENTICATION, 5, DNPDEFS_QUAL_16BIT_FREE_FORMAT);

  /* Save index for where to put 2 byte length */
  lengthIndex = pResponse->msgLength;
  pResponse->msgLength += 2;

  /* Add object data */ 
  tmwtarg_store32(&pAuthInfo->keyChangeSequenceNumber, pResponse->pMsgBuf + pResponse->msgLength);
  pResponse->msgLength += 4;
 
  tmwtarg_store16(&userNumber, pResponse->pMsgBuf + pResponse->msgLength);
  pResponse->msgLength += 2;

  if(pUserContext != TMWDEFS_NULL)
  {
    TMWCRYPTO_KEY tempKey;
    /* If user update key has expired this call will return failure. */
    if (!tmwcrypto_getKey(pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_USER_UPDATE_KEY, (void*)userNumber, &tempKey))
    {
      /* When user role/updatekey expires, delete this userNumber from SCL */
      sdnpsa_removeUser(pAuthInfo, userNumber);
      pUserContext = TMWDEFS_NULL;

      SDNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, SDNPDIAG_AUTH_USEREXPIRED);
    }
    else
    {
      /* Get this in case key and key size has been reconfigured */
      pUserContext->keyWrapAlgorithm = tmwcrypto_getAlgorithm(pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_USER_UPDATE_KEY, (void*)userNumber);
      pResponse->pMsgBuf[pResponse->msgLength++] = pUserContext->keyWrapAlgorithm;
      pResponse->pMsgBuf[pResponse->msgLength++] = pUserContext->keyStatus;

      /* Specify MAC algorithim used to calculate MAC value
       * In Version 5 use old key even if it is not OK
       */
      if (pUserContext->monitorSessionKeyExists)
      {
        macAlgorithm = pAuthInfo->MACAlgorithm;
      } 
      pResponse->pMsgBuf[pResponse->msgLength++] = macAlgorithm;
    }
  }

  if(pUserContext == TMWDEFS_NULL)
  {
    pResponse->pMsgBuf[pResponse->msgLength++] = TMWCRYPTO_ALG_KEYWRAP_AES256;
    pResponse->pMsgBuf[pResponse->msgLength++] = DNPAUTH_KEY_AUTHFAIL;
    pResponse->pMsgBuf[pResponse->msgLength++] = 0; /* MAC Algorithm */

    DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_BADUSER);
  }

  challengeLengthIndex = pResponse->msgLength;
  pResponse->msgLength += 2;

  /* Calculate how much room left in message */
  length = (pResponse->maxLength - pResponse->msgLength);
  if (length > DNPAUTH_MAX_CHALLENGE_DATA)
    length = DNPAUTH_MAX_CHALLENGE_DATA;

  if(!tmwcrypto_getRandomData(pSDNPSession->dnp.pCryptoHandle, pAuthInfo->randomChallengeDataLength,
    &pResponse->pMsgBuf[pResponse->msgLength], &challengeDataLength))
  {
    dnpchnl_freeTxData(pResponse);
    return;
  }

  pResponse->msgLength = (TMWTYPES_USHORT)(pResponse->msgLength + challengeDataLength);

  /* Store length of challenge data in the correct place */
  tmwtarg_store16(&challengeDataLength, pResponse->pMsgBuf + challengeLengthIndex);

  DNPDIAG_AUTH_SHOW_DATA(pSession, dataTypeGenChallData, &pResponse->pMsgBuf[challengeLengthIndex + 2], challengeDataLength, 0);

  /* Make sure user exists. */
  if(pUserContext != TMWDEFS_NULL)
  {
    /* Starting in version 3 and 4, even if keys are not valid, add mac using old monitor session key
     * When there is no old monitor session key, don't send the mac.
     */ 
    if (pUserContext->monitorSessionKeyExists)
    {
      macLength = (pResponse->maxLength - pResponse->msgLength);

      /* If AES-GMAC, set up init vector */
      if (pAuthInfo->MACAlgorithm == DNPAUTH_MAC_AESGMAC_12OCTET)
      {
#if TMWCNFG_SUPPORT_CRYPTO_AESGMAC
        /*
          pSession->srcAddress;
          userNumber
          pAuthInfo->keyChangeSequenceNumber
          last csq sent by master in v3 or by OS in v1 or zero
        */
        TMWTYPES_UCHAR *pInitVector = pAuthInfo->dataIfBuffer2;
        TMWTYPES_USHORT vectorLength = 0;

        tmwtarg_store16(&pSDNPSession->dnp.tmw.srcAddress, &pInitVector[vectorLength]);
        vectorLength += 2;

        tmwtarg_store16(&userNumber, &pInitVector[vectorLength]);
        vectorLength += 2;

        tmwtarg_store32(&pAuthInfo->keyChangeSequenceNumber, &pInitVector[vectorLength]);
        vectorLength += 4;

        /* Use last csq sent by master in g120v3 or by OS in g120v1 */
        tmwtarg_store32(&pAuthInfo->challengeSequenceNumber, &pInitVector[vectorLength]);
        vectorLength += 4;

        DNPDIAG_AUTH_INITVECTOR((TMWSESN*)pAuthInfo->pSession, pInitVector, vectorLength, 0);

        tmwcrypto_setIVector(pSDNPSession->dnp.pCryptoHandle, &pUserContext->monitorSessionKey, pInitVector, vectorLength);
#else
        DNPDIAG_ERROR(pAuthInfo->pSession->pChannel, pAuthInfo->pSession, DNPDIAG_AUTH_MACFAIL);
#endif
      }

      if(!_determineMACValue(pAuthInfo, TMWDEFS_FALSE, pAuthInfo->MACAlgorithm, &pUserContext->monitorSessionKey, pUserContext->lastKeyChange, 
        pUserContext->lastKeyChangeLength, TMWDEFS_NULL, 0, &pResponse->pMsgBuf[pResponse->msgLength], &macLength))
      {
        dnpchnl_freeTxData(pResponse);
        return;
      }

      pResponse->msgLength = (TMWTYPES_USHORT)(pResponse->msgLength + macLength); 
      length = length + macLength;
    } 
     
    DNPDIAG_SHOW_KEY_STATUS(pSession, userNumber, pAuthInfo->keyChangeSequenceNumber,
        pUserContext->keyWrapAlgorithm, pUserContext->keyStatus, macAlgorithm, 0);

#if TMWCNFG_SUPPORT_CRYPTO_AESGMAC
    if(pAuthInfo->MACAlgorithm == DNPAUTH_MAC_AESGMAC_12OCTET)
      /* Set the init vector back to empty */
      tmwcrypto_setIVector(pSDNPSession->dnp.pCryptoHandle, &pUserContext->monitorSessionKey, TMWDEFS_NULL, 0); 
#endif

    /* Update the length in the object prefix.  */
    length = pResponse->msgLength - (lengthIndex+2);
    tmwtarg_store16(&length, pResponse->pMsgBuf + lengthIndex);
   
    /* Save this key status message starting with KSQ, but not including MAC data */
    length = length - macLength;
    if(length <= SDNPAUTH_KEYSTATUSMAXSIZE)
    {
      memcpy(pUserContext->lastKeyStatus, &pResponse->pMsgBuf[lengthIndex+2], length);
      pUserContext->lastKeyStatusLength = length;
    }
    else
    {
      DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_TOO_BIG);
    }
  }
  else
  {
    /* Update the length in the object prefix.  */
    length = pResponse->msgLength - (lengthIndex+2);
    tmwtarg_store16(&length, pResponse->pMsgBuf + lengthIndex);
    DNPDIAG_SHOW_KEY_STATUS(pSession, userNumber, pAuthInfo->keyChangeSequenceNumber,
      TMWCRYPTO_ALG_KEYWRAP_AES256, DNPAUTH_KEY_AUTHFAIL, macAlgorithm, 0);
  }

  sdnpdata_authLogTx(pSDNPSession->pDbHandle, 5, userNumber, pAuthInfo->keyChangeSequenceNumber, pResponse->pMsgBuf, pResponse->msgLength);

  /* Send key status to master*/ 
  if(!dnpchnl_sendFragment(pResponse))
  {
    dnpchnl_freeTxData(pResponse);
  }
   
  _msgSent(pAuthInfo, 5, userNumber); 
}
  
/* function: sdnpsa_sendErrorResponseV7
 * purpose: build and send error message object group 120 v7
 * arguments:   
 * returns:   
 */  
void TMWDEFS_GLOBAL sdnpsa_sendErrorResponseV7(
  SDNPSESN *pSDNPSession,
  TMWTYPES_USHORT rxAddress,
  TMWTYPES_ULONG sequenceNumber,
  TMWTYPES_USHORT userNumber,
  TMWTYPES_UCHAR errorCode,
  TMWTYPES_CHAR *pErrorText,
  TMWTYPES_USHORT errorTextLength) 
{ 
  TMWSESN_TX_DATA *pResponse;
  TMWTYPES_USHORT length;
  TMWTYPES_USHORT lengthIndex; 
  TMWTYPES_MS_SINCE_70 msSince70;
  TMWDTIME timeStamp;
  TMWSESN *pSession = (TMWSESN*)pSDNPSession;
  DNPCHNL *pDNPChannel = (DNPCHNL*)pSession->pChannel;
  SDNPAUTH_INFO *pAuthInfo = _getAuthInfo(pSDNPSession); 

  /* Get the time now in case we need to log but NOT send the error response */
  sdnputil_getDateTime(pSession, &timeStamp);

  if ((pAuthInfo->statistic[DNPAUTH_ERROR_MSG_SENT_INDEX] + 1)
    > pAuthInfo->statsMaxValue[SDNPAUTH_ERROR_MSG_SENT_MAX_INDEX])
  {
    sdnpdata_authLogErrorTx(pSDNPSession->pDbHandle, userNumber, pAuthInfo->assocId, sequenceNumber, errorCode, &timeStamp, TMWDEFS_NULL, 0, TMWDEFS_FALSE);
    return;
  }

  _authSecStatIncrement(pSDNPSession, DNPAUTH_ERROR_MSG_SENT_INDEX);
 
  pResponse = dnpchnl_newTxData((TMWCHNL *)pDNPChannel,
    pSession, pDNPChannel->txFragmentSize, rxAddress);

  if(pResponse == TMWDEFS_NULL)
  {
    return;
  } 

#if TMWCNFG_SUPPORT_DIAG
  pResponse->pMsgDescription = "Authentication Error";
#endif

  _initializeResponse(pSDNPSession, pResponse, pAuthInfo->applSequenceNumber, DNPDEFS_FC_AUTH_RESPONSE);

  pResponse->pMsgBuf[pResponse->msgLength++] = DNPDEFS_OBJ_120_AUTHENTICATION;
  pResponse->pMsgBuf[pResponse->msgLength++] = 7;
  pResponse->pMsgBuf[pResponse->msgLength++] = DNPDEFS_QUAL_16BIT_FREE_FORMAT;
  pResponse->pMsgBuf[pResponse->msgLength++] = 1;
  
  DNPDIAG_SHOW_TX_OBJECT_HDR((TMWSESN*)pSDNPSession, DNPDEFS_OBJ_120_AUTHENTICATION, 7, DNPDEFS_QUAL_16BIT_FREE_FORMAT);

  /* Save index for where to put 2 byte length */
  lengthIndex = pResponse->msgLength;
  pResponse->msgLength += 2;
  
  /* Add object data */ 
  tmwtarg_store32(&sequenceNumber, pResponse->pMsgBuf + pResponse->msgLength);
  pResponse->msgLength += 4;

  /* User Number */
  tmwtarg_store16(&userNumber, pResponse->pMsgBuf + pResponse->msgLength);
  pResponse->msgLength += 2;  
  
  /* Association Id */
  tmwtarg_store16(&pAuthInfo->assocId, pResponse->pMsgBuf + pResponse->msgLength);
  pResponse->msgLength += 2;

  pResponse->pMsgBuf[pResponse->msgLength++] = errorCode;
  
  /* Write 48 bit event time */
  dnpdtime_dateTimeToMSSince70(&msSince70, &timeStamp);
  dnpdtime_writeMsSince70(&pResponse->pMsgBuf[pResponse->msgLength], &msSince70);
  pResponse->msgLength += 6;
  
  /* Optional error text in message */ 
  if(errorTextLength > 0)
  {
    memcpy(&pResponse->pMsgBuf[pResponse->msgLength], pErrorText, errorTextLength);
    pResponse->msgLength = (TMWTYPES_USHORT)pResponse->msgLength + errorTextLength;
  }

  /* Update the length in the object prefix. length of error data +15 */
  length = errorTextLength +15; 
  tmwtarg_store16(&length, pResponse->pMsgBuf + lengthIndex);

  sdnpdata_authLogErrorTx(pSDNPSession->pDbHandle, userNumber, pAuthInfo->assocId, sequenceNumber, errorCode, &timeStamp, pErrorText, errorTextLength, TMWDEFS_TRUE);
  DNPDIAG_SHOW_AUTH_ERROR((TMWSESN*)pSDNPSession, userNumber, pAuthInfo->assocId, sequenceNumber, errorCode, &timeStamp, pErrorText, errorTextLength, TMWDEFS_FALSE, 0);

  /* Send error message to master*/ 
  if(!dnpchnl_sendFragment(pResponse))
  {
    dnpchnl_freeTxData(pResponse);
  }

  _msgSent(pAuthInfo, 7, userNumber); 

  return;
}

#if DNPCNFG_SUPPORT_AUTHKEYUPDATE   
/* function: _sendNullResponse
 * purpose:  
 * arguments:   
 * returns:   
 */  
static void TMWDEFS_LOCAL _sendNullResponse(
  SDNPSESN *pSDNPSession,
  TMWTYPES_USHORT rxAddress)
{ 
  TMWSESN_TX_DATA *pResponse;
  DNPCHNL *pDNPChannel = (DNPCHNL *)pSDNPSession->dnp.tmw.pChannel;
  SDNPAUTH_INFO *pAuthInfo = _getAuthInfo(pSDNPSession);  

  pResponse = dnpchnl_newTxData((TMWCHNL *)pDNPChannel,
    (TMWSESN*)pSDNPSession, pDNPChannel->txFragmentSize, rxAddress);

  if(pResponse == TMWDEFS_NULL)
  {
    return;
  } 
#if TMWCNFG_SUPPORT_DIAG
  pResponse->pMsgDescription = "Authentication Null Response";
#endif

  _initializeResponse(pSDNPSession, pResponse, pAuthInfo->applSequenceNumber, DNPDEFS_FC_AUTH_RESPONSE);

  /* Send challenge to master*/ 
  if(!dnpchnl_sendFragment(pResponse))
  {
    dnpchnl_freeTxData(pResponse);
  }  
}  

#if DNPCNFG_SUPPORT_AUTHKEYUPDASYM
static TMWTYPES_BOOL TMWDEFS_LOCAL _isAsymmetric(
  TMWTYPES_UCHAR keyChangeMethod)
{
  /* For now just do this based on greater than 63 as the spec says 
   * In the future, we may need to call a database function for vendor specific choices 
   */
  if(keyChangeMethod>63)
    return TMWDEFS_TRUE;
  else
    return TMWDEFS_FALSE;
}
#endif

/* function: _sendUpdateKeyChangeReplyV12
 * purpose: build and send Update Key Change Reply message object group 120 v12
 * arguments:   
 * returns:   
 */  
static void TMWDEFS_LOCAL _sendUpdateKeyChangeReplyV12(
  SDNPSESN *pSDNPSession,
  TMWTYPES_USHORT rxAddress)
{ 
  TMWSESN_TX_DATA *pResponse;
  TMWTYPES_USHORT length;
  TMWTYPES_USHORT lengthIndex;  
  TMWTYPES_USHORT challengeLengthIndex;  
  TMWSESN *pSession = (TMWSESN*)pSDNPSession;
  DNPCHNL *pDNPChannel = (DNPCHNL*)pSession->pChannel;
  SDNPAUTH_INFO *pAuthInfo = _getAuthInfo(pSDNPSession); 
 
  pResponse = dnpchnl_newTxData((TMWCHNL *)pDNPChannel,
    pSession, pDNPChannel->txFragmentSize, rxAddress);

  if(pResponse == TMWDEFS_NULL)
  {
    return;
  } 

#if TMWCNFG_SUPPORT_DIAG
  pResponse->pMsgDescription = "Authentication Update Key Change Reply";
#endif

  _initializeResponse(pSDNPSession, pResponse, pAuthInfo->applSequenceNumber, DNPDEFS_FC_AUTH_RESPONSE);

  pResponse->pMsgBuf[pResponse->msgLength++] = DNPDEFS_OBJ_120_AUTHENTICATION;
  pResponse->pMsgBuf[pResponse->msgLength++] = 12;
  pResponse->pMsgBuf[pResponse->msgLength++] = DNPDEFS_QUAL_16BIT_FREE_FORMAT;
  pResponse->pMsgBuf[pResponse->msgLength++] = 1;
  
  DNPDIAG_SHOW_TX_OBJECT_HDR((TMWSESN*)pSDNPSession, DNPDEFS_OBJ_120_AUTHENTICATION, 12, DNPDEFS_QUAL_16BIT_FREE_FORMAT);

  /* Save index for where to put 2 byte length */
  lengthIndex = pResponse->msgLength;
  pResponse->msgLength += 2;
  
  /* Add object data */ 
  tmwtarg_store32(&pAuthInfo->keyChangeSequenceNumber, pResponse->pMsgBuf + pResponse->msgLength);
  pResponse->msgLength += 4;

  /* User Number */
  tmwtarg_store16(&pAuthInfo->currentUserNumber, pResponse->pMsgBuf + pResponse->msgLength);
  pResponse->msgLength += 2;  

  /* challenge data length goes here */ 
  challengeLengthIndex = pResponse->msgLength; 
  pResponse->msgLength += 2;  

  /* Calculate how much room left in message for challenge data */
  length = (pResponse->maxLength - pResponse->msgLength);
  if (length > DNPAUTH_MAX_CHALLENGE_DATA)
    length = DNPAUTH_MAX_CHALLENGE_DATA;

  if(!tmwcrypto_getRandomData(pSDNPSession->dnp.pCryptoHandle, dnpauth_methodChallengeLength(pAuthInfo->keyChangeMethod),
    &pResponse->pMsgBuf[pResponse->msgLength], &length))
   {
    dnpchnl_freeTxData(pResponse); 
    return;
  }
  
  /* save challenge data sent to master */
  memcpy(pAuthInfo->outstationChallengeData, &pResponse->pMsgBuf[pResponse->msgLength], length);
  pAuthInfo->outstationChallengeDataLength = length;

  /* Store the challenge data length */
  tmwtarg_store16(&length, pResponse->pMsgBuf + challengeLengthIndex);
  pResponse->msgLength = (TMWTYPES_USHORT)(pResponse->msgLength + length);

  /* Update the length in the object prefix. */
  length = pResponse->msgLength - (lengthIndex+2); 
  tmwtarg_store16(&length, pResponse->pMsgBuf + lengthIndex);

  DNPDIAG_SHOW_AUTH_UPDATEKEYCHGRPLY((TMWSESN*)pSDNPSession, pAuthInfo->currentUserNumber, pAuthInfo->keyChangeSequenceNumber, 
    pAuthInfo->outstationChallengeData, pAuthInfo->outstationChallengeDataLength, 0);

  sdnpdata_authLogTx(pSDNPSession->pDbHandle, 12, pAuthInfo->currentUserNumber, pAuthInfo->keyChangeSequenceNumber, pResponse->pMsgBuf, pResponse->msgLength);  

  /* Send message to master*/ 
  if(!dnpchnl_sendFragment(pResponse))
  {
    dnpchnl_freeTxData(pResponse);
  }

  return;
}

/* function: _sendUpdateKeyChangeConfV15
 * purpose: build and send Update Key Change Confirmation message object group 120 v15
 * arguments:   
 * returns:   
 */  
static void TMWDEFS_LOCAL _sendUpdateKeyChangeConfV15(
  SDNPSESN *pSDNPSession,
  TMWTYPES_USHORT rxAddress)
{ 
  TMWSESN_TX_DATA *pResponse;
  TMWTYPES_USHORT length;
  TMWTYPES_USHORT lengthIndex; 
  TMWTYPES_USHORT plainDataLength;
  TMWCRYPTO_KEY updateKey;
  TMWSESN *pSession = (TMWSESN*)pSDNPSession;
  DNPCHNL *pDNPChannel = (DNPCHNL*)pSession->pChannel;
  SDNPAUTH_INFO *pAuthInfo = _getAuthInfo(pSDNPSession); 
  TMWTYPES_UCHAR *pPlainData = pAuthInfo->dataIfBuffer;

  pResponse = dnpchnl_newTxData((TMWCHNL *)pDNPChannel,
    pSession, pDNPChannel->txFragmentSize, rxAddress);

  if(pResponse == TMWDEFS_NULL)
  {
    return;
  } 

#if TMWCNFG_SUPPORT_DIAG
  pResponse->pMsgDescription = "Authentication Update Key Change Confirm";
#endif

  _initializeResponse(pSDNPSession, pResponse, pAuthInfo->applSequenceNumber, DNPDEFS_FC_AUTH_RESPONSE);

  pResponse->pMsgBuf[pResponse->msgLength++] = DNPDEFS_OBJ_120_AUTHENTICATION;
  pResponse->pMsgBuf[pResponse->msgLength++] = 15;
  pResponse->pMsgBuf[pResponse->msgLength++] = DNPDEFS_QUAL_16BIT_FREE_FORMAT;
  pResponse->pMsgBuf[pResponse->msgLength++] = 1;
  
  DNPDIAG_SHOW_TX_OBJECT_HDR((TMWSESN*)pSDNPSession, DNPDEFS_OBJ_120_AUTHENTICATION, 15, DNPDEFS_QUAL_16BIT_FREE_FORMAT);

  /* Save index for where to put 2 byte length */
  lengthIndex = pResponse->msgLength;
  pResponse->msgLength += 2;
  
  length = SDNPAUTH_BUFFERSIZE; 
  if(TMWDEFS_FALSE == sdnpdata_authGetUserName(pSDNPSession->pDbHandle, pAuthInfo->currentUserNumber, (TMWTYPES_CHAR *)pPlainData, &length))
  {
    DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_FINDUSERNAME); 
    dnpchnl_freeTxData(pResponse); 
    return;
  }

  /* outstation challenge data was saved when v12 was sent */ 
  memcpy((pPlainData+length), pAuthInfo->outstationChallengeData, pAuthInfo->outstationChallengeDataLength); 
  plainDataLength = length + pAuthInfo->outstationChallengeDataLength;

  /* master challenge data was saved when v11 was received. */ 
  memcpy((pPlainData+plainDataLength), pAuthInfo->masterChallengeData, pAuthInfo->masterChallengeDataLength);
  plainDataLength += pAuthInfo->masterChallengeDataLength;

  tmwtarg_store32(&pAuthInfo->keyChangeSequenceNumber, (pPlainData+plainDataLength));
  plainDataLength += 4;

  tmwtarg_store16(&pAuthInfo->currentUserNumber, (pPlainData+plainDataLength));
  plainDataLength += 2;

  /* encrypt them */
  length = (TMWTYPES_USHORT)(pResponse->msgLength - (pResponse->msgLength+2));

  if(_getKey(pSession, pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_USER_UPDATE_KEY, (void*)pAuthInfo->currentUserNumber, &updateKey))
  { 
    TMWTYPES_BOOL status = TMWDEFS_FALSE;

    if(dnpauth_methodChallengeLength(pAuthInfo->keyChangeMethod) <= length)
    {

#if TMWCNFG_SUPPORT_CRYPTO_AESGMAC
      /* If AES-GMAC set up init vector */
      if(dnpauth_methodToTMWMacAlgo(pAuthInfo->keyChangeMethod) == TMWCRYPTO_ALG_MAC_AESGMAC)
      { 
        /* 
         pSDNPSession->srcAddress 
         pAuthInfo->currentUserNumber
         pAuthInfo->keyChangeSequenceNumber 
         last csq sent by master in v3 or by OS in v1 or zero
        */   
        TMWTYPES_UCHAR *pInitVector = pAuthInfo->dataIfBuffer2;  
        TMWTYPES_USHORT vectorLength = 0;  

        tmwtarg_store16(&pSDNPSession->dnp.tmw.srcAddress, &pInitVector[vectorLength]);
        vectorLength += 2;

        tmwtarg_store16(&pAuthInfo->currentUserNumber, &pInitVector[vectorLength]);
        vectorLength += 2;
        
        tmwtarg_store32(&pAuthInfo->keyChangeSequenceNumber, &pInitVector[vectorLength]);
        vectorLength += 4;
          
        tmwtarg_store32(&pAuthInfo->challengeSequenceNumber, &pInitVector[vectorLength]);
        vectorLength += 4;
 
        DNPDIAG_AUTH_INITVECTOR((TMWSESN*)pAuthInfo->pSession, pInitVector, vectorLength, 0); 

        tmwcrypto_setIVector(pSDNPSession->dnp.pCryptoHandle, &updateKey, pInitVector, vectorLength); 
      }
#endif

      status = tmwcrypto_MACValue(pSDNPSession->dnp.pCryptoHandle, dnpauth_methodToTMWMacAlgo(pAuthInfo->keyChangeMethod),
        &updateKey, dnpauth_methodChallengeLength(pAuthInfo->keyChangeMethod),
        pPlainData, (TMWTYPES_USHORT)plainDataLength, 
        &pResponse->pMsgBuf[pResponse->msgLength], &length);

      DNPDIAG_AUTH_SHOW_DATA(pSession, dataTypePlainData, pPlainData, plainDataLength, 0);
      DNPDIAG_AUTH_SHOW_DATA(pSession, dataTypeGenMAC, &pResponse->pMsgBuf[pResponse->msgLength], length, 0);
    }

#if TMWCNFG_SUPPORT_CRYPTO_AESGMAC
    if(dnpauth_methodToTMWMacAlgo(pAuthInfo->keyChangeMethod) == TMWCRYPTO_ALG_MAC_AESGMAC)
      /* Set the init vector back to empty */
      tmwcrypto_setIVector(pSDNPSession->dnp.pCryptoHandle, &updateKey, TMWDEFS_NULL, 0); 
#endif

    if(!status)
    {
      DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_UPDATE_FAILED);
      dnpchnl_freeTxData(pResponse);
      return;
    }
 
    pResponse->msgLength += length;
 
    /* Update the length in the object prefix. */
    length = pResponse->msgLength - (lengthIndex +2); 
    tmwtarg_store16(&length, pResponse->pMsgBuf + lengthIndex);
 
    DNPDIAG_SHOW_AUTH_UPDATEKEYCHGCONF(pSession, pAuthInfo->currentUserNumber, 0, 0);
    sdnpdata_authLogTx(pSDNPSession->pDbHandle, 15, pAuthInfo->currentUserNumber, 0, pResponse->pMsgBuf, pResponse->msgLength);

    /* Send message to master*/ 
    if(!dnpchnl_sendFragment(pResponse))
    {
      dnpchnl_freeTxData(pResponse);
    }
  }
  return;
}
#endif

/* function: _parseApplHeader
 * purpose: 
 * arguments:   
 * returns:   
 */  
static void TMWDEFS_LOCAL _parseApplHeader(
  TMWSESN_RX_DATA *pRxFragment,
  SDNPAUTH_RX_MSG *pMsg)
{
  /* Initialize message pointers */
  pMsg->pMsgBuf = pRxFragment->pMsgBuf;

  pMsg->msgLength = pRxFragment->msgLength;
  pMsg->offset = 0;

  pMsg->rxAddress = pRxFragment->rxAddress;

  /* Read application control byte */
  pMsg->ac = pMsg->pMsgBuf[pMsg->offset++];

  /* Read function code */
  pMsg->fc = pMsg->pMsgBuf[pMsg->offset++];
}

/* function: _parseObjectHeader */
static TMWTYPES_BOOL TMWDEFS_LOCAL _parseObjectHeader(
  SDNPAUTH_RX_MSG *pMsg,
  DNPAUTH_OBJECT_HEADER *pHdr)
{
  TMWTYPES_ULONG offset = pMsg->offset;

  /* Protect against badly formatted message */
  if(!_validateMsgLength(TMWDEFS_NULL, pMsg, 3))
  {
    return(TMWDEFS_FALSE);
  }
 
  pHdr->group     = pMsg->pMsgBuf[offset++];
  pHdr->variation = pMsg->pMsgBuf[offset++];
  pHdr->qualifier = pMsg->pMsgBuf[offset++];

  /* Skip quantity for these qualifiers. */
  if((pHdr->qualifier == DNPDEFS_QUAL_8BIT_LIMITED_QTY)
    ||(pHdr->qualifier == DNPDEFS_QUAL_16BIT_FREE_FORMAT))
  {
    /* Protect against badly formatted message */
    if(!_validateMsgLength(TMWDEFS_NULL, pMsg, 1))
    {
      return(TMWDEFS_FALSE);
    }
    offset++;
  } 
  
  pMsg->offset = offset;
  return(TMWDEFS_TRUE);
}

/* function: _processChallengeRequestV1 */
/* process reception of object group 120 v1 */
static TMWTYPES_BOOL TMWDEFS_LOCAL _processChallengeRequestV1(
  SDNPSESN *pSDNPSession,
  SDNPAUTH_RX_MSG *pRxFragment,
  SDNPAUTH_USER *pUserContext)
{
  TMWTYPES_ULONG sequenceNumber;
  TMWTYPES_USHORT bytesInObject;
  TMWTYPES_USHORT userNumber; 
  TMWTYPES_UCHAR macAlgorithm; 
  TMWTYPES_UCHAR reasonForChallenge; 
  SDNPAUTH_INFO *pAuthInfo = _getAuthInfo(pSDNPSession);

  /* Protect against badly formatted message */
  if(!_validateMsgLength((TMWSESN*)pSDNPSession, pRxFragment, 10))
  {
    return(TMWDEFS_FALSE);
  }
 
  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &bytesInObject);
  pRxFragment->offset += 2;

  tmwtarg_get32(&pRxFragment->pMsgBuf[pRxFragment->offset], &sequenceNumber);
  pRxFragment->offset += 4;
 
  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &userNumber);
  pRxFragment->offset += 2;

  macAlgorithm = pRxFragment->pMsgBuf[pRxFragment->offset++]; 
  reasonForChallenge = pRxFragment->pMsgBuf[pRxFragment->offset++]; 
  
  /* Get Challenge Data Length */  
  bytesInObject = bytesInObject - 8;
  DNPDIAG_SHOW_AUTH_CHALLENGE((TMWSESN*)pSDNPSession, 0, pAuthInfo->challengeSequenceNumber, pAuthInfo->MACAlgorithm, DNPAUTH_REASON_CRITICAL, TMWDIAG_ID_RX);
  DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pSDNPSession, dataTypeRcvdChallData, &pRxFragment->pMsgBuf[pRxFragment->offset], bytesInObject, TMWDIAG_ID_RX);

  /* Move past Challenge Data in message */
  pRxFragment->offset = pRxFragment->offset + bytesInObject;
   
  /* Challenges (and aggressive mode responses) indicate critical messages sent */
  _authSecStatIncrement(pSDNPSession, DNPAUTH_CRIT_MSG_SENT_INDEX);

  sdnpdata_authLogRx(pSDNPSession->pDbHandle, 1, userNumber, sequenceNumber, pRxFragment->pMsgBuf, pRxFragment->msgLength);  

  if (pUserContext == TMWDEFS_NULL)
  {
    DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_BADUSER);
    sdnpsa_sendErrorResponseV7(pSDNPSession, pRxFragment->rxAddress, sequenceNumber, userNumber, DNPAUTH_ERROR_UNKNOWN_USER, TMWDEFS_NULL, 0);
    return(TMWDEFS_FALSE);
  }

  /* Protect against badly formatted message */
  if(!_validateMsgLength((TMWSESN*)pSDNPSession, pRxFragment, 0))
  {
    return(TMWDEFS_FALSE);
  }

#ifdef TMW_SUPPORT_MONITOR
  if(pSDNPSession->dnp.tmw.pChannel->pPhysContext->monitorMode)
    return(TMWDEFS_TRUE);
#endif

  /* Spec requires configuration to disallow use of SHA1 */
  if((pAuthInfo->disallowSHA1 &&
     (dnpauth_MACtoTMWCryptoAlgo(macAlgorithm) == TMWCRYPTO_ALG_MAC_SHA1))
     ||(!tmwcrypto_algorithmSupport(pSDNPSession->dnp.pCryptoHandle, dnpauth_MACtoTMWCryptoAlgo(macAlgorithm)))) 
  {
    DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_MACSUPPORT);  
    sdnpsa_sendErrorResponseV7(pSDNPSession, pRxFragment->rxAddress, sequenceNumber, userNumber, DNPAUTH_ERROR_MACNOTPERMIT, TMWDEFS_NULL, 0);  
    return(TMWDEFS_FALSE);
  }  
  
  if (bytesInObject < 4 || bytesInObject > 64)
  {
    /* TMW 1815 does not say this, but DNP SA Conformance tests expect this */
    DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_BADCLENGTH);
    sdnpsa_sendErrorResponseV7(pSDNPSession, pRxFragment->rxAddress, sequenceNumber, userNumber, DNPAUTH_ERROR_AUTHENTFAILED, TMWDEFS_NULL, 0);
    return(TMWDEFS_FALSE);
  }

  if (pRxFragment->msgLength <= SDNPAUTH_RXCHALLENGEMAXSIZE)
  {
    memcpy(pAuthInfo->lastChallengeRcvd, pRxFragment->pMsgBuf, pRxFragment->msgLength);
    pAuthInfo->lastChallengeRcvdLength = pRxFragment->msgLength;
  }
  else
  {
    DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_TOO_BIG);
    sdnpsa_sendErrorResponseV7(pSDNPSession, pRxFragment->rxAddress, sequenceNumber, userNumber, DNPAUTH_ERROR_AUTHENTFAILED, TMWDEFS_NULL, 0);
    return(TMWDEFS_FALSE);
  } 
  
  if (sequenceNumber != (pAuthInfo->aggressiveModeTxSequence + 1))
  {
    /* TMW 1815 does not say this, but DNP SA Conformance tests expect this */
    _authSecStatIncrement(pSDNPSession, DNPAUTH_UNEXPECTED_MSG_INDEX);
  }

  pAuthInfo->aggressiveModeTxSequence = sequenceNumber;
  pAuthInfo->MACAlgorithmRcvd = macAlgorithm;
  
  _sendChallengeV1ReplyV2(pSDNPSession, sequenceNumber, userNumber, pRxFragment); 
   
  return(TMWDEFS_TRUE);
}  

/* function: _processChallengeReplyV2 */
/* process reception of object group 120 v2 */
static TMWTYPES_BOOL TMWDEFS_LOCAL _processChallengeReplyV2(
  SDNPSESN *pSDNPSession,
  SDNPAUTH_RX_MSG *pRxFragment,
  SDNPAUTH_USER *pUserContext)
{
  TMWTYPES_BOOL monitorMode;
  TMWTYPES_BOOL status; 
  TMWTYPES_USHORT userNumber;
  TMWTYPES_ULONG sequenceNumber;
  TMWTYPES_USHORT bytesInObject;

  /* Protect against badly formatted message */
  if(!_validateMsgLength((TMWSESN*)pSDNPSession, pRxFragment, 8))
  {
    return(TMWDEFS_FALSE);
  }

  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &bytesInObject);
  pRxFragment->offset += 2;

  tmwtarg_get32(&pRxFragment->pMsgBuf[pRxFragment->offset], &sequenceNumber);
  pRxFragment->offset += 4;

  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &userNumber);
  pRxFragment->offset += 2;

  /* Get MAC value from message */  
  bytesInObject = bytesInObject - 6;

  status = TMWDEFS_TRUE;
  monitorMode = TMWDEFS_FALSE;
  
#ifdef TMW_SUPPORT_MONITOR
  monitorMode = pSDNPSession->dnp.tmw.pChannel->pPhysContext->monitorMode;
#endif

  /* Protect against badly formatted message */
  if(!_validateMsgLength((TMWSESN*)pSDNPSession, pRxFragment, bytesInObject))
  {
    return(TMWDEFS_FALSE);
  }

  DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pSDNPSession, dataTypeRcvdMAC, &pRxFragment->pMsgBuf[pRxFragment->offset], bytesInObject, TMWDIAG_ID_RX);

  if(!monitorMode)
  {
    if(pUserContext != TMWDEFS_NULL)
    {
      /* When the challenge was sent the user number was 0, so this message could not be counted, count it now */
      pUserContext->keyChangeCount++;
      status = _validateChallengeReply(pSDNPSession, pUserContext, &pRxFragment->pMsgBuf[pRxFragment->offset], 
        bytesInObject, sequenceNumber);
    }
    else
    {
      status = TMWDEFS_FALSE;
    }
  }

  DNPDIAG_SHOW_AUTH_REPLY((TMWSESN*)pSDNPSession, userNumber, sequenceNumber, status, TMWDIAG_ID_RX);

  pRxFragment->offset = pRxFragment->offset + bytesInObject;

  sdnpdata_authLogRx(pSDNPSession->pDbHandle, 2, userNumber, sequenceNumber, pRxFragment->pMsgBuf, pRxFragment->msgLength);  

  return status;
}  


#ifdef TMW_SUPPORT_MONITOR 
static void TMWDEFS_LOCAL _monitorRemoveAggrEnd(
  SDNPSESN        *pSDNPSession,
  SDNPAUTH_RX_MSG *pRxFragment,
  TMWTYPES_USHORT  userNumber, 
  TMWTYPES_ULONG   sequenceNumber)
{
  int i;
  TMWTYPES_ULONG savedRxOffset;

  /* Since we don't know the mac algorithm being used, try all we know of */
  TMWTYPES_UCHAR aggrModeMACLength[5] = {4, 8, 10, 12, 16};

  for(i=0; i<5; i++)
  {
    DNPAUTH_OBJECT_HEADER hdr;

    /* Protect against badly formatted message */
    if(!_validateMsgLength((TMWSESN*)pSDNPSession, pRxFragment, (6 + aggrModeMACLength[i])))
    {
      return;
    }

    savedRxOffset = pRxFragment->offset;
    pRxFragment->offset = pRxFragment->msgLength - (6 + aggrModeMACLength[i]);
    if(!_parseObjectHeader(pRxFragment, &hdr))
      return;

    if((hdr.group == 120) && (hdr.variation == 9))
    {   
      /* remove aggressivemode object from message, so rest of stack does not need to parse it */
      pRxFragment->msgLength -= (6+aggrModeMACLength[i]);
 
      DNPDIAG_SHOW_AUTH_HEADER((TMWSESN*)pSDNPSession, &hdr);
      DNPDIAG_SHOW_AUTH_AGGRESSIVE((TMWSESN*)pSDNPSession, userNumber, sequenceNumber, 0,
        1, TMWDIAG_ID_RX);
  
      sdnpdata_authLogRx(pSDNPSession->pDbHandle, 9, userNumber, sequenceNumber, pRxFragment->pMsgBuf, pRxFragment->msgLength); 
      return;
    }  
    pRxFragment->offset = savedRxOffset;
  }
  return;
}
#endif

/* function: _processAggrModeRequestV3 */
/* process reception of object group 120 v3 */
static TMWTYPES_BOOL TMWDEFS_LOCAL _processAggrModeRequestV3(
  SDNPSESN *pSDNPSession,
  SDNPAUTH_RX_MSG *pRxFragment,
  SDNPAUTH_USER *pUserContext)
{    
  TMWTYPES_USHORT aggrModeMACLength; 
  TMWTYPES_USHORT length; 
  TMWTYPES_BOOL status;
  TMWTYPES_ULONG sequenceNumber;
  TMWTYPES_USHORT userNumber;
  DNPAUTH_OBJECT_HEADER hdr;
  SDNPAUTH_INFO *pAuthInfo = _getAuthInfo(pSDNPSession);
 
  /* Protect against badly formatted message */
  if(!_validateMsgLength((TMWSESN*)pSDNPSession, pRxFragment, 6))
  { 
    return(TMWDEFS_FALSE);
  }

  status = TMWDEFS_FALSE;

  /* Even invalid Aggressive Mode request should be considered critical 1815 Table 7-6 Index 8 
   * Also several DNP SA conformance tests expect it
   */
  _authSecStatIncrement(pSDNPSession, DNPAUTH_CRIT_MSG_RCVD_INDEX);
  
  tmwtarg_get32(&pRxFragment->pMsgBuf[pRxFragment->offset], &sequenceNumber);
  pRxFragment->offset += 4;

  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &userNumber);
  pRxFragment->offset += 2; 

#ifdef TMW_SUPPORT_MONITOR
  if(pSDNPSession->dnp.tmw.pChannel->pPhysContext->monitorMode) 
  { 
    DNPDIAG_SHOW_AUTH_AGGRESSIVE((TMWSESN*)pSDNPSession, userNumber, sequenceNumber, 0, TMWDEFS_TRUE, TMWDIAG_ID_RX);
    _monitorRemoveAggrEnd(pSDNPSession, pRxFragment, userNumber, sequenceNumber);
    return(TMWDEFS_TRUE);
  }
#endif

#if TMWCNFG_SUPPORT_DIAG
  if(!pAuthInfo->rcvdAtLeastOneChallengeResponse)
  {
    DNPDIAG_ERROR(pAuthInfo->pSession->pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_AGGRNOCHALL);
    return(TMWDEFS_FALSE);
  }
#endif

  /* length of MAC data to be used was specified in last challenge sent to master,
   * so it is possible to start at the end of the message to look for an aggressive
   * mode object 
   */ 
  aggrModeMACLength = dnpauth_MACtoLength(pAuthInfo->MACAlgorithm);
  
  /* Protect against badly formatted message */
  if(!_validateMsgLength((TMWSESN*)pSDNPSession, pRxFragment, (6 + aggrModeMACLength)))
  { 
    return(TMWDEFS_FALSE);
  }

  pRxFragment->offset = pRxFragment->msgLength - (6 + aggrModeMACLength); 
  if(!_parseObjectHeader(pRxFragment, &hdr))
    return(TMWDEFS_FALSE);

  if((hdr.group == 120) && (hdr.variation == 9))
  {  
    TMWTYPES_ULONG expectedSequenceNumber;

    /* verify sequence number 
     * For aggressive mode reply to prechallenge it uses CSQ from challenge.
     * Other aggressive mode requests must increment CSQ to prevent the replay of an old request
     * (till a new challenge is sent by OS).
     */
    if((pRxFragment->ac & DNPDEFS_AC_UNSOLICITED) != 0) 
    {  
      /* Master would have seen this new CSQ by now */
      pAuthInfo->aggressiveModeRcvd = 0;

      if(pAuthInfo->lastCSQSent < pAuthInfo->lastUnsolCSQSent)
        pAuthInfo->lastCSQSent = pAuthInfo->lastUnsolCSQSent;

      expectedSequenceNumber = pAuthInfo->lastUnsolCSQSent;
    }
    else
    {
      expectedSequenceNumber = pAuthInfo->lastCSQSent;
      if(pRxFragment->fc != DNPDEFS_FC_CONFIRM)
      {
        expectedSequenceNumber += (pAuthInfo->aggressiveModeRcvd+1);
      }
    }
    
    tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &length);
    pRxFragment->offset = pRxFragment->offset+2;

    DNPDIAG_SHOW_AUTH_HEADER((TMWSESN*)pSDNPSession, &hdr);
    
    status = _validateAggressiveMode(pAuthInfo, pUserContext, sequenceNumber, expectedSequenceNumber, pRxFragment, length);
    if(status)
    { 
      /* If valid, set CSQ to the sequence received in aggressive mode request, unless already greater than that
       * handle the wrap back to zero case also
       */
      if((sequenceNumber > pAuthInfo->challengeSequenceNumber)
        ||((pAuthInfo->challengeSequenceNumber > 0xfffffff0) && (sequenceNumber <16)))
      {
        pAuthInfo->challengeSequenceNumber = sequenceNumber; 
      }

      if(pRxFragment->fc != DNPDEFS_FC_CONFIRM)
        pAuthInfo->aggressiveModeRcvd++;
   
      /* remove aggressivemode object from message, so rest of stack does not need to parse it */
      pRxFragment->msgLength -= (6 + aggrModeMACLength);
    }
    else
    {
      DNPDIAG_ERROR(pAuthInfo->pSession->pChannel, pAuthInfo->pSession, DNPDIAG_AUTH_AGGRRXFAIL);
    }

    DNPDIAG_SHOW_AUTH_AGGRESSIVE((TMWSESN*)pSDNPSession, userNumber, sequenceNumber, expectedSequenceNumber,
     status, TMWDIAG_ID_RX);
     
    sdnpdata_authLogRx(pSDNPSession->pDbHandle, 9, userNumber, sequenceNumber, pRxFragment->pMsgBuf, pRxFragment->msgLength); 
  }  
  return status;
}
 
/* function: _processKeyStatusRequestV4 */
/* process reception of object group 120 v4 */
static void TMWDEFS_LOCAL _processKeyStatusRequestV4(
  SDNPSESN *pSDNPSession,
  SDNPAUTH_RX_MSG *pRxFragment,
  SDNPAUTH_USER *pUserContext)
{   
  TMWTYPES_USHORT userNumber;
  SDNPAUTH_INFO *pAuthInfo = _getAuthInfo(pSDNPSession);

  /* Protect against badly formatted message */
  if(pRxFragment->msgLength < 8)
  { 
    DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_INVALID_SIZE); 
    return;
  }

  /* [6] is start of user number */ 
  tmwtarg_get16(&pRxFragment->pMsgBuf[6], &userNumber);
  /* we incremented offset in earlier processing */
 
  sdnpdata_authLogRx(pSDNPSession->pDbHandle, 4, userNumber, 0, pRxFragment->pMsgBuf, pRxFragment->msgLength); 

#ifdef TMW_SUPPORT_MONITOR
  if(pSDNPSession->dnp.tmw.pChannel->pPhysContext->monitorMode) 
  {
    return;
  }
#endif 

  /* SAv5 (1815-2012) 7.6.1.4.6 says send g120v7 code 12 Security Statistic Exceeded if more than
   * configured number status requests are received within Expected Session Key Change Interval
   * this is per user.
   */
  if(pUserContext != TMWDEFS_NULL)
  {
    if(++pUserContext->sessionKeyStatusCount > pAuthInfo->maxSessionKeyStatusCount)
    {
      sdnpdata_authSesnKeyStatCount(pSDNPSession->pDbHandle, pAuthInfo->assocId, userNumber,
        pAuthInfo->keyChangeSequenceNumber);  
    }
  }

  pAuthInfo->keyChangeSequenceNumber++;

#if TMWCNFG_SUPPORT_CRYPTO_AESGMAC
  /* Persist this according to SAV5 4.2.1.1 if AES-GMAC is supported */
  sdnpdata_authStoreKSQ(pSDNPSession->pDbHandle, pAuthInfo->keyChangeSequenceNumber);
#endif

  /* Even if pUserContext is TMWDEFS_NULL, key status AUTH FAIL should be sent
   * 1815-2012 A.45.5.2.2 and TB 2016-002 3.1.2.3
   */
  _sendKeyStatusResponseV5(pSDNPSession, pRxFragment->rxAddress, userNumber);

  return;
}

/* function: _processKeyChangeRequestV6 */
/* process reception of object group 120 v6 */
static TMWTYPES_BOOL TMWDEFS_LOCAL _processKeyChangeRequestV6(
  SDNPSESN *pSDNPSession,
  SDNPAUTH_RX_MSG *pRxFragment,
  SDNPAUTH_USER *pUserContext)
{
  TMWTYPES_BOOL status;
  TMWTYPES_USHORT userNumber; 
  TMWTYPES_USHORT bytesInObject;
  TMWTYPES_USHORT keyLength;
  TMWTYPES_ULONG sequenceNumber;
  TMWTYPES_ULONG expectedSequenceNumber = 0;
  SDNPAUTH_INFO *pAuthInfo = _getAuthInfo(pSDNPSession);
   
  /* Protect against badly formatted message */
  if(!_validateMsgLength((TMWSESN*)pSDNPSession, pRxFragment, 8))
  { 
    return(TMWDEFS_FALSE);
  }

  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &bytesInObject);
  pRxFragment->offset += 2;

  tmwtarg_get32(&pRxFragment->pMsgBuf[pRxFragment->offset], &sequenceNumber);
  pRxFragment->offset += 4;

  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &userNumber);
  pRxFragment->offset += 2;
 
  /* Determine length of Encrypted Key Wrap Data in message */  
  bytesInObject = bytesInObject - 6;

  /* Protect against badly formatted message */
  if(!_validateMsgLength((TMWSESN*)pSDNPSession, pRxFragment, bytesInObject))
  { 
    return(TMWDEFS_FALSE);
  }

#ifdef TMW_SUPPORT_MONITOR
  if(pSDNPSession->dnp.tmw.pChannel->pPhysContext->monitorMode)
  {
    DNPDIAG_MON_AUTH_KEYCHANGE((TMWSESN*)pSDNPSession, userNumber, sequenceNumber); 
    return TMWDEFS_TRUE;
  }
#endif

  status = TMWDEFS_FALSE; 
  keyLength = 0;
  if(pUserContext != TMWDEFS_NULL)
  {
    /* Validate request */
    expectedSequenceNumber = pAuthInfo->keyChangeSequenceNumber++;
    
#if TMWCNFG_SUPPORT_CRYPTO_AESGMAC
    /* Persist this according to SAV5 4.2.1.1 if AES-GMAC is supported */
    sdnpdata_authStoreKSQ(pSDNPSession->pDbHandle, pAuthInfo->keyChangeSequenceNumber);
#endif

    if(sequenceNumber == expectedSequenceNumber) 
    {
      if(_verifyAndGetSessionKeys(pAuthInfo, pUserContext,
        &pRxFragment->pMsgBuf[pRxFragment->offset], bytesInObject, &keyLength))
      {
        if(pRxFragment->msgLength <= SDNPAUTH_KEYCHANGEMAXSIZE)
        {
          memcpy(pUserContext->lastKeyChange, pRxFragment->pMsgBuf, pRxFragment->msgLength);
          pUserContext->lastKeyChangeLength = pRxFragment->msgLength;
          
          /* When new session keys are received a challenge/reply must take place before an aggressive mode request
           * This is to prevent the same challenge data being used forever.
           */
          pAuthInfo->rcvdAtLeastOneChallengeResponse = TMWDEFS_FALSE;
          pAuthInfo->lastChallengeRcvdLength = 0;
          status = TMWDEFS_TRUE;
        }
        else
        {
          DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_TOO_BIG);  
        }
      }
    } 
  }
  
  /* Move past encrypted key wrap data */
  pRxFragment->offset = pRxFragment->offset + bytesInObject;

  DNPDIAG_SHOW_AUTH_KEYCHANGE((TMWSESN*)pSDNPSession, userNumber, keyLength, sequenceNumber, expectedSequenceNumber, status, TMWDIAG_ID_RX); 
  sdnpdata_authLogRx(pSDNPSession->pDbHandle, 6, userNumber, sequenceNumber, pRxFragment->pMsgBuf, pRxFragment->msgLength); 

  return(status);
} 

/* function: _processErrorRequestV7 */
/* process reception of object group 120 v7 */
static TMWTYPES_BOOL TMWDEFS_LOCAL _processErrorRequestV7(
  SDNPSESN *pSDNPSession,
  SDNPAUTH_RX_MSG *pRxFragment,
  TMWTYPES_UCHAR *pErrorCode)
{
  TMWTYPES_ULONG sequenceNumber;
  TMWTYPES_USHORT bytesInObject;
  TMWTYPES_USHORT userNumber; 
  TMWTYPES_USHORT assocId; 
  TMWTYPES_UCHAR errorCode;
  TMWTYPES_MS_SINCE_70 msSince70;
  TMWDTIME timeStamp;

  /* Protect against badly formatted message */
  if(!_validateMsgLength((TMWSESN*)pSDNPSession, pRxFragment, 17))
  { 
    return(TMWDEFS_FALSE);
  }

  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &bytesInObject);
  pRxFragment->offset += 2;

  tmwtarg_get32(&pRxFragment->pMsgBuf[pRxFragment->offset], &sequenceNumber);
  pRxFragment->offset += 4;

  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &userNumber);
  pRxFragment->offset += 2;

  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &assocId);
  pRxFragment->offset += 2;

  errorCode  = pRxFragment->pMsgBuf[pRxFragment->offset++]; 
  
  dnpdtime_readMsSince70(&msSince70, &pRxFragment->pMsgBuf[pRxFragment->offset]);
  dnpdtime_msSince70ToDateTime(&timeStamp, &msSince70);
  pRxFragment->offset += 6;

  /* Get length of Optional Error Text from message */  
  bytesInObject = bytesInObject - 15;

  sdnpdata_authLogErrorRx(pSDNPSession->pDbHandle, userNumber, assocId, sequenceNumber, errorCode, &timeStamp,
    (TMWTYPES_CHAR *)&pRxFragment->pMsgBuf[pRxFragment->offset], bytesInObject);
  
  DNPDIAG_SHOW_AUTH_ERROR((TMWSESN*)pSDNPSession, userNumber, assocId, sequenceNumber, errorCode, &timeStamp,
    (TMWTYPES_CHAR *)&pRxFragment->pMsgBuf[pRxFragment->offset], bytesInObject, TMWDEFS_FALSE, TMWDIAG_ID_RX);  

  pRxFragment->offset = pRxFragment->offset + bytesInObject;

  /* Protect against badly formatted message */
  if(!_validateMsgLength((TMWSESN*)pSDNPSession, pRxFragment, 0))
  { 
    return(TMWDEFS_FALSE);
  }

  *pErrorCode = errorCode;

  _authSecStatIncrement(pSDNPSession, DNPAUTH_ERROR_MSG_RCVD_INDEX);  

  return(TMWDEFS_TRUE);
} 
   
#if DNPCNFG_SUPPORT_AUTHKEYUPDATE
 
/* function: _findOrCreateUserContext
 * purpose: Create a per user authentication context
 * arguments: pointer to authentication info structure 
 * returns: pointer to authentication user structure
 */ 
static SDNPAUTH_USER * TMWDEFS_LOCAL _findOrCreateUserContext(
  SDNPAUTH_INFO *pAuthInfo, 
  TMWTYPES_USHORT userNumber)
{
  SDNPAUTH_USER *pUserContext = TMWDEFS_NULL;

  if(userNumber == 0)
    return TMWDEFS_NULL;

  while((pUserContext = (SDNPAUTH_USER *)tmwdlist_getAfter(
    &pAuthInfo->authContexts, (TMWDLIST_MEMBER *)pUserContext)) != TMWDEFS_NULL)
  {  
    if(userNumber == pUserContext->userNumber) 
    {
      return(pUserContext);
    }
  }

  pUserContext = (SDNPAUTH_USER *)sdnpmem_alloc(SDNPMEM_AUTH_USER_TYPE);
  if (pUserContext != TMWDEFS_NULL)
  {
    pUserContext->userNumber = userNumber;
    /* Session keys will be received from master in g120v6 */
    pUserContext->monitorSessionKeyExists = TMWDEFS_FALSE;
    pUserContext->keyStatus = DNPAUTH_KEY_NOTINIT;
    pUserContext->lastKeyStatusLength = 0;
    pUserContext->lastKeyChangeLength = 0;
    pUserContext->sessionKeyStatusCount = 0;
    pUserContext->pAuthInfo = pAuthInfo;

    /* key change timer and count */
    tmwtimer_init(&pUserContext->expectedSessionKeyTimer);
    pUserContext->keyChangeCount = 0;

    tmwdlist_addEntry(&pAuthInfo->authContexts, (TMWDLIST_MEMBER *)pUserContext);
    return(pUserContext);
  }

  return TMWDEFS_NULL;
}

#if DNPCNFG_SUPPORT_AUTHKEYUPDASYM
#if SDNPDATA_SUPPORT_OBJ120_V8
/* function: _processUserCertificateV8 */
/* process reception of object group 120 v8 containing user certificate */
static void TMWDEFS_LOCAL _processUserCertificateV8(
  SDNPSESN *pSDNPSession,
  SDNPAUTH_RX_MSG *pRxFragment)
{
  TMWTYPES_USHORT length;
  TMWTYPES_UCHAR  keyChangeMethod;
  TMWTYPES_UCHAR  certificateType;

  /* Protect against badly formatted message */
  if (!_validateMsgLength((TMWSESN*)pSDNPSession, pRxFragment, 3))
  {
    return;
  }

  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &length);
  pRxFragment->offset += 2;

  keyChangeMethod = pRxFragment->pMsgBuf[pRxFragment->offset++];
  certificateType = pRxFragment->pMsgBuf[pRxFragment->offset++];
  length -= 2;

  /* Protect against badly formatted message */
  if (!_validateMsgLength((TMWSESN*)pSDNPSession, pRxFragment, length))
  {
    return;
  }

  /* name should start at index x */
  /* SPM
   * DNPDIAG_SHOW_AUTH_USERCERT((TMWSESN*)pSDNPSession, keyChangeMethod, certificateType, TMWDIAG_ID_RX);
  */

  sdnpdata_authLogRx(pSDNPSession->pDbHandle, 8, 0, 0, pRxFragment->pMsgBuf, pRxFragment->msgLength);

  /* is this key change method supported? */
  if (!sdnpdata_authKeyChgMethodSupport(pSDNPSession->pDbHandle, keyChangeMethod))
  {
    SDNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, SDNPDIAG_AUTH_BADUPDMETHOD);
    sdnpsa_sendErrorResponseV7(pSDNPSession, pRxFragment->rxAddress, 0, 0, DNPAUTH_ERROR_UPDCHGNOTPERMIT, TMWDEFS_NULL, 0);

    /* TMW-not in spec */
    _authSecStatIncrement(pSDNPSession, DNPAUTH_FAILUPDKEY_CHANGE_INDEX);
  }
  else
  {
    /*
      Verify sequence number incremented

      Verify the Area of Responsibility text string in the
      certificate matches at least one such string preconfigured for this outstation

      store global user name, user role, operation, user public key
    */

    /* validate and store the certification data */
    SDNPAUTH_INFO *pAuthInfo = _getAuthInfo(pSDNPSession);
    TMWTYPES_USHORT userNumber;
    TMWTYPES_UCHAR  operation = 0;
    TMWTYPES_UCHAR  error = 0;
    TMWTYPES_ULONG statusChangeSequenceNumber = 0;
    TMWCRYPTO_KEY  authorityKey;

    _getKey((TMWSESN*)pSDNPSession, pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_AUTH_ASYM_PUB_KEY, 0, &authorityKey);
  
    if (tmwcrypto_verifyCertificate(pSDNPSession->dnp.pCryptoHandle,
      &authorityKey,
      &pRxFragment->pMsgBuf[pRxFragment->offset], length))
    {
      userNumber = sdnpdata_authUserCertRcvd(pSDNPSession->pDbHandle,
        keyChangeMethod, certificateType, &pRxFragment->pMsgBuf[pRxFragment->offset], length,
        &statusChangeSequenceNumber, &operation, &error);
       
      if (userNumber != 0)
      {
        TMWTYPES_BOOL enforceSCS = TMWDEFS_TRUE;
        if ((pAuthInfo->testConfig & SDNPAUTH_TEST_ALLOW_V8_SCS) == 1)
        {
          enforceSCS = TMWDEFS_FALSE;
        }

        if (enforceSCS && statusChangeSequenceNumber <= pAuthInfo->lastSCS)
        {
          /* Check for wrap allowing for missed sequence and lastSCS inited to 0xffffff
           */
          if (!((pAuthInfo->lastSCS > 0xfffffff0) && (statusChangeSequenceNumber < 16)))
          {
            SDNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, SDNPDIAG_AUTH_BADUPDSCS);
            error = DNPAUTH_ERROR_INVALIDCERTDATA;
          }
        }
        else
        {
          pAuthInfo->lastSCS = statusChangeSequenceNumber;
          /* This is an x509 certificate that contains a user public key in addition to other things
            */
          tmwcrypto_putCertificate(pSDNPSession->dnp.pCryptoHandle, (void *)userNumber,
            &pRxFragment->pMsgBuf[pRxFragment->offset], length);

          _sendNullResponse(pSDNPSession, pRxFragment->rxAddress);

          if (operation == DNPAUTH_USER_STATUS_DELETE)
          {
            /* delete this userNumber from SCL */
            sdnpsa_removeUser(pAuthInfo, userNumber);
          }
        }

        _authSecStatIncrement(pSDNPSession, DNPAUTH_SUCCESS_AUTHENT_INDEX);
      }
      else
      {
        if (operation == DNPAUTH_USER_STATUS_ADD)
        {
          error = DNPAUTH_ERROR_UPDCHGNOTPERMIT;
        }
        else
        {
          error = DNPAUTH_ERROR_UNKNOWN_USER;
          DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_UNKNOWN_USR);
        }
      }
    }
    else
    {
      SDNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, SDNPDIAG_AUTH_BADSIGNATURE);
      error = DNPAUTH_ERROR_INVALIDSIG;
    }

    if(error)
    {
      DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_UPDATE_FAILED);
      sdnpsa_sendErrorResponseV7(pSDNPSession, pRxFragment->rxAddress, 0,
       0, error, TMWDEFS_NULL, 0);
    
      /* TMW-not in spec */
      _authSecStatIncrement(pSDNPSession, DNPAUTH_FAILUPDKEY_CHANGE_INDEX); 
    }
  }

  /* move past certification data from message */
  pRxFragment->offset += length;
}
#endif /* SDNPDATA_SUPPORT_OBJ120_V8 */
#endif

/* function: _processUserStatusChangeV10 */
/* process reception of object group 120 v10 */
static TMWTYPES_BOOL TMWDEFS_LOCAL _processUserStatusChangeV10(
  SDNPSESN *pSDNPSession,
  SDNPAUTH_RX_MSG *pRxFragment)
{
  TMWTYPES_USHORT bytesInObject;
  TMWTYPES_UCHAR  errorCode;
  TMWTYPES_UCHAR  keyChangeMethod;
  TMWTYPES_UCHAR  operation;
  TMWTYPES_ULONG  statusChangeSequenceNumber;
  TMWTYPES_USHORT userRole;
  TMWTYPES_USHORT userRoleExpiryInterval;
  TMWTYPES_USHORT userNameLength;
  TMWTYPES_USHORT userPublicKeyLength;
#if DNPCNFG_SUPPORT_AUTHKEYUPDASYM
  TMWTYPES_ULONG  userPublicKeyIndex;
#endif
  TMWTYPES_USHORT certificationDataLength;
  TMWTYPES_USHORT valueLength;
  TMWTYPES_BOOL   enforceSCS;
  TMWCRYPTO_KEY   key;
  SDNPAUTH_INFO  *pAuthInfo = _getAuthInfo(pSDNPSession);
  TMWTYPES_UCHAR *pValue = pAuthInfo->dataIfBuffer;

  /* Protect against badly formatted message */
  if (!_validateMsgLength((TMWSESN*)pSDNPSession, pRxFragment, 18))
  {
    return(TMWDEFS_FALSE);
  }

  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &bytesInObject);
  pRxFragment->offset += 2;

  keyChangeMethod = pRxFragment->pMsgBuf[pRxFragment->offset++];
  operation = pRxFragment->pMsgBuf[pRxFragment->offset++];

  tmwtarg_get32(&pRxFragment->pMsgBuf[pRxFragment->offset], &statusChangeSequenceNumber);
  pRxFragment->offset += 4;

  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &userRole);
  pRxFragment->offset += 2;

  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &userRoleExpiryInterval);
  pRxFragment->offset += 2;

  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &userNameLength);
  pRxFragment->offset += 2;

  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &userPublicKeyLength);
  pRxFragment->offset += 2;

  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &certificationDataLength);
  pRxFragment->offset += 2;

  /* user name */
  pRxFragment->offset += userNameLength;

  /* If symmetric, user public key will be empty */
#if DNPCNFG_SUPPORT_AUTHKEYUPDASYM
  /* to avoid warning */
  userPublicKeyIndex = pRxFragment->offset;
#endif
  if (userPublicKeyLength > 0)
  {
    /* user public key */
    pRxFragment->offset += userPublicKeyLength;
  }

  /* Protect against badly formatted message */
  if (!_validateMsgLength((TMWSESN*)pSDNPSession, pRxFragment, certificationDataLength))
  {
    return(TMWDEFS_FALSE);
  }

  /* name should start at index 24 */
  DNPDIAG_SHOW_AUTH_USERSTATUS((TMWSESN*)pSDNPSession, userNameLength, &pRxFragment->pMsgBuf[24],
    keyChangeMethod, operation, userRole, userRoleExpiryInterval, statusChangeSequenceNumber, pAuthInfo->lastSCS, TMWDIAG_ID_RX);

  sdnpdata_authLogRx(pSDNPSession->pDbHandle, 10, 0, statusChangeSequenceNumber, pRxFragment->pMsgBuf, pRxFragment->msgLength);

  enforceSCS = TMWDEFS_TRUE;
  if ((pAuthInfo->testConfig & SDNPAUTH_TEST_ALLOW_V10_SCS) != 0)
  {
    enforceSCS = TMWDEFS_FALSE;
  }

  if (enforceSCS && statusChangeSequenceNumber <= pAuthInfo->lastSCS)
  { 
    /* Check for wrap allowing for missed sequence and lastSCS inited to 0xffffff 
    */ 
    if(!((pAuthInfo->lastSCS > 0xfffffff0) && (statusChangeSequenceNumber < 16)))
    {
      SDNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, SDNPDIAG_AUTH_BADUPDSCS);  

      /* TMW-there is no error enum for this situation */
      sdnpsa_sendErrorResponseV7(pSDNPSession, pRxFragment->rxAddress, statusChangeSequenceNumber, 0, DNPAUTH_ERROR_INVALIDCERTDATA, TMWDEFS_NULL, 0);  
    
      /* TMW-not in spec */
      _authSecStatIncrement(pSDNPSession, DNPAUTH_FAILUPDKEY_CHANGE_INDEX); 
      return TMWDEFS_FALSE;
    }
  }
  pAuthInfo->lastSCS = statusChangeSequenceNumber;

  /* is this key change method supported? */
  if(!sdnpdata_authKeyChgMethodSupport(pSDNPSession->pDbHandle, keyChangeMethod))   
  {
    SDNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, SDNPDIAG_AUTH_BADUPDMETHOD);  
    sdnpsa_sendErrorResponseV7(pSDNPSession, pRxFragment->rxAddress, statusChangeSequenceNumber, 0, DNPAUTH_ERROR_UPDCHGNOTPERMIT, TMWDEFS_NULL, 0);  
    
    /* TMW-not in spec */
    _authSecStatIncrement(pSDNPSession, DNPAUTH_FAILUPDKEY_CHANGE_INDEX); 
    return TMWDEFS_FALSE;
  }

  /* Fill pValue in with data, so that certification data can be verified
   * This data will contain an
   *   Operation,
   *   Status Change Sequence (SCS) number between the Authority and Outstation,
   *   Role and Interval, 
   *   Length of globally unique Name
   *   if asymmetric change method 
   *     User Public Key length 
   *     Globally Unique Name representing user
   *     User Public key
   *
   *   If symmetric 
   *     Globally Unique Name representing user 
   */
  tmwtarg_store8(&operation, pValue);
  valueLength = 1;

  tmwtarg_store32(&statusChangeSequenceNumber, (pValue+valueLength));
  valueLength += 4;
  
  tmwtarg_store16(&userRole, (pValue+valueLength));
  valueLength += 2;

  tmwtarg_store16(&userRoleExpiryInterval, (pValue+valueLength));
  valueLength += 2;
  
  tmwtarg_store16(&userNameLength, (pValue+valueLength));
  valueLength += 2;

#if DNPCNFG_SUPPORT_AUTHKEYUPDASYM
  errorCode = DNPAUTH_ERROR_NONE;
  if(_isAsymmetric(keyChangeMethod))
  {
    tmwtarg_store16(&userPublicKeyLength, (pValue+valueLength));
    valueLength += 2;
   
    memcpy((pValue + valueLength), &pRxFragment->pMsgBuf[24], userNameLength); 
    valueLength += userNameLength;
 
    if(userPublicKeyLength > 0)
    {
      memcpy((pValue + valueLength), &pRxFragment->pMsgBuf[userPublicKeyIndex], userPublicKeyLength); 
      valueLength += userPublicKeyLength; 
        
      DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pSDNPSession, dataTypeUserPublicKey, &pRxFragment->pMsgBuf[userPublicKeyIndex], userPublicKeyLength, TMWDIAG_ID_RX);
    }

    DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pSDNPSession, dataTypeCertData, &pRxFragment->pMsgBuf[pRxFragment->offset], certificationDataLength, TMWDIAG_ID_RX);

    /* spec says validate the authority’s digital signature using the authority’s preconfigured public key.
     * This was signed by the authority using its private key 
     */  

    _getKey((TMWSESN*)pSDNPSession, pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_AUTH_ASYM_PUB_KEY, 0, &key); 
    if(!tmwcrypto_verifySignature(pSDNPSession->dnp.pCryptoHandle,
      dnpauth_methodToSignatureAlgorithm(keyChangeMethod), &key, 
      pValue, valueLength, 
      &pRxFragment->pMsgBuf[pRxFragment->offset], certificationDataLength))
    {
      SDNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, SDNPDIAG_AUTH_BADSIGNATURE);
      errorCode = DNPAUTH_ERROR_INVALIDSIG;
    }
  }
  else
#endif
  {
    TMWTYPES_USHORT valueLength2;
    TMWTYPES_UCHAR *pValue2 = pAuthInfo->dataIfBuffer2; 
    
    errorCode = DNPAUTH_ERROR_INVALIDCERTDATA;
 
    /*
     * Hash the received data and compare it to the hash value in the message.
     * Authority created the hash using a key called Authority Certification Key 
     * that was PRESHARED (configured) with this outstation.
     */
    if(_getKey((TMWSESN*)pSDNPSession, pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_AUTH_CERT_SYM_KEY, 0, &key) == TMWDEFS_TRUE)
    { 
#if TMWCNFG_SUPPORT_CRYPTO_AESGMAC
      /* If AES-GMAC, set up init vector */
      if(dnpauth_methodToTMWMacAlgo(keyChangeMethod) == TMWCRYPTO_ALG_MAC_AESGMAC)
      { 
        /*
          pSession->destAddress;
          usernumber==0
          statusChangeSequenceNumber
          csq==0   
        */  
        TMWTYPES_UCHAR *pInitVector = pAuthInfo->dataIfBuffer2;  
        TMWTYPES_USHORT vectorLength = 0;
        TMWTYPES_ULONG zero = 0;

        tmwtarg_store16(&pSDNPSession->dnp.tmw.destAddress, &pInitVector[vectorLength]);
        vectorLength += 2;

        tmwtarg_store16((TMWTYPES_USHORT*)&zero, &pInitVector[vectorLength]);
        vectorLength += 2;
        
        tmwtarg_store32(&statusChangeSequenceNumber, &pInitVector[vectorLength]);
        vectorLength += 4;
        
        tmwtarg_store32(&zero, &pInitVector[vectorLength]);
        vectorLength += 4;

        DNPDIAG_AUTH_INITVECTOR((TMWSESN*)pAuthInfo->pSession, pInitVector, vectorLength, TMWDIAG_ID_RX); 

        tmwcrypto_setIVector(pSDNPSession->dnp.pCryptoHandle, &key, pInitVector, vectorLength); 
      }
#endif
 
      memcpy((pValue + valueLength), &pRxFragment->pMsgBuf[24], userNameLength); 
      valueLength += userNameLength;

      DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pSDNPSession, dataTypeRcvdMAC, &pRxFragment->pMsgBuf[pRxFragment->offset], certificationDataLength, TMWDIAG_ID_RX);

      /* Now use dataIfBuffer2 and valueLength2 for MAC value */
      /* Set maximum allowed size */
      valueLength2 = SDNPAUTH_BUFFERSIZE;
      if((certificationDataLength <= SDNPAUTH_BUFFERSIZE) 
       &&(tmwcrypto_MACValue(pSDNPSession->dnp.pCryptoHandle, dnpauth_methodToTMWMacAlgo(keyChangeMethod), 
        &key, certificationDataLength,
        pValue, valueLength,
        pValue2, &valueLength2)))
      {

        DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pSDNPSession, dataTypePlainData, pValue, valueLength, TMWDIAG_ID_RX);
        DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pSDNPSession, dataTypeGenMAC, pValue2, valueLength2, TMWDIAG_ID_RX);
      
        /* compare the two hash values */
        if(!memcmp(&pRxFragment->pMsgBuf[pRxFragment->offset], pValue2, certificationDataLength))
        { 
          errorCode = DNPAUTH_ERROR_NONE;
        }
        else
        {
          errorCode = DNPAUTH_ERROR_INVALIDCERTDATA;
          DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_BADMAC);
        }
      
#if TMWCNFG_SUPPORT_CRYPTO_AESGMAC
        if(dnpauth_methodToTMWMacAlgo(keyChangeMethod) == TMWCRYPTO_ALG_MAC_AESGMAC)
          /* Set the init vector back to empty */
          tmwcrypto_setIVector(pSDNPSession->dnp.pCryptoHandle, &key, TMWDEFS_NULL, 0); 
#endif 
      }
    }
  }

  /* validate request as specified in 3.2.6.5 */
  /* store data */
  if(errorCode == DNPAUTH_ERROR_NONE)
  {
    /* reject RESERVED values for user role */
    if (userRole <= 7 || userRole >= 32768)
    {
      TMWTYPES_USHORT userNumber = sdnpdata_authUserStatusChgRcvd(pSDNPSession->pDbHandle,
        /* user name starting at index 24 */
        (TMWTYPES_CHAR*)&pRxFragment->pMsgBuf[24], userNameLength,
        keyChangeMethod, operation, userRole, userRoleExpiryInterval);

      _authSecStatIncrement(pSDNPSession, DNPAUTH_SUCCESS_AUTHENT_INDEX);

#if DNPCNFG_SUPPORT_AUTHKEYUPDASYM
      if ((userNumber != 0) && (userPublicKeyLength > 0))
      {
        tmwcrypto_setKeyData(pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_USER_ASYM_PUB_KEY, (void *)userNumber,
          &pRxFragment->pMsgBuf[userPublicKeyIndex], userPublicKeyLength);
      }
#endif
      if (userNumber == 0)
      {
        if (operation == DNPAUTH_USER_STATUS_ADD)
        {
          errorCode = DNPAUTH_ERROR_UPDCHGNOTPERMIT;
        }
        else
        {
          errorCode = DNPAUTH_ERROR_UNKNOWN_USER;
          DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_UNKNOWN_USR);
        }
      }
      else if (operation == DNPAUTH_USER_STATUS_DELETE)
      {
        /* delete this userNumber from SCL */
        sdnpsa_removeUser(pAuthInfo, userNumber);
      }
    }
    else
    {
      /* DNP SA Conformance test says Reserved roles will cause g120v7 to be sent, but error value is not specified. */
      errorCode = DNPAUTH_ERROR_AUTHENTFAILED;
    }
  }

  /* move past certification data from message */
  pRxFragment->offset += certificationDataLength;
 
  /* Either send error response or 0x83 authentication null response */
  if(errorCode == DNPAUTH_ERROR_NONE)
  {
    _sendNullResponse(pSDNPSession, pRxFragment->rxAddress);
  }
  else
  { 
    DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_UPDATE_FAILED);
    sdnpsa_sendErrorResponseV7(pSDNPSession, pRxFragment->rxAddress, statusChangeSequenceNumber,
      0, errorCode, TMWDEFS_NULL, 0);
    
    /* TMW-not in spec */
    _authSecStatIncrement(pSDNPSession, DNPAUTH_FAILUPDKEY_CHANGE_INDEX); 
  }
   
  return(TMWDEFS_TRUE);
}
  
/* function: _processUpdateKeyChangeReqV11 */
/* process reception of object group 120 v11 */
static TMWTYPES_BOOL TMWDEFS_LOCAL _processUpdateKeyChangeReqV11(
  SDNPSESN *pSDNPSession,
  SDNPAUTH_RX_MSG *pRxFragment)
{
  SDNPAUTH_INFO *pAuthInfo;
  SDNPAUTH_USER *pUserContext;
  TMWTYPES_ULONG  userNameIndex;
  TMWTYPES_USHORT userNumber;
  TMWTYPES_USHORT bytesInObject;
  TMWTYPES_USHORT userNameLength;
  TMWTYPES_USHORT masterChallengeLength;
  TMWTYPES_UCHAR  keyChangeMethod;
  TMWTYPES_UCHAR  errorCode;

  pAuthInfo = _getAuthInfo(pSDNPSession); 
 
  /* Protect against badly formatted message */
  if(!_validateMsgLength((TMWSESN*)pSDNPSession, pRxFragment, 7))
  { 
    return(TMWDEFS_FALSE);
  }

  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &bytesInObject);
  pRxFragment->offset += 2;
 
  keyChangeMethod = pRxFragment->pMsgBuf[pRxFragment->offset++]; 

  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &userNameLength);
  pRxFragment->offset += 2;

  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &masterChallengeLength);
  pRxFragment->offset += 2;

  /* leave user name in message, just point to later */ 
  userNameIndex = pRxFragment->offset;
  pRxFragment->offset += userNameLength;   

  /* Protect against badly formatted message */
  if(!_validateMsgLength((TMWSESN*)pSDNPSession, pRxFragment, 0))
  { 
    return(TMWDEFS_FALSE);
  }

  DNPDIAG_SHOW_AUTH_UPDKEYCHGREQ((TMWSESN*)pSDNPSession, userNameLength, &pRxFragment->pMsgBuf[userNameIndex], 
    keyChangeMethod, masterChallengeLength, &pRxFragment->pMsgBuf[pRxFragment->offset], TMWDIAG_ID_RX);
  sdnpdata_authLogRx(pSDNPSession->pDbHandle, 11, 0, 0, pRxFragment->pMsgBuf, pRxFragment->msgLength); 

  /* challenge data from message */
  memcpy(pAuthInfo->masterChallengeData, &pRxFragment->pMsgBuf[pRxFragment->offset], masterChallengeLength);
  pAuthInfo->masterChallengeDataLength = masterChallengeLength; 
  pRxFragment->offset += masterChallengeLength;

  /* is this key change method supported? */
  if (sdnpdata_authKeyChgMethodSupport(pSDNPSession->pDbHandle, keyChangeMethod))
  {
    /* Determine what user number this user name is assigned */
    userNumber = sdnpdata_authUpdateKeyChgReq(pSDNPSession->pDbHandle, keyChangeMethod,
      (TMWTYPES_CHAR*)&pRxFragment->pMsgBuf[userNameIndex], userNameLength);

    pUserContext = _findOrCreateUserContext(pAuthInfo, userNumber);
    if (pUserContext != TMWDEFS_NULL)
    {
      pAuthInfo->currentUserNumber = userNumber;

      /* as indicated in g120v12 sheet */
      pAuthInfo->keyChangeSequenceNumber++;

#if TMWCNFG_SUPPORT_CRYPTO_AESGMAC
      /* Persist this according to SAV5 4.2.1.1 if AES-GMAC is supported */
      sdnpdata_authStoreKSQ(pSDNPSession->pDbHandle, pAuthInfo->keyChangeSequenceNumber);
#endif

      pAuthInfo->keyChangeMethod = keyChangeMethod;

      return TMWDEFS_TRUE;
    }
    errorCode = DNPAUTH_ERROR_UNKNOWN_USER;
  }
  else
  {
    SDNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, SDNPDIAG_AUTH_BADUPDMETHOD);
    errorCode = DNPAUTH_ERROR_UPDCHGNOTPERMIT;
  }

  sdnpsa_sendErrorResponseV7(pSDNPSession, pRxFragment->rxAddress, pAuthInfo->keyChangeSequenceNumber, 0, errorCode, TMWDEFS_NULL, 0);

  /* TMW-not in spec */
  _authSecStatIncrement(pSDNPSession, DNPAUTH_FAILUPDKEY_CHANGE_INDEX); 
  return TMWDEFS_FALSE;
}
 
/* function: _processUpdateKeyChangeV13 */
/* process reception of object group 120 v13 */
static TMWTYPES_UCHAR TMWDEFS_LOCAL _processUpdateKeyChangeV13(
  SDNPSESN *pSDNPSession,
  SDNPAUTH_RX_MSG *pRxFragment)
{
  SDNPAUTH_INFO *pAuthInfo; 
  TMWTYPES_UCHAR *pValue;
  TMWCRYPTO_KEY key;
  TMWTYPES_ULONG  keyChangeSequenceNumber;
  TMWTYPES_USHORT bytesInObject;
  TMWTYPES_USHORT userNumber;
  TMWTYPES_USHORT encryptedUpdateKeyLength;  
  TMWTYPES_USHORT decryptedLength;
  TMWTYPES_UCHAR errorCode = DNPAUTH_ERROR_NONE;
 
  pAuthInfo = _getAuthInfo(pSDNPSession); 
  decryptedLength = SDNPAUTH_BUFFERSIZE;  
  pValue = pAuthInfo->dataIfBuffer;
 
  /* Protect against badly formatted message */
  if(!_validateMsgLength((TMWSESN*)pSDNPSession, pRxFragment, 10))
  { 
    return(TMWDEFS_FALSE);
  }

  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &bytesInObject);
  pRxFragment->offset += 2;

  tmwtarg_get32(&pRxFragment->pMsgBuf[pRxFragment->offset], &keyChangeSequenceNumber);
  pRxFragment->offset += 4;

  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &userNumber);
  pRxFragment->offset += 2;
  
  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &encryptedUpdateKeyLength);
  pRxFragment->offset += 2;

  DNPDIAG_SHOW_AUTH_UPDATEKEYCHANGE((TMWSESN*)pSDNPSession, userNumber, keyChangeSequenceNumber, TMWDIAG_ID_RX);

  if (pAuthInfo->keyChangeSequenceNumber == keyChangeSequenceNumber)
  {
    pAuthInfo->userNameLength = DNPCNFG_AUTH_MAX_USERNAME_LENGTH;
    if (!sdnpdata_authGetUserName(pSDNPSession->pDbHandle, userNumber, (TMWTYPES_CHAR *)&pAuthInfo->username, &pAuthInfo->userNameLength))
    {
      /* User name cannot be retrieved */
      DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_FINDUSERNAME);
      errorCode = DNPAUTH_ERROR_UNKNOWN_USER;
    } 
  }
  else
  {
    errorCode = DNPAUTH_ERROR_INVALIDCERTDATA;
  }
 
  if(errorCode == DNPAUTH_ERROR_NONE)
  {
#if DNPCNFG_SUPPORT_AUTHKEYUPDASYM
    if(_isAsymmetric(pAuthInfo->keyChangeMethod))
    {  
      /* Decrypt the data encrypted by the master using the outstations public key and
       *   decrypted using the outstation private key.
       *   The private and public keys should be generated on the outstation and the  
       *   generated public key should be configured on the master. 
       */ 
      _getKey((TMWSESN*)pSDNPSession, pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_OS_ASYM_PRV_KEY, 0, &key);
      if (!tmwcrypto_decryptData(pSDNPSession->dnp.pCryptoHandle, dnpauth_methodToKeyTransAlgorithm(pAuthInfo->keyChangeMethod), &key,
        &pRxFragment->pMsgBuf[pRxFragment->offset], encryptedUpdateKeyLength,
        pValue, &decryptedLength))
      {
        errorCode = DNPAUTH_ERROR_INVALIDSIG;
      }

      pAuthInfo->pEncryptedUpdateKeyData = &pRxFragment->pMsgBuf[pRxFragment->offset];
      pAuthInfo->encryptedUpdateKeyLength = encryptedUpdateKeyLength;
    }
    else
#endif
    {
     /* Decrypt the data that has been encrypted by the authority using a symmetric key 
      * called Authority Certification Key that was PRESHARED (configured) with this outstation.
      * This would use a key wrap algorithm since it contains the update key 
      */ 
      if (_getKey((TMWSESN*)pSDNPSession, pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_AUTH_CERT_SYM_KEY, 0, &key))
      {
        if (!tmwcrypto_decryptData(pSDNPSession->dnp.pCryptoHandle, dnpauth_methodToKeyTransAlgorithm(pAuthInfo->keyChangeMethod), &key,
          &pRxFragment->pMsgBuf[pRxFragment->offset], encryptedUpdateKeyLength,
          pValue, &decryptedLength))
        {
          errorCode = DNPAUTH_ERROR_INVALIDSIG;
        }
      }
      else
      {
        DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_GETKEYFAIL);
      }
    }
  }

  if(errorCode == DNPAUTH_ERROR_NONE)
  {
    TMWTYPES_UCHAR updateKeyLength;

    DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pSDNPSession, dataTypeKeyData, &pRxFragment->pMsgBuf[pRxFragment->offset], encryptedUpdateKeyLength, TMWDIAG_ID_RX);
    DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pSDNPSession, dataTypePlainData, pValue, decryptedLength, TMWDIAG_ID_RX);
   
    /* The encrypted data should contain the following data
     * (User Name, Update Key, Outstation Challenge Data, Padding Data)
     *  Verify User Name and Outstation Challenge Data 
     */ 
    updateKeyLength = dnpauth_getUpdateKeyLength(pAuthInfo->keyChangeMethod);
    if(memcmp(pValue, pAuthInfo->username, pAuthInfo->userNameLength))
    { 
      /* User name does not match */
      DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_USERNAME); 
      errorCode = DNPAUTH_ERROR_INVALIDCERTDATA;
    }
    else if(memcmp((pValue+pAuthInfo->userNameLength+updateKeyLength), pAuthInfo->outstationChallengeData, pAuthInfo->outstationChallengeDataLength))
    {
      /* Challenge data does not match */
      DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_BADCHALLENGE); 
      errorCode = DNPAUTH_ERROR_INVALIDCERTDATA;
    }
    else
    {
      /* tell database to save this update key, but to keep the old one in case this fails the next step */
      tmwcrypto_setKeyData(pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_USER_UPDATE_KEY, (void *)userNumber, 
        (pValue+pAuthInfo->userNameLength), updateKeyLength);
    }
  }
  else
  {  
    /* could not get key or tmwcrypto_decryptData failed */
    DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_DECRYPT);    
  }

  pRxFragment->offset += encryptedUpdateKeyLength;
   
  sdnpdata_authLogRx(pSDNPSession->pDbHandle, 13, userNumber, keyChangeSequenceNumber, pRxFragment->pMsgBuf, pRxFragment->msgLength); 

  return(errorCode);
} 

#if DNPCNFG_SUPPORT_AUTHKEYUPDASYM
/* function: _processUpdKeyChangeSigV14 */
/* process reception of object group 120 v14 */
static TMWTYPES_BOOL TMWDEFS_LOCAL _processUpdKeyChangeSigV14(
  SDNPSESN *pSDNPSession,
  SDNPAUTH_RX_MSG *pRxFragment)
{ 
  SDNPAUTH_USER *pUserContext;
  SDNPAUTH_INFO *pAuthInfo;
  TMWTYPES_UCHAR *pValue;
  TMWTYPES_BOOL status;
  TMWTYPES_USHORT bytesInObject;
  TMWTYPES_USHORT length;
  TMWCRYPTO_KEY key;
  
  pAuthInfo = _getAuthInfo(pSDNPSession); 
  pValue = pAuthInfo->dataIfBuffer;

  /* Protect against badly formatted message */
  if(!_validateMsgLength((TMWSESN*)pSDNPSession, pRxFragment, 2))
  { 
    return(TMWDEFS_FALSE);
  }

  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &bytesInObject);
  pRxFragment->offset += 2;
  
  /* Protect against badly formatted message */
  if(!_validateMsgLength((TMWSESN*)pSDNPSession, pRxFragment, bytesInObject))
  { 
    return(TMWDEFS_FALSE);
  }

  /* verify signature using public key that was received in g120v10
   * and see if it is valid for the data received.
   * The data should contain Outstation Name, Master challenge data, Outstation challenge data, 
   * key change sequence number, user number and Encrypted Update Key Data
   */
  /* This must be set to maximum allowed length so that get name function knows */
  pAuthInfo->outstationNameLength = DNPCNFG_AUTH_MAX_OSNAME_LENGTH;
  if(!sdnpdata_authGetOSName(pSDNPSession->pDbHandle, 
   (TMWTYPES_CHAR *)&pAuthInfo->outstationName, &pAuthInfo->outstationNameLength))
  {
    pAuthInfo->outstationNameLength = 0;
  }
 
  memcpy(pValue, pAuthInfo->outstationName, pAuthInfo->outstationNameLength);

  memcpy((pValue+pAuthInfo->outstationNameLength), 
    pAuthInfo->masterChallengeData, pAuthInfo->masterChallengeDataLength);

  length = pAuthInfo->outstationNameLength+pAuthInfo->masterChallengeDataLength;
  memcpy((pValue+length), 
    pAuthInfo->outstationChallengeData, pAuthInfo->outstationChallengeDataLength);

  length += pAuthInfo->outstationChallengeDataLength;

  pUserContext = _findUserContext(pAuthInfo, pAuthInfo->currentUserNumber);
  if(pUserContext == TMWDEFS_NULL)
  {
    DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_UPDATE_FAILED);
    pRxFragment->offset = pRxFragment->msgLength;
    return(TMWDEFS_FALSE);
  }

  tmwtarg_store32(&pAuthInfo->keyChangeSequenceNumber, (pValue+length));

  length += 4;
  tmwtarg_store16(&pAuthInfo->currentUserNumber, (pValue+length));

  length +=2;
  memcpy((pValue+length), 
   pAuthInfo->pEncryptedUpdateKeyData, pAuthInfo->encryptedUpdateKeyLength);

  length += pAuthInfo->encryptedUpdateKeyLength;

  DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pSDNPSession, dataTypeCertData, &pRxFragment->pMsgBuf[pRxFragment->offset], bytesInObject, TMWDIAG_ID_RX);

  /* Verify signature using the public key that was received in g120v10 
   *  This will contain
   *    Outstation Name, Master challenge data, Outstation challenge data, 
   *    key change sequence number, user number and Encrypted Update Key Data
   */  
  _getKey((TMWSESN*)pSDNPSession, pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_USER_ASYM_PUB_KEY, (void*)pAuthInfo->currentUserNumber, &key); 
  status = tmwcrypto_verifySignature(pSDNPSession->dnp.pCryptoHandle, dnpauth_methodToSignatureAlgorithm(pAuthInfo->keyChangeMethod), &key,
    pValue, length, &pRxFragment->pMsgBuf[pRxFragment->offset], bytesInObject);
  
  if(status)
  {
    /* start using new update key and role now */
    tmwcrypto_commitKey(pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_USER_UPDATE_KEY, (void*)pAuthInfo->currentUserNumber, TMWDEFS_TRUE);
    pUserContext->keyWrapAlgorithm = tmwcrypto_getAlgorithm(pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_USER_UPDATE_KEY, (void*)pAuthInfo->currentUserNumber);
    _authSecStatIncrement(pSDNPSession, DNPAUTH_SUCCESS_AUTHENT_INDEX);
  }
  else
  {
    /* discard this tentative update key */
    SDNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, SDNPDIAG_AUTH_BADSIGNATURE);
    tmwcrypto_commitKey(pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_USER_UPDATE_KEY, (void*)pAuthInfo->currentUserNumber, TMWDEFS_FALSE);
   
    /* After return from this function, Error Response will be sent. */
  }
  
  DNPDIAG_SHOW_AUTH_UPDATEKEYCHGSIG((TMWSESN*)pSDNPSession, TMWDIAG_ID_RX);
  sdnpdata_authLogRx(pSDNPSession->pDbHandle, 15, pAuthInfo->currentUserNumber, 0, pRxFragment->pMsgBuf, pRxFragment->msgLength); 

  pRxFragment->offset += bytesInObject;

  return(status);
} 
#endif

/* function: _processUpdateKeyChangeConfV15 */
/* process reception of object group 120 v15 */
static TMWTYPES_BOOL TMWDEFS_LOCAL _processUpdateKeyChangeConfV15(
  SDNPSESN *pSDNPSession,
  SDNPAUTH_RX_MSG *pRxFragment)
{ 
  SDNPAUTH_USER *pUserContext;
  TMWTYPES_BOOL status;
  TMWTYPES_USHORT bytesInObject;
  TMWCRYPTO_KEY updateKey;
  SDNPAUTH_INFO *pAuthInfo = _getAuthInfo(pSDNPSession); 
  TMWTYPES_UCHAR *pValue = pAuthInfo->dataIfBuffer;
  TMWTYPES_UCHAR *pValue2 = pAuthInfo->dataIfBuffer2;  
  TMWTYPES_USHORT valueLength = 0;  
  TMWTYPES_USHORT valueLength2 = SDNPAUTH_BUFFERSIZE;

  /* Protect against badly formatted message */
  if(!_validateMsgLength((TMWSESN*)pSDNPSession, pRxFragment, 2))
  { 
    return(TMWDEFS_FALSE);
  }

  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &bytesInObject);
  pRxFragment->offset += 2;
  
  /* Protect against badly formatted message */
  if((pRxFragment->offset+bytesInObject) > pRxFragment->msgLength)
  {
    DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_INVALID_SIZE); 
    return(TMWDEFS_FALSE);
  }
  pUserContext = _findUserContext(pAuthInfo, pAuthInfo->currentUserNumber);
  if(pUserContext == TMWDEFS_NULL)
  {
    DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_UPDATE_FAILED);
    pRxFragment->offset = pRxFragment->msgLength;
    return(TMWDEFS_FALSE);
  }
 
  status = TMWDEFS_FALSE;

  if(_getKey((TMWSESN*)pSDNPSession, pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_USER_UPDATE_KEY, (void*)pAuthInfo->currentUserNumber, &updateKey)) 
  {  
#if TMWCNFG_SUPPORT_CRYPTO_AESGMAC
    /* If AES-GMAC set up init vector */
    if(dnpauth_methodToTMWMacAlgo(pAuthInfo->keyChangeMethod) == TMWCRYPTO_ALG_MAC_AESGMAC)
    { 
      /*   
         pSession->destAddress; 
         pAuthInfo->currentUserNumber
         pAuthInfo->keyChangeSequenceNumber 
         last csq sent by master in v3 or by OS in v1 or zero 
      */  
      TMWTYPES_UCHAR *pInitVector = pAuthInfo->dataIfBuffer2;  
      TMWTYPES_USHORT vectorLength = 0; 

      tmwtarg_store16(&pSDNPSession->dnp.tmw.destAddress, &pInitVector[vectorLength]);
      vectorLength += 2;

      tmwtarg_store16(&pAuthInfo->currentUserNumber, &pInitVector[vectorLength]);
      vectorLength += 2;
      
      tmwtarg_store32(&pAuthInfo->keyChangeSequenceNumber, &pInitVector[vectorLength]);
      vectorLength += 4;
         
      tmwtarg_store32(&pAuthInfo->challengeSequenceNumber, &pInitVector[vectorLength]);
      vectorLength += 4;
    
      DNPDIAG_AUTH_INITVECTOR((TMWSESN*)pAuthInfo->pSession, pInitVector, vectorLength, 0); 

      tmwcrypto_setIVector(pSDNPSession->dnp.pCryptoHandle, &updateKey, pInitVector, vectorLength); 
    }
#endif

    /* MAC should be on Outstation Name, master challenge data, outstation challenge data, 
     * key change sequence number and user number 
     */ 
    /* This must be set to maximum allowed length so that get name function knows */
    pAuthInfo->outstationNameLength = DNPCNFG_AUTH_MAX_OSNAME_LENGTH;
    if(!sdnpdata_authGetOSName(pSDNPSession->pDbHandle, 
        (TMWTYPES_CHAR *)&pAuthInfo->outstationName, &pAuthInfo->outstationNameLength))
    {
      pAuthInfo->outstationNameLength = 0;
    }

    memcpy(pValue, pAuthInfo->outstationName, pAuthInfo->outstationNameLength);
    valueLength = pAuthInfo->outstationNameLength;

    memcpy((pValue+valueLength), pAuthInfo->masterChallengeData, pAuthInfo->masterChallengeDataLength);
    valueLength += pAuthInfo->masterChallengeDataLength;

    memcpy((pValue+valueLength), pAuthInfo->outstationChallengeData, pAuthInfo->outstationChallengeDataLength);
    valueLength += pAuthInfo->outstationChallengeDataLength;

    tmwtarg_store32(&pAuthInfo->keyChangeSequenceNumber, (pValue+valueLength));
    valueLength += 4;
    
    tmwtarg_store16(&pAuthInfo->currentUserNumber, (pValue+valueLength));
    valueLength += 2;
     
    if(bytesInObject <= valueLength2)
    {
      DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pSDNPSession, dataTypeRcvdMAC, &pRxFragment->pMsgBuf[pRxFragment->offset], bytesInObject, TMWDIAG_ID_RX);

      status = tmwcrypto_MACValue(pSDNPSession->dnp.pCryptoHandle, dnpauth_methodToTMWMacAlgo(pAuthInfo->keyChangeMethod), 
        &updateKey, bytesInObject,
        pValue, valueLength, pValue2, &valueLength2);

      DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pSDNPSession, dataTypePlainData, pValue, valueLength, TMWDIAG_ID_RX);
      DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pSDNPSession, dataTypeGenMAC, pValue2, valueLength2, TMWDIAG_ID_RX);

#if TMWCNFG_SUPPORT_CRYPTO_AESGMAC
      if(dnpauth_methodToTMWMacAlgo(pAuthInfo->keyChangeMethod) == TMWCRYPTO_ALG_MAC_AESGMAC)
        /* Set the init vector back to empty */
        tmwcrypto_setIVector(pSDNPSession->dnp.pCryptoHandle, &updateKey, TMWDEFS_NULL, 0); 
#endif
    }

    if(status)
    {
      if(memcmp(pValue2, &pRxFragment->pMsgBuf[pRxFragment->offset], bytesInObject))
      {
        DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_BADMAC);
        status = TMWDEFS_FALSE;
      }
    }
  }
  
  if(status)
  {
    /* start using new update key now */
    tmwcrypto_commitKey(pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_USER_UPDATE_KEY, (void*)pAuthInfo->currentUserNumber, TMWDEFS_TRUE);
    pUserContext->keyWrapAlgorithm = tmwcrypto_getAlgorithm(pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_USER_UPDATE_KEY, (void*)pAuthInfo->currentUserNumber);
    _authSecStatIncrement(pSDNPSession, DNPAUTH_SUCCESS_AUTHENT_INDEX);
  }
  else
  {
    /* discard this tentative update key */
    DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_UPDATE_FAILED);
    tmwcrypto_commitKey(pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_USER_UPDATE_KEY, (void*)pAuthInfo->currentUserNumber, TMWDEFS_FALSE); 

    /* After return from this function, Error Response will be sent. */
  }

  DNPDIAG_SHOW_AUTH_UPDATEKEYCHGCONF((TMWSESN*)pSDNPSession, pAuthInfo->currentUserNumber, status, TMWDIAG_ID_RX);
  sdnpdata_authLogRx(pSDNPSession->pDbHandle, 15, pAuthInfo->currentUserNumber, 0, pRxFragment->pMsgBuf, pRxFragment->msgLength); 

  pRxFragment->offset += bytesInObject;
  
  return(status);
} 
#endif /* DNPCNFG_SUPPORT_AUTHKEYUPDATE   */


TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpsa_addUser( 
  SDNPAUTH_INFO *pAuthInfo,
  TMWTYPES_USHORT userNumber)
{
  SDNPAUTH_USER *pUserContext;

  /* Make sure user number does not yet exist */
  pUserContext = _findUserContext(pAuthInfo, userNumber);
  if(pUserContext == TMWDEFS_NULL)
  {
    pUserContext = (SDNPAUTH_USER *)sdnpmem_alloc(SDNPMEM_AUTH_USER_TYPE);
    if(pUserContext != TMWDEFS_NULL)
    {  
      DNPSESN *pDNPSession = (DNPSESN*)pAuthInfo->pSession;
      pUserContext->userNumber = userNumber;
      pUserContext->keyWrapAlgorithm = tmwcrypto_getAlgorithm(pDNPSession->pCryptoHandle, TMWCRYPTO_USER_UPDATE_KEY, (void*)userNumber);
      pUserContext->keyStatus = DNPAUTH_KEY_NOTINIT;
      pUserContext->lastKeyStatusLength = 0;
      pUserContext->lastKeyChangeLength = 0;

      /* Session keys will be received from master in g120v6 */
      pUserContext->monitorSessionKeyExists = TMWDEFS_FALSE;

      pUserContext->pAuthInfo = pAuthInfo;
      pUserContext->keyChangeCount = 0;
      pUserContext->sessionKeyStatusCount = 0;

      /* key change timer and count */
      tmwtimer_init(&pUserContext->expectedSessionKeyTimer);  

      tmwdlist_addEntry(&pAuthInfo->authContexts, (TMWDLIST_MEMBER *)pUserContext);

      return TMWDEFS_TRUE;
    }
  }
  return TMWDEFS_FALSE;
}

TMWTYPES_USHORT TMWDEFS_GLOBAL sdnpsa_getUser( 
  SDNPAUTH_INFO *pAuthInfo,
  TMWTYPES_USHORT index)
{
  TMWTYPES_USHORT count = 0;
  SDNPAUTH_USER *pUserContext = TMWDEFS_NULL;
  while((pUserContext = (SDNPAUTH_USER *)tmwdlist_getAfter(
    &pAuthInfo->authContexts, (TMWDLIST_MEMBER *)pUserContext)) != TMWDEFS_NULL)
  {   
    if(count == index)
    { 
      return pUserContext->userNumber;
    }
    count++;
  }
  return 0;
}

TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpsa_removeUser( 
  SDNPAUTH_INFO *pAuthInfo,
  TMWTYPES_USHORT userNumber)
{
  SDNPAUTH_USER *pUserContext = TMWDEFS_NULL;

  /* Don't allow default user to be removed */
  if(userNumber == 1)
    return TMWDEFS_FALSE;

  while((pUserContext = (SDNPAUTH_USER *)tmwdlist_getAfter(
    &pAuthInfo->authContexts, (TMWDLIST_MEMBER *)pUserContext)) != TMWDEFS_NULL)
  {   
    if(pUserContext->userNumber == userNumber)
    { 
      tmwtimer_cancel(&pUserContext->expectedSessionKeyTimer);  

      tmwdlist_removeEntry(&pAuthInfo->authContexts, (TMWDLIST_MEMBER *)pUserContext);
      sdnpmem_free(pUserContext);
      return TMWDEFS_TRUE;
    }
  }
  return TMWDEFS_FALSE;
}

void TMWDEFS_GLOBAL sdnpsa_getConfig(
  void *pInfo,
  SDNPSESN_AUTH_CONFIG *pConfig)
{
  SDNPAUTH_INFO *pAuthInfo = (SDNPAUTH_INFO *)pInfo;
  if(pAuthInfo != TMWDEFS_NULL)
  {
    SDNPSESN *pSDNPSession = (SDNPSESN*)pAuthInfo->pSession;

    pConfig->operateInV2Mode            = TMWDEFS_FALSE;
    pConfig->assocId                    = pAuthInfo->assocId;
    pConfig->MACAlgorithm               = pAuthInfo->MACAlgorithm;
    pConfig->replyTimeout               = pAuthInfo->replyTimeout;
    pConfig->maxApplTimeoutCount        = pAuthInfo->maxApplTimeoutCount; 
    pConfig->keyChangeInterval          = pAuthInfo->keyChangeInterval;
    pConfig->maxKeyChangeCount          = pAuthInfo->maxKeyChangeCount;
    pConfig->aggressiveModeSupport      = pAuthInfo->aggressiveModeSupport;
    pConfig->disallowSHA1               = pAuthInfo->disallowSHA1;
    pConfig->extraDiags                 = pAuthInfo->extraDiags;
    pConfig->testConfig                 = pAuthInfo->testConfig;
    pConfig->randomChallengeDataLength  = pAuthInfo->randomChallengeDataLength;
    pConfig->maxSessionKeyStatusCount   = pAuthInfo->maxSessionKeyStatusCount;
    pConfig->maxAuthenticationFailures  = pAuthInfo->maxAuthenticationFailures;
    pConfig->maxReplyTimeouts           = pAuthInfo->maxReplyTimeouts;
    pConfig->maxAuthenticationRekeys    = pAuthInfo->maxAuthenticationRekeys;
    pConfig->maxErrorMessagesSent       = pAuthInfo->maxErrorMessagesSent;

    pConfig->authSendAggrResp     = pSDNPSession->authSendAggrResp;
    pConfig->authSendAggrUnsol    = pSDNPSession->authSendAggrUnsol;
    pConfig->preChallengeApplConf = pSDNPSession->preChallengeApplConf;
  }
}

/*
 * sdnpsa_init is only called when authentication is first enabled.
 * sdnpsa_setConfig is called after that and every time config has been modified.
 */
void TMWDEFS_GLOBAL sdnpsa_setConfig(
  void *pInfo,
  const SDNPSESN_AUTH_CONFIG *pConfig)
{
  SDNPAUTH_INFO *pAuthInfo;
  SDNPSESN *pSDNPSession;

  pAuthInfo = (SDNPAUTH_INFO *)pInfo;
  pSDNPSession = (SDNPSESN*)pAuthInfo->pSession;

  pAuthInfo->assocId = pConfig->assocId;
  pAuthInfo->MACAlgorithm = pConfig->MACAlgorithm;
  pAuthInfo->replyTimeout = pConfig->replyTimeout;
  pAuthInfo->maxApplTimeoutCount = pConfig->maxApplTimeoutCount;
  pAuthInfo->keyChangeInterval = pConfig->keyChangeInterval;
  pAuthInfo->maxKeyChangeCount = pConfig->maxKeyChangeCount;
  pAuthInfo->aggressiveModeSupport = pConfig->aggressiveModeSupport;
  pAuthInfo->disallowSHA1 = pConfig->disallowSHA1;
  pAuthInfo->extraDiags = pConfig->extraDiags;
  pAuthInfo->testConfig = pConfig->testConfig;
  pAuthInfo->randomChallengeDataLength = pConfig->randomChallengeDataLength;
  /* According to TB2016-002 4-64 */
  if (pAuthInfo->randomChallengeDataLength < DNPAUTH_MIN_CHALLENGE_DATA)
    pAuthInfo->randomChallengeDataLength = DNPAUTH_MIN_CHALLENGE_DATA;
  if (pAuthInfo->randomChallengeDataLength > DNPAUTH_MAX_CHALLENGE_DATA)
    pAuthInfo->randomChallengeDataLength = DNPAUTH_MAX_CHALLENGE_DATA;
  pAuthInfo->maxSessionKeyStatusCount = pConfig->maxSessionKeyStatusCount;
  pAuthInfo->maxAuthenticationFailures = pConfig->maxAuthenticationFailures;
  pAuthInfo->maxReplyTimeouts = pConfig->maxReplyTimeouts;
  pAuthInfo->maxAuthenticationRekeys = pConfig->maxAuthenticationRekeys;
  pAuthInfo->maxErrorMessagesSent = pConfig->maxErrorMessagesSent;

  pSDNPSession->authSendAggrResp = pConfig->authSendAggrResp;
  pSDNPSession->authSendAggrUnsol = pConfig->authSendAggrUnsol;
  pSDNPSession->preChallengeApplConf = pConfig->preChallengeApplConf;
   
  /* set statistics and thresholds according to database values */
  _adjustStatsAndThresholds(pAuthInfo);
}

/* function: sdnpsa_init */
/*
 * sdnpsa_init is only called when authentication is first enabled.
 * sdnpsa_setConfig is called after that and every time config has been modified.
 */
SDNPAUTH_INFO * TMWDEFS_GLOBAL sdnpsa_init(
  SDNPSESN *pSDNPSession,
  const SDNPSESN_AUTH_CONFIG *pConfig)
{  
  int i;
  SDNPAUTH_INFO *pAuthInfo = (SDNPAUTH_INFO *)sdnpmem_alloc(SDNPMEM_AUTH_INFO_TYPE);
  if(pAuthInfo != TMWDEFS_NULL)
  { 
    pSDNPSession->dnp.pCryptoHandle = tmwcrypto_init(pSDNPSession->dnp.pUserHandle); 
    if(pSDNPSession->dnp.pCryptoHandle == TMWDEFS_NULL)
      return TMWDEFS_NULL;


#if TMW_PRIVATE_AUTHTEST
    sdnpauthtest_init(pAuthInfo);  
#endif

    pAuthInfo->pSession = (TMWSESN*)pSDNPSession;
    pAuthInfo->state = SDNPAUTH_STATE_IDLE;
    pAuthInfo->currentUserNumber = 0; 

#if DNPCNFG_SUPPORT_AUTHKEYUPDATE
    pAuthInfo->lastSCS = 0;
#endif

    pAuthInfo->rcvdAtLeastOneChallengeResponse = TMWDEFS_FALSE;

    pAuthInfo->lastChallengeRcvdLength  = 0;
    pAuthInfo->aggressiveModeTxSequence = 0;
    pAuthInfo->aggressiveModeRcvd       = 0;
    pAuthInfo->applTimeoutCount         = 0;

    pAuthInfo->keyChangeSequenceNumber  = 0; 
#if TMWCNFG_SUPPORT_CRYPTO_AESGMAC
    /* Persist this according to SAV5 4.2.1.1 if AES-GMAC is supported 
     * How can we know if master is going to tell us to use AES-GMAC?
     */
    sdnpdata_authGetKSQ(pSDNPSession->pDbHandle, &pAuthInfo->keyChangeSequenceNumber);
#endif

    pAuthInfo->challengeSequenceNumber  = 0; 
    pAuthInfo->lastChallengeSentLength  = 0; 
    pAuthInfo->lastUnsolCSQSent         = 0;
    pAuthInfo->lastCSQSent              = 0;

#if DNPCNFG_SUPPORT_AUTHKEYUPDATE
    pAuthInfo->masterChallengeDataLength = 0;
    pAuthInfo->outstationChallengeDataLength = 0;
 
    pAuthInfo->outstationNameLength = 0;
#endif
     
    /* Initialize statistics */ 
    for (i = 0; i < DNPAUTH_NUMBER_STATISTICS; i++)
    {
      pAuthInfo->statistic[i] = 0;
    }

    /* Statistics must be persistent over restart. 
     * They will be loaded from database in setconfig if the database is available
     * Otherwise they will be loaded when first statistic is incremented.
     */
    pAuthInfo->statsLoaded = TMWDEFS_FALSE;

    /* reply timer */
    tmwtimer_init(&pAuthInfo->replyTimer);
    pAuthInfo->replyTimeout = pConfig->replyTimeout;

    pAuthInfo->extraDiags = pConfig->extraDiags;
    pAuthInfo->testConfig = pConfig->testConfig;
     
    /* Init this to zero so we can tell there is no pending request */
    pAuthInfo->pendingRequest.msgLength = 0;

    /* List of authentication contexts */
    tmwdlist_initialize(&pAuthInfo->authContexts);
  }
  return(pAuthInfo);
}

/* function: sdnpsa_close */
void TMWDEFS_GLOBAL sdnpsa_close(
  void *pInfo)
{
  SDNPAUTH_USER *pUserContext;
  SDNPAUTH_INFO *pAuthInfo = (SDNPAUTH_INFO*)pInfo;

  /* cancel all authentication timers */
  tmwtimer_cancel(&pAuthInfo->replyTimer); 
   
  /* deallocate all user contexts, */
  while((pUserContext = (SDNPAUTH_USER *)tmwdlist_getFirst(&pAuthInfo->authContexts)) != TMWDEFS_NULL)
  { 
    /* Remove user context from list */
    tmwdlist_removeEntry(&pAuthInfo->authContexts, (TMWDLIST_MEMBER *)pUserContext);

    tmwtimer_cancel(&pUserContext->expectedSessionKeyTimer); 

    sdnpmem_free(pUserContext);
  }

#if TMW_PRIVATE_AUTHTEST
    sdnpauthtest_close(pAuthInfo);  
#endif

  sdnpmem_free(pAuthInfo);
} 

/* function: sdnpsa_getKeyStatus */
TMWTYPES_UCHAR TMWDEFS_GLOBAL sdnpsa_getKeyStatus(
  TMWSESN *pSession,
  TMWTYPES_USHORT userNumber)
{
  SDNPSESN *pSDNPSession = (SDNPSESN *)pSession;
  SDNPAUTH_INFO *pAuthInfo = (SDNPAUTH_INFO*)pSDNPSession->pAuthenticationInfo;
  if (pAuthInfo != TMWDEFS_NULL)
  {
    SDNPAUTH_USER *pUserContext = _findUserContext(pAuthInfo, userNumber);
    if (pUserContext != TMWDEFS_NULL)
    {
      return(pUserContext->keyStatus);
    }
  }
  return 0;
}

/* function: sdnpsa_resetLastSCS */
TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpsa_resetLastSCS(
   TMWSESN *pSession)
{ 
  SDNPSESN *pSDNPSession = (SDNPSESN *)pSession;
  SDNPAUTH_INFO *pAuthInfo = (SDNPAUTH_INFO*)pSDNPSession->pAuthenticationInfo;
  if(pAuthInfo != TMWDEFS_NULL)
  {
#if DNPCNFG_SUPPORT_AUTHKEYUPDATE
    pAuthInfo->lastSCS = 0;
    return TMWDEFS_TRUE;
#endif
  }
  return TMWDEFS_FALSE;
}

/* function: _savePendingRequest */
static void TMWDEFS_LOCAL _savePendingRequest(
  TMWSESN_RX_DATA *pRxFragment, 
  SDNPAUTH_INFO *pAuthInfo,
  TMWTYPES_UCHAR fc)
{
  pAuthInfo->pendingRequest = *pRxFragment;
  pAuthInfo->pendingRequest.pMsgBuf = pAuthInfo->pendingData;
  pAuthInfo->pendingRequestFc = fc;
  memcpy(pAuthInfo->pendingRequest.pMsgBuf, pRxFragment->pMsgBuf, pRxFragment->msgLength);
}

/* function: _discardPendingRequest */
static void TMWDEFS_LOCAL _discardPendingRequest(
  SDNPAUTH_INFO *pAuthInfo,
  TMWTYPES_ULONG event)
{
  pAuthInfo->pendingRequest.msgLength = 0;
  pAuthInfo->state = SDNPAUTH_STATE_IDLE;
  _authSecStatIncrement((SDNPSESN*)pAuthInfo->pSession, DNPAUTH_DISCARDED_MSG_INDEX); 
  SDNPDIAG_AUTHDISCARDPENDING(pAuthInfo->pSession, event);
}

#ifdef TMW_SUPPORT_MONITOR
/* function: _monitorProcessing */
static TMWSESN_RX_DATA * TMWDEFS_LOCAL _monitorProcessing(
  TMWSESN *pSession,
  TMWSESN_RX_DATA *pRxFragment)
{ 
  TMWTYPES_ULONG sequence;
  TMWTYPES_USHORT userNumber;
  TMWTYPES_UCHAR errorCode;
  SDNPAUTH_RX_MSG rxMsg;   
  DNPAUTH_OBJECT_HEADER hdr; 
  
  if(pRxFragment == TMWDEFS_NULL)
    return TMWDEFS_NULL;

  /* Application Confirm, or invalid formatted message */
  if(pRxFragment->msgLength <= 2)
    return(pRxFragment);
 
  _parseApplHeader(pRxFragment, &rxMsg);
  if(!_parseObjectHeader(&rxMsg, &hdr))
    return TMWDEFS_NULL;
     
  if(DNPDEFS_OBJ_120_AUTHENTICATION == hdr.group)
  {
    SDNPAUTH_INFO *pAuthInfo; 
    SDNPAUTH_USER *pUserContext;
    DNPDIAG_SHOW_AUTH_HEADER(pSession, &hdr);
 
    if(!_getUserAndSequence(&rxMsg, hdr.variation, &sequence, &userNumber))
    {
      return TMWDEFS_NULL;
    }
    pAuthInfo = _getAuthInfo((SDNPSESN*)pSession); 
    pUserContext = _findUserContext(pAuthInfo, userNumber); 
    switch(hdr.variation) 
    {
    case 1:
      _processChallengeRequestV1((SDNPSESN*)pSession, &rxMsg, pUserContext); 
      pRxFragment = TMWDEFS_NULL;
      break;

    case 2:
      _processChallengeReplyV2((SDNPSESN*)pSession, &rxMsg, pUserContext);
      pRxFragment = TMWDEFS_NULL;
      break;

    case 3: 
      _processAggrModeRequestV3((SDNPSESN*)pSession, &rxMsg, pUserContext); 

      /* Skip over the aggressive mode request object at the beginning of message 
       * _processAggrModeRequestV3() removed object from end of message already.
       * Moving the original application control byte and the function code to the
       * beginning of the message makes normal DNP processing simpler and more efficient
       */ 
      pRxFragment->pMsgBuf[DNPAUTH_OBJ120V3_SIZE]   = pRxFragment->pMsgBuf[DNPDEFS_AH_INDEX_APPL_CTRL];
      pRxFragment->pMsgBuf[DNPAUTH_OBJ120V3_SIZE+1] = pRxFragment->pMsgBuf[DNPDEFS_AH_INDEX_FUNC_CODE];
      pRxFragment->pMsgBuf += DNPAUTH_OBJ120V3_SIZE;
      pRxFragment->msgLength = rxMsg.msgLength-DNPAUTH_OBJ120V3_SIZE;
      break;

    case 4:
      _processKeyStatusRequestV4((SDNPSESN*)pSession, &rxMsg, pUserContext); 
      pRxFragment = TMWDEFS_NULL;
      break;

    case 6:
      _processKeyChangeRequestV6((SDNPSESN*)pSession, &rxMsg, pUserContext); 
      pRxFragment = TMWDEFS_NULL;
      break;

    case 7:
      _processErrorRequestV7((SDNPSESN*)pSession, &rxMsg, &errorCode); 
      pRxFragment = TMWDEFS_NULL;
      break;
 
#if DNPCNFG_SUPPORT_AUTHKEYUPDATE 
#if SDNPDATA_SUPPORT_OBJ120_V8
    case 8: 
      _processUserCertificateV8((SDNPSESN*)pSession, &rxMsg); 
      pRxFragment = TMWDEFS_NULL;
      break;
#endif

    case 10:
      _processUserStatusChangeV10((SDNPSESN*)pSession, &rxMsg); 
      pRxFragment = TMWDEFS_NULL;
      break;

    case 11:
      _processUpdateKeyChangeReqV11((SDNPSESN*)pSession, &rxMsg);
      pRxFragment = TMWDEFS_NULL;
      break;
        
    case 13:
      _processUpdateKeyChangeV13((SDNPSESN*)pSession, &rxMsg); 
      pRxFragment = TMWDEFS_NULL;
      break;

    case 15:  
      _processUpdateKeyChangeConfV15((SDNPSESN*)pSession, &rxMsg); 
      pRxFragment = TMWDEFS_NULL;
      break;
#endif
     
    default:
      /* invalid variation */
      break;
    }
  } 
      
  return(pRxFragment);
}
#endif


static void TMWDEFS_LOCAL _setAllUsersKeyStatus(SDNPAUTH_INFO *pAuthInfo, TMWTYPES_UCHAR status)
{ 
  SDNPAUTH_USER *pUserContext = TMWDEFS_NULL;
  while((pUserContext = (SDNPAUTH_USER *)tmwdlist_getAfter(
    &pAuthInfo->authContexts, (TMWDLIST_MEMBER *)pUserContext)) != TMWDEFS_NULL)
  { 
    pUserContext->keyStatus = status;
  }
}

/* function: sdnpsa_applTimeout
 * purpose: 
 * arguments:    
 * returns:    
 *  void
 */  
void TMWDEFS_GLOBAL sdnpsa_applTimeout(
  SDNPSESN *pSDNPSession)
{
  SDNPAUTH_INFO *pAuthInfo = _getAuthInfo(pSDNPSession); 
  if(pAuthInfo != TMWDEFS_NULL)
  { 
    DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN *)pSDNPSession, DNPDIAG_AUTH_APPLTIMEOUT);

    /* If application response times out, allow for configured value of these before calling it a COMM_FAIL */ 
    pAuthInfo->applTimeoutCount++;
    if(pAuthInfo->applTimeoutCount > pAuthInfo->maxApplTimeoutCount)
    {
      sdnpsa_processing((TMWSESN *)pSDNPSession, SDNPAUTH_EVT_COMMFAILUREDETECTED, 0, TMWDEFS_NULL);
      pAuthInfo->applTimeoutCount = 0;
    }
  }
}
 
/* function: sdnpsa_applConfirm
 * purpose: 
 * arguments:    
 * returns:    
 *  void
 */  
void TMWDEFS_GLOBAL sdnpsa_applConfirm(
  SDNPSESN *pSDNPSession)
{
  SDNPAUTH_INFO *pAuthInfo = _getAuthInfo(pSDNPSession); 
  if(pAuthInfo != TMWDEFS_NULL)
    pAuthInfo->applTimeoutCount = 0;
}

/* function: _setKeyStatus */
static void TMWDEFS_LOCAL _setKeyStatus(SDNPAUTH_USER *pUserContext,
  TMWTYPES_UCHAR status)
{
  if (pUserContext != TMWDEFS_NULL)
    pUserContext->keyStatus = status;
}

/* This returns TMWDEFS_NULL if processing of this message is complete  
 * (a challenge request might have been sent back to master)
 * and the request queued for later processing.
 */
TMWSESN_RX_DATA *sdnpsa_processing(
  TMWSESN *pSession,
  TMWTYPES_ULONG event,
  TMWTYPES_USHORT userNumber,
  TMWSESN_RX_DATA *pRxFragment)
{
  SDNPAUTH_INFO *pAuthInfo; 
  TMWTYPES_ULONG sequenceNumber; 
  TMWTYPES_ULONG authentFailuresStat;
  TMWTYPES_UCHAR errorCode;
  SDNPAUTH_RX_MSG rxMsg;   
  DNPAUTH_OBJECT_HEADER hdr;
  TMWTYPES_BOOL userNumberRcvd = TMWDEFS_FALSE;
  SDNPAUTH_USER *pUserContext = TMWDEFS_NULL;
  SDNPSESN *pSDNPSession = (SDNPSESN *)pSession;

#ifdef TMW_SUPPORT_MONITOR
  if(pSession->pChannel->pPhysContext->monitorMode)
  {
    return(_monitorProcessing(pSession, pRxFragment));   
  }
#endif

  pAuthInfo = _getAuthInfo(pSDNPSession); 
 
#if TMW_PRIVATE_AUTHTEST 
  if(sdnpauthtest_testing(pSession, pAuthInfo, event, userNumber, pRxFragment))
    return TMWDEFS_NULL;
#endif

  /* init variable to legal but easily noticeable value.
   */
  sequenceNumber = 0xffff;

  /* init these to prevent warnings */
  rxMsg.fc = 0;
  rxMsg.ac = 0;
 
  /* This could be processing a received message, or another event such as a timeout
   * first check to see if it is a received message.
   */
  if(event == SDNPAUTH_EVT_MSG_RECEIVED) 
  {  
    /* Invalid formatted message */
    if(pRxFragment->msgLength < 2)
      return(pRxFragment);

    _parseApplHeader(pRxFragment, &rxMsg);
    _authSecStatIncrement(pSDNPSession, DNPAUTH_TOTAL_MSG_RCVD_INDEX);

    /* confirms without aggressive mode data can be skipped */
    if(rxMsg.msgLength > 2) 
    {
      if(!_parseObjectHeader(&rxMsg, &hdr))
        return TMWDEFS_NULL;
       
      if(DNPDEFS_OBJ_120_AUTHENTICATION == hdr.group)
      {
        DNPDIAG_SHOW_AUTH_HEADER(pSession, &hdr); 
        if(!_getUserAndSequence(&rxMsg, hdr.variation, &sequenceNumber, &userNumber))
        {
          return TMWDEFS_NULL;
        }
        userNumberRcvd = TMWDEFS_TRUE;
        switch(hdr.variation)
        {
        case 1: 
          /* Include UNSOL bit with sequence number */
          pAuthInfo->applSequenceNumber = (TMWTYPES_UCHAR)(rxMsg.ac & 0x1f);
          event = SDNPAUTH_EVT_CHALLENGE;
          break;

        case 2:
          event = SDNPAUTH_EVT_CHALLENGE_REPLY;
          break;

        case 3:
          pAuthInfo->applSequenceNumber = (TMWTYPES_UCHAR)(rxMsg.ac & DNPDEFS_AC_SEQUENCE_MASK);
          event = SDNPAUTH_EVT_AGGRESSIVE_MODE;
          break;

        case 4: 
          pAuthInfo->applSequenceNumber = (TMWTYPES_UCHAR)(rxMsg.ac & DNPDEFS_AC_SEQUENCE_MASK);
          event = SDNPAUTH_EVT_KEYSTATUSREQ;
          break;

        case 6: 
          pAuthInfo->applSequenceNumber = (TMWTYPES_UCHAR)(rxMsg.ac & DNPDEFS_AC_SEQUENCE_MASK);
          event = SDNPAUTH_EVT_KEYCHANGEREQ;
          break;

        case 7:
          /* This is the only valid function code for an error sent from the master. 
           * If it is a read error event request, pass it to the normal protocol stack
           */
          if(rxMsg.fc == DNPDEFS_FC_AUTH_REQUEST_NOACK)
          {
            event = SDNPAUTH_EVT_ERRORREQ;
          }
          else if(rxMsg.fc != DNPDEFS_FC_READ)
          {
            DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_RXBADMSG);  
            return TMWDEFS_NULL;
          }
          break;

#if DNPCNFG_SUPPORT_AUTHKEYUPDATE
#if SDNPDATA_SUPPORT_OBJ120_V8
        case 8:  
          /* Received User Certificate message */
          /* Handle this here since it is state machine independent */
          pAuthInfo->applSequenceNumber = (TMWTYPES_UCHAR)(rxMsg.ac & DNPDEFS_AC_SEQUENCE_MASK);
          event = SDNPAUTH_EVT_USERCERT_RCVD;
          _processUserCertificateV8((SDNPSESN*)pSession, &rxMsg); 
          
          return(TMWDEFS_NULL); 
          /* break if no return */
#endif

        case 10:
          /* Received User Status Change message */
          /* Handle this here since it is state machine independent */
          pAuthInfo->applSequenceNumber = (TMWTYPES_UCHAR)(rxMsg.ac & DNPDEFS_AC_SEQUENCE_MASK);
          event = SDNPAUTH_EVT_USERSTATUS_RCVD;
          _processUserStatusChangeV10((SDNPSESN*)pSession, &rxMsg); 
          
          return(TMWDEFS_NULL); 
          /* break if no return */
 
        case 11:
          /* Received User Status Change message */
          /* Handle this here since it is state machine independent */
          pAuthInfo->applSequenceNumber = (TMWTYPES_UCHAR)(rxMsg.ac & DNPDEFS_AC_SEQUENCE_MASK);
          event = SDNPAUTH_EVT_UPDKEYCHGREQ_RCVD; 
          if(_processUpdateKeyChangeReqV11((SDNPSESN*)pSession, &rxMsg))
          {
            /* send back a v12 */
            _sendUpdateKeyChangeReplyV12((SDNPSESN*)pSession, rxMsg.rxAddress);
          }

          return(TMWDEFS_NULL); 
          /* break if no return */
        
        case 13:
          /* Received User Status Change message */
          /* Handle this here since it is state machine independent */
          {
            pAuthInfo->applSequenceNumber = (TMWTYPES_UCHAR)(rxMsg.ac & DNPDEFS_AC_SEQUENCE_MASK);

            event = SDNPAUTH_EVT_UPDKEYCHG_RCVD; 

            errorCode = _processUpdateKeyChangeV13((SDNPSESN*)pSession, &rxMsg); 
            /* If the v13 portion was valid */
            if(errorCode == DNPAUTH_ERROR_NONE)
            {
              /* This should be followed by a v14 if asymmetric or v15 if symmetric */
              if(!_parseObjectHeader(&rxMsg, &hdr))
                return(TMWDEFS_NULL); 

              if(hdr.variation == 14)
              {
                DNPDIAG_SHOW_AUTH_HEADER(pSession, &hdr);
#if DNPCNFG_SUPPORT_AUTHKEYUPDASYM
                if (!_processUpdKeyChangeSigV14((SDNPSESN*)pSession, &rxMsg))
                {
                  errorCode = DNPAUTH_ERROR_INVALIDSIG;
                }
  #endif
              }
              else if(hdr.variation == 15)
              {
                DNPDIAG_SHOW_AUTH_HEADER(pSession, &hdr);
                if (!_processUpdateKeyChangeConfV15((SDNPSESN*)pSession, &rxMsg))
                {
                  errorCode = DNPAUTH_ERROR_INVALIDCERTDATA;
                }
              }
              else
              {
                errorCode = DNPAUTH_ERROR_AUTHENTFAILED;
              }
              
              if(errorCode == DNPAUTH_ERROR_NONE)
              {
                /* success */
                _authSecStatIncrement(pSDNPSession, DNPAUTH_UPDKEY_CHANGE_INDEX); 

                _sendUpdateKeyChangeConfV15((SDNPSESN*)pSession, rxMsg.rxAddress);  
              }
              /* else handled by if(errorCode != DNPAUTH_ERROR_NONE) */
            }
            if(errorCode != DNPAUTH_ERROR_NONE)
            {
              /* failure */
              /* TMW-not in spec */
              _authSecStatIncrement(pSDNPSession, DNPAUTH_FAILUPDKEY_CHANGE_INDEX); 
              sdnpsa_sendErrorResponseV7(pSDNPSession, pRxFragment->rxAddress, pAuthInfo->keyChangeSequenceNumber, 
                pAuthInfo->currentUserNumber, errorCode, TMWDEFS_NULL, 0);
            }
            return(TMWDEFS_NULL);
          } 
          /* break if no return */

        case 15: 
          if(!_processUpdateKeyChangeConfV15((SDNPSESN*)pSession, &rxMsg))
          { 
            /* failure */

            /* TMW-not in spec */
            _authSecStatIncrement(pSDNPSession, DNPAUTH_FAILUPDKEY_CHANGE_INDEX);

            /* Not in Spec, but in DNP SA Conformance Tests*/
            _authSecStatIncrement(pSDNPSession, DNPAUTH_DISCARDED_MSG_INDEX);

            sdnpsa_sendErrorResponseV7(pSDNPSession, pRxFragment->rxAddress, pAuthInfo->keyChangeSequenceNumber, 
              pAuthInfo->currentUserNumber, DNPAUTH_ERROR_AUTHENTFAILED, TMWDEFS_NULL, 0);
          }
          else
          { 
            _sendUpdateKeyChangeConfV15((SDNPSESN*)pSession, rxMsg.rxAddress);  
          }
          return(TMWDEFS_NULL);
          /* break if no return */
#endif

        default:
          userNumberRcvd = TMWDEFS_FALSE;
          /* invalid variation */
          break;
        }
        
        /* v10-v15 don't really need to be counted for determining when session keys should be changed. */
        _authMsgReceived(pAuthInfo, hdr.variation, userNumber);
      }
    }

    /* Check to see if this is an aggressive mode broadcast message */
    if((event == SDNPAUTH_EVT_AGGRESSIVE_MODE) && (pRxFragment->isBroadcast))
    {
      /* discard aggressive broadcast messages, because they will not work properly. */
      SDNPDIAG_ERROR(pAuthInfo->pSession->pChannel, pAuthInfo->pSession, SDNPDIAG_AUTH_BROAD_DISC);
      return(TMWDEFS_NULL);
    }

    /* if event has not been determined yet */
    if(event == SDNPAUTH_EVT_MSG_RECEIVED)
    {
      if (rxMsg.fc == DNPDEFS_FC_CONFIRM && pSDNPSession->preChallengeApplConf && pSDNPSession->unsolInitialNullConfirmed)
      {
        /* Discard application confirm that was not sent aggressive mode as requested.
         * 1815-2012 7.5.2.3.2 bullets e,f,g
         * SAv5 does not allow Initial Null UR with a prechallenge (bullet h).
         */
        SDNPDIAG_ERROR(pAuthInfo->pSession->pChannel, pAuthInfo->pSession, SDNPDIAG_AUTH_NOT_AGGR);
        return(TMWDEFS_NULL);
      }

      /* See if it is a critical message */
      rxMsg.offset = 2;
      if(sdnpdata_authIsCriticalReq(pSDNPSession->pDbHandle, rxMsg.fc, rxMsg.pMsgBuf, rxMsg.msgLength)) 
      { 
        if(pRxFragment->isBroadcast)
        {
          /* discard critical broadcast messages, because we cannot challenge them. */
          SDNPDIAG_ERROR(pAuthInfo->pSession->pChannel, pAuthInfo->pSession, SDNPDIAG_AUTH_BROAD_DISC);
          return(TMWDEFS_NULL);
        }

        pAuthInfo->applSequenceNumber = (TMWTYPES_UCHAR)(rxMsg.ac & DNPDEFS_AC_SEQUENCE_MASK);
        event = SDNPAUTH_EVT_CRITICAL_RCVD;
        
        _authSecStatIncrement(pSDNPSession, DNPAUTH_CRIT_MSG_RCVD_INDEX);
      }
      else
      {
        event = SDNPAUTH_EVT_NONCRITICAL_RCVD;
      }
    }
  }
  else
  {
    /* an event such as a timeout, not a received message was passed in */
    rxMsg.msgLength = 0;
    rxMsg.offset = 0;
  }
 
  /* if the error reply was because of a challenge it would have user number 0, process it */
  /* Also, if key status request has an unknown user number send a key status with AUTH FAIL */
  /* Also, DNP SA Conformance Tests require sending error response to g120v1 challenge with bad user number */
  pUserContext = _findUserContext(pAuthInfo, userNumber);
  if(userNumberRcvd && (pUserContext == TMWDEFS_NULL) && ((event != SDNPAUTH_EVT_ERRORREQ) && (event != SDNPAUTH_EVT_KEYSTATUSREQ) && (event != SDNPAUTH_EVT_CHALLENGE)))
  {
    DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_BADUSER);
    _unexpectedMsgRcvd(pSDNPSession, pAuthInfo->state, event, pRxFragment);  

    /* return here, so NULL pUserContext will not be used below if master sends us a
     * an unconfigured user number
     */
    return TMWDEFS_NULL;
  }

  SDNPDIAG_AUTHEVENT((TMWSESN*)pSDNPSession, pAuthInfo->state, event);

  authentFailuresStat = 0;

  if(pAuthInfo->state == SDNPAUTH_STATE_WAITFORREPLY)
  {
    switch(event)
    {
    case SDNPAUTH_EVT_NONCRITICAL_RCVD:
      /* 1815-2012 Table 7-8 row 2, noncritical
       * Increment the Unexpected Messages statistic.  
       * Log the occurrence.
       * Discard the new Non-Critical ASDU.
       * Increment the Discarded Messages statistic. 
       * TMW-If unsolicited application confirm allow it.
       */ 
      if((rxMsg.msgLength == 2) 
        && ((rxMsg.ac & DNPDEFS_AC_UNSOLICITED) == DNPDEFS_AC_UNSOLICITED))
      { 
        return(pRxFragment);
      }

      _unexpectedMsgRcvd(pSDNPSession, pAuthInfo->state, event, pRxFragment); 
      break;

    case SDNPAUTH_EVT_CRITICAL_RCVD:
      /* 1815-2012 Table 7-8 row 3, critical,
       * Increment the Critical Messages Received statistic 
       * Increment the Unexpected Messages statistic. 
       * Log the occurrence.
       * Discard the new Critical ASDU.
       * Increment the Discarded Messages statistic. 
       */ 

      /* CRIT_MSG_RCVD incremented where detected above */
      _unexpectedMsgRcvd(pSDNPSession, pAuthInfo->state, event, pRxFragment); 
      break; 

      /* no row 4 on outstation */

    case SDNPAUTH_EVT_CHALLENGE_REPLY:
      /* 1815-2012 Table 7-8, Row 5 and 6
       * if valid, process queued ASDU, 
       *   Cancel reply timer
       *   Reset max reply timeouts
       *   Increment successful authentication stat
       * if invalid, 
       *   Increment Authentications Failures Stat
       *   Cancel the reply timer
       *   Reset max reply timeouts
       *   Discard ASDU that was queued pending authentication 
       *   Increment the Discarded Messages statistic. 
       *   Send error message reason 1 Authentication Failed
       *   If max error message sent exceeded, behave as Max Auth Failures Exceeded below
       * TMW-User number for this event, but do not check it, authentication would fail if wrong...
       */
      tmwtimer_cancel(&pAuthInfo->replyTimer);
      pAuthInfo->state = SDNPAUTH_STATE_IDLE; 
 
      _resetSecStatMaxValue(pSDNPSession, SDNPAUTH_REPLY_TIMEOUT_MAX_INDEX); 

      if(_processChallengeReplyV2(pSDNPSession, &rxMsg, pUserContext))
      {      
        pAuthInfo->rcvdAtLeastOneChallengeResponse = TMWDEFS_TRUE; 
        if(pAuthInfo->pendingRequest.msgLength > 0)
        {
          _authSecStatIncrement(pSDNPSession, DNPAUTH_SUCCESS_AUTHENT_INDEX); 
          /* ask database if this user is allowed to issue this request */  
          if(sdnpdata_authRequestAllowed(pSDNPSession->pDbHandle, userNumber, pAuthInfo->pendingRequestFc, pAuthInfo->pendingRequest.pMsgBuf, pAuthInfo->pendingRequest.msgLength))
          {
            return(&pAuthInfo->pendingRequest);
          }
          else
          { 
            SDNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, SDNPDIAG_AUTH_AUTHORFAIL);
            _discardPendingRequest(pAuthInfo, SDNPAUTH_EVT_CHALLENGE_REPLY); 
            _authSecStatIncrement(pSDNPSession, DNPAUTH_AUTHOR_FAIL_INDEX);
            sdnpsa_sendErrorResponseV7(pSDNPSession, pRxFragment->rxAddress, pAuthInfo->challengeSequenceNumber, userNumber, DNPAUTH_ERROR_AUTHORFAILED, TMWDEFS_NULL, 0);
          }
        }
      } 
      else
      {
        /* row 6 Invalid Challenge Reply */

        /* This will set state to idle */
        _discardPendingRequest(pAuthInfo, SDNPAUTH_EVT_CHALLENGE_REPLY);

        sdnpsa_sendErrorResponseV7(pSDNPSession, pRxFragment->rxAddress, pAuthInfo->challengeSequenceNumber, userNumber, DNPAUTH_ERROR_AUTHENTFAILED, TMWDEFS_NULL, 0);

        /* max authent failures exceeded will be handled below */
        authentFailuresStat = _authSecStatIncrement(pSDNPSession, DNPAUTH_AUTHENT_FAIL_INDEX);
        
        _resetSecStatMaxValue(pSDNPSession, SDNPAUTH_REPLY_TIMEOUT_MAX_INDEX);
      }   
      break; 

    case SDNPAUTH_EVT_REPLYTIMEOUT:
      /* 1815-2012 Table 7-8, Row 7 and part of row 9 
       *   Increment the Reply Timeouts statistic.
       *   Cancel the Reply Timer. TMW-since it timed out, no need to cancel it.
       *   Discard any ASDUs that were queued pending an authentication Reply.
       *   Increment the Discarded Messages statistic
       *   TMW-increment failed authent statistic 
       */
      {
        TMWTYPES_ULONG replyTimeoutsStat = _authSecStatIncrement(pSDNPSession, DNPAUTH_REPLY_TIMEOUT_INDEX); 
        _discardPendingRequest(pAuthInfo, SDNPAUTH_EVT_REPLYTIMEOUT);

        if(replyTimeoutsStat > pAuthInfo->statsMaxValue[SDNPAUTH_REPLY_TIMEOUT_MAX_INDEX])
        {
          /* 1815-2012 Table 7-8, Row 9 */ 
          /* User number is not known when waiting for a challenge reply 
           * Set All keys to COMM FAIL.
           */
          _setAllUsersKeyStatus(pAuthInfo, DNPAUTH_KEY_COMMFAIL);

          _resetSecStatMaxValue(pSDNPSession, SDNPAUTH_REPLY_TIMEOUT_MAX_INDEX);  
        }
      }
      break;

      /* no row 8 on outstation */

    case SDNPAUTH_EVT_COMMFAILUREDETECTED: 
      /* 1815-2012 Table 7-8, Row 9, 
       * Discard ASDU that was queued pending authentication
       * Increment the Discarded Messages statistic
       * set current key status to COMM Fail
       * reset Max Reply Timeouts
       * set state to Idle  
       * affects all users.
       */ 
      _discardPendingRequest(pAuthInfo, SDNPAUTH_EVT_COMMFAILUREDETECTED); 

      _setAllUsersKeyStatus(pAuthInfo, DNPAUTH_KEY_COMMFAIL); 

      _resetSecStatMaxValue(pSDNPSession, SDNPAUTH_REPLY_TIMEOUT_MAX_INDEX);  
      break;

      /* No row 10 on outstation */

      /* Row 11 and 12 Max Authentication Failures Exceeded below */ 
   
    case SDNPAUTH_EVT_ERRORREQ:
      /* 1815-2012 Table 7-8, Row 13, Log the error message, 
       * Log the error message. 
       * If the Error Code is <5> MAC algorithm Not Permitted, 
       * use a different MAC algorithm to send the next Challenge.
       * Discard the pending ASDU.
       * Increment the Discarded Messages statistic.
       * Increment the Error Messages Rxed statistic.
       * Cancel the Reply Timer.
       * Reset Max Reply Timeouts.
       */ 
      tmwtimer_cancel(&pAuthInfo->replyTimer);
      if(_processErrorRequestV7(pSDNPSession, &rxMsg, &errorCode))
      {
        if (errorCode == DNPAUTH_ERROR_MACNOTPERMIT)
        {
          /* if code == 5 use a different algorithm for next challenge  */
          DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_MACDEFAULT);
          
          /* SHA256 is the default preferred, but switch to SHA1 if we have to */
          if ((pAuthInfo->MACAlgorithm == DNPAUTH_MAC_SHA256_16OCTET)
            && (!pAuthInfo->disallowSHA1))
          {
            pAuthInfo->MACAlgorithm = DNPAUTH_MAC_SHA1_10OCTET;
          }
          else
          {
            pAuthInfo->MACAlgorithm = DNPAUTH_MAC_SHA256_16OCTET;
          }
        }
        _discardPendingRequest(pAuthInfo, SDNPAUTH_EVT_ERRORREQ); 
        _resetSecStatMaxValue(pSDNPSession, SDNPAUTH_REPLY_TIMEOUT_MAX_INDEX); 
      }
      break;

    case SDNPAUTH_EVT_EXPECTEDKEYTIMEOUT:
      /* 1815-2012 Table 7-8 row 15 and 16, 
       * set key status NOT INIT and invalidate those session keys  
       */  
      _setKeyStatus(pUserContext, DNPAUTH_KEY_NOTINIT);
      break;

    case SDNPAUTH_EVT_KEYSTATUSREQ:
      /* 1815-2012 Table 7-8, Row 17 
       * Increment the Unexpected Messages statistic.
       * Discard the Key Status Request
       * Increment the Discarded Messages statistic.
       */   
      _unexpectedMsgRcvd(pSDNPSession, pAuthInfo->state, event, pRxFragment);
      break;
 
    case SDNPAUTH_EVT_AGGRESSIVE_MODE:
      /* According to 1815-2012 Table 7-8, Row 17-23
       */
      if(_processAggrModeRequestV3(pSDNPSession, &rxMsg, pUserContext)) 
      {
        if(pAuthInfo->aggressiveModeSupport)
        {
          /* Skip over the aggressive mode request object at the beginning of message 
           * _processAggrModeRequestV3() removed object from end of message already.
           * Moving the original application control byte and the function code to the
           * beginning of the message makes normal DNP processing simpler and more efficient
           */ 
          pRxFragment->pMsgBuf[DNPAUTH_OBJ120V3_SIZE]   = pRxFragment->pMsgBuf[DNPDEFS_AH_INDEX_APPL_CTRL];
          pRxFragment->pMsgBuf[DNPAUTH_OBJ120V3_SIZE+1] = pRxFragment->pMsgBuf[DNPDEFS_AH_INDEX_FUNC_CODE];
          pRxFragment->pMsgBuf += DNPAUTH_OBJ120V3_SIZE;
          pRxFragment->msgLength = rxMsg.msgLength-DNPAUTH_OBJ120V3_SIZE;

          _authSecStatIncrement(pSDNPSession, DNPAUTH_SUCCESS_AUTHENT_INDEX); 
          if(rxMsg.fc != DNPDEFS_FC_CONFIRM) 
          {
            tmwtimer_cancel(&pAuthInfo->replyTimer);
            _discardPendingRequest(pAuthInfo, SDNPAUTH_EVT_AGGRESSIVE_MODE);
            _unexpectedMsgRcvd(pSDNPSession, pAuthInfo->state, event, pRxFragment); 
            _resetSecStatMaxValue(pSDNPSession, SDNPAUTH_REPLY_TIMEOUT_MAX_INDEX);  
          }
          return(pRxFragment);
        }
        else 
        {
          /* this is a valid aggressive mode except that aggressive mode is disabled
           * This must be from the real master
           */
          _unexpectedMsgRcvd(pSDNPSession, pAuthInfo->state, event, pRxFragment); 
  
          /* 1815 2012 Row 21 says <= MAX. Should say < MAX!
           * When == MAX this would discard the pending critical ASDU but NOT be able to send g120v7, because it already sent MAX!
           * When greater than MAX, it will NOT discard pending critical and will NOT send g120v7
           * < Max provides better behavior and matches DNP SA Conformance test 4.4
           */
          if(pAuthInfo->statistic[DNPAUTH_ERROR_MSG_SENT_INDEX]
            < pAuthInfo->statsMaxValue[SDNPAUTH_ERROR_MSG_SENT_MAX_INDEX])
          {
            /* also sets state to IDLE */
            _discardPendingRequest(pAuthInfo, SDNPAUTH_EVT_AGGRESSIVE_MODE); 
        
            sdnpsa_sendErrorResponseV7(pSDNPSession, pRxFragment->rxAddress, sequenceNumber, userNumber, DNPAUTH_ERROR_AGGRESSNOTPERMIT, TMWDEFS_NULL, 0);

            tmwtimer_cancel(&pAuthInfo->replyTimer); 
             
            _resetSecStatMaxValue(pSDNPSession, SDNPAUTH_REPLY_TIMEOUT_MAX_INDEX);
          } 
        }
      }
      else /* invalid aggressive mode request */
      { 
        if(pAuthInfo->aggressiveModeSupport)
        { 
          authentFailuresStat = _authSecStatIncrement(pSDNPSession, DNPAUTH_AUTHENT_FAIL_INDEX); 
        } 

        /* 1815-2012 Table 7-8 row 23 does NOT say to send error message
         * Just unexpected and discarded statistic
         */
        _unexpectedMsgRcvd(pSDNPSession, pAuthInfo->state, event, pRxFragment); 
      }  
      break; 

    case SDNPAUTH_EVT_KEYCHANGEREQ:
      /* 1815-2012 Table 7-8, Row 25 and 26
       * If Valid Key Change
       *  Discard ASDU pending authentication
       *  Store new Keys, set Key Status OK
       *  Transmit Key Status Message
       *  Cancel Reply timer
       *  Reset Max Reply Timeouts.
       *  Reset Max Error Messages Sent
       *  Reset Max Authentication Rekeys
       * If invalid Key Change 
       *   Discard the invalid Key Change message.
       *   Increment Unexpected Messages statistic
       *   Increment Discarded Messages statistic
       *   Stay in wait for reply state  
       */
      if(_processKeyChangeRequestV6(pSDNPSession, &rxMsg, pUserContext))
      {  
        tmwtimer_cancel(&pAuthInfo->replyTimer);
        _discardPendingRequest(pAuthInfo, SDNPAUTH_EVT_KEYCHANGEREQ);
        _setKeyStatus(pUserContext, DNPAUTH_KEY_OK);

        _resetSecStatMaxValue(pSDNPSession, SDNPAUTH_REPLY_TIMEOUT_MAX_INDEX); 
        _resetSecStatMaxValue(pSDNPSession, SDNPAUTH_ERROR_MSG_SENT_MAX_INDEX); 
        _resetSecStatMaxValue(pSDNPSession, SDNPAUTH_REKEY_DUETOFAIL_MAX_INDEX);

        /* TMW-not in spec */
        _authSecStatIncrement(pSDNPSession, DNPAUTH_SESKEY_CHANGE_INDEX);

        _startExpectedKeyChangeTimer(pAuthInfo, pUserContext->userNumber, pAuthInfo->keyChangeInterval);  
        _sendKeyStatusResponseV5(pSDNPSession, pRxFragment->rxAddress, userNumber); 
      } 
      else
      {
        _unexpectedMsgRcvd(pSDNPSession, pAuthInfo->state, event, pRxFragment); 

        /* TMW-not in spec */
        _authSecStatIncrement(pSDNPSession, DNPAUTH_FAILSESKEY_CHANGE_INDEX);
      }
      break;

    case SDNPAUTH_EVT_CHALLENGE:
      /* According to 1815-2012 Table 7-8, Row 27
       * Reply as described in section 3.2.4 Responder procedures 
       */
      _processChallengeRequestV1(pSDNPSession, &rxMsg, pUserContext); 
      break;

      /* 1815-2012 Table 7-8 Row 28 not on outstation */

    default:
      break;
    }

    /* check this after switch, since it would occur in a case above */
    if(authentFailuresStat > pAuthInfo->statsMaxValue[SDNPAUTH_AUTHENT_FAIL_MAX_INDEX])
    {
      /* According to 1815-2012 Table 7-8, Row 11 and 12 
       * If Rekeys Due to Authentication Failure statistic is > Max Authentication Rekeys
       *  Reset Max Authentication Failures
       *  go to idle 
       *  If operating over TCP
       *    Close TCP connection
       *    Log the event
       * Else
       *  Set the current Key Status to AUTH_FAIL.
       *  Increment the Rekeys Due To Authentication Failure statistic.
       *  Reset Max Authentication Failures
       *  Discard the pending Critical ASDU
       *  Increment Discarded Messages statistic.

       */ 
      _resetSecStatMaxValue(pSDNPSession, SDNPAUTH_AUTHENT_FAIL_MAX_INDEX);
 
      if(pAuthInfo->statistic[DNPAUTH_REKEY_DUETOFAIL_INDEX]
        > pAuthInfo->statsMaxValue[SDNPAUTH_REKEY_DUETOFAIL_MAX_INDEX])
      {
		    DNPLINK_CONTEXT *pLinkContext;

        /* TMW-not in spec, also discard the pending ASDU if it was not discarded above */
        if(pAuthInfo->pendingRequest.msgLength != 0)
        {
          _discardPendingRequest(pAuthInfo, event);
        } 
        
        /* If over TCP, close and log event */ 
        pLinkContext = (DNPLINK_CONTEXT *)pSession->pChannel->pLinkContext;
        if((pLinkContext->networkType == DNPLINK_NETWORK_TCP_ONLY)
          || (pLinkContext->networkType == DNPLINK_NETWORK_TCP_UDP))
        {
          dnplink_closeAndOpen(pSession); 
          sdnpdata_authLogMaxRekeyTCPClose(pSDNPSession->pDbHandle);
        }

        pAuthInfo->state = SDNPAUTH_STATE_IDLE; 
      }
      else
      {
        _setKeyStatus(pUserContext, DNPAUTH_KEY_AUTHFAIL);
        _authSecStatIncrement(pSDNPSession, DNPAUTH_REKEY_DUETOFAIL_INDEX); 

        /* reset Max Auth Failures above */
        /* TMW row 6 already discarded the pending request above, but not row 22 */
        if (pAuthInfo->pendingRequest.msgLength != 0)
        {
          _discardPendingRequest(pAuthInfo, SDNPAUTH_EVT_MAXAUTHENTFAILURES);
        }
      }
    }
  }
  else  /* pAuthInfo->state == SDNPAUTH_STATE_IDLE */ 
  { 
    switch(event)
    {
    case SDNPAUTH_EVT_NONCRITICAL_RCVD:
      /* 1815-2012 Table 7-8, Row 2 rx noncritical, 
       * Process the Non-Critical ASDU and transmit response as required by protocol. 
       * Pass it on to rest of DNP stack
       */ 
      return(pRxFragment);
      break;

    case SDNPAUTH_EVT_CRITICAL_RCVD:
      /* 1815-2012 Table 7-8, Row 3, Rx Critical, 
       * Increment Challenge Sequence Number, 
       * Create and transmit a challenge message
       * Start reply timer, 
       * Queue critical ASDU for execution later 
       * Increment the Critical Messages Received statistic
       * Go to WaitForReply state
       */
      pAuthInfo->state = SDNPAUTH_STATE_WAITFORREPLY;
      /* CRIT_MSG_RCVD incremented where dectected above */
      _sendChallengeV1(pSDNPSession, pRxFragment->rxAddress, DNPAUTH_REASON_CRITICAL); 

      /* save this message to be processed after challenge reply */
      _savePendingRequest(pRxFragment, pAuthInfo, rxMsg.fc); 
      break;

    case SDNPAUTH_EVT_CHALLENGE_REPLY:
      /* 1815-2012 Table 7-8, Row 5 and 6, discard challenge reply message, stay in idle state */ 
      _unexpectedMsgRcvd(pSDNPSession, pAuthInfo->state, event, pRxFragment); 
      break;

    case SDNPAUTH_EVT_REPLYTIMEOUT:
      /* 1815-2012 Table 7-8, Row 7, Should not occur, stay in idle state */
      break;

    case SDNPAUTH_EVT_COMMFAILUREDETECTED:
      /* 1815-2012 Table 7-8, Row 9 */ 
      _resetSecStatMaxValue(pSDNPSession, SDNPAUTH_REPLY_TIMEOUT_MAX_INDEX); 
      _setAllUsersKeyStatus(pAuthInfo, DNPAUTH_KEY_COMMFAIL); 
      break;

      /* 1815-2012 Table 7-8 no row 10 on outstation */
      /* 1815-2012 Table 7-8 Row 11 and 12 handled below */

    case SDNPAUTH_EVT_ERRORREQ:
      /* 1815-2012 Table 7-8, Row 13, 
       * log the error message, noting it was unexpected 
       * TMW-this error might not be unexpected if master is indicating chosen key wrap is not supported.
       */ 
      if(_processErrorRequestV7(pSDNPSession, &rxMsg, &errorCode))
      {
        if(errorCode == DNPAUTH_ERROR_KEYWRAPNOTPERMIT)
        { 
          /* use default key wrap algorithm */
          DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_KEYWRAPDEFAULT); 
          /* pAuthInfo->keyWrapAlgorithm = DNPAUTH_KEYWRAP_AES128;    what user? */
        }
        else 
          _authSecStatIncrement(pSDNPSession, DNPAUTH_UNEXPECTED_MSG_INDEX);
      }
    break;
      
    case SDNPAUTH_EVT_EXPECTEDKEYTIMEOUT:
      /* 1815-2012 Table 7-8, Row 15,
       * Set key status NOT INIT,
       * invalidate current session keys 
       * Starting in version 4/5 old session keys are still used for key status 
       * Stay in Idle state.
       */  
      _setKeyStatus(pUserContext, DNPAUTH_KEY_NOTINIT);
      break;

    case SDNPAUTH_EVT_KEYSTATUSREQ:
      /* 1815-2012 Table 7-8, Row 16,
       * Transmit a key status message with current key status
       * if user not valid increment stats, done above, will not
       * get here.
       */  
      _processKeyStatusRequestV4(pSDNPSession, &rxMsg, pUserContext);
      break;
      
    case SDNPAUTH_EVT_AGGRESSIVE_MODE:
      /* 1815-2012 Table 7-8, Row 17-23
       * If valid, and aggressive mode enabled, process this aggressive mode message
       * If valid and aggressive mode disabled, send error message Aggressive Mode not supported
       * If invalid send error message with UnexpectedReply or Aggressive Mode not supported.
       */

      if(_processAggrModeRequestV3(pSDNPSession, &rxMsg, pUserContext))
      {
        if(pAuthInfo->aggressiveModeSupport)
        {  
          /* Skip over the aggressive mode request object at the beginning of message 
           * _processAggrModeRequestV3() removed object from end of message already.
           * Moving the original application control byte and the function code to the
           * beginning of the message makes normal DNP processing simpler and more efficient
           */ 
          pRxFragment->pMsgBuf[DNPAUTH_OBJ120V3_SIZE]   = pRxFragment->pMsgBuf[DNPDEFS_AH_INDEX_APPL_CTRL];
          pRxFragment->pMsgBuf[DNPAUTH_OBJ120V3_SIZE+1] = pRxFragment->pMsgBuf[DNPDEFS_AH_INDEX_FUNC_CODE];
          pRxFragment->pMsgBuf += DNPAUTH_OBJ120V3_SIZE;
          pRxFragment->msgLength = rxMsg.msgLength-DNPAUTH_OBJ120V3_SIZE;

          _authSecStatIncrement(pSDNPSession, DNPAUTH_SUCCESS_AUTHENT_INDEX);

          /* ask database if this user is allowed to issue this request */  
          if(sdnpdata_authRequestAllowed(pSDNPSession->pDbHandle, userNumber, rxMsg.fc, pRxFragment->pMsgBuf, pRxFragment->msgLength))
          {
            return(pRxFragment);
          }
          else
          { 
            _authSecStatIncrement(pSDNPSession, DNPAUTH_AUTHOR_FAIL_INDEX);
            errorCode = DNPAUTH_ERROR_AUTHORFAILED; 
            SDNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, SDNPDIAG_AUTH_AUTHORFAIL);
          }
        }   
        else
        {
          _unexpectedMsgRcvd(pSDNPSession, pAuthInfo->state, event, pRxFragment); 
          errorCode = DNPAUTH_ERROR_AGGRESSNOTPERMIT;
        }
      }
      else
      {
        if(pAuthInfo->aggressiveModeSupport)
        {
          authentFailuresStat = _authSecStatIncrement(pSDNPSession, DNPAUTH_AUTHENT_FAIL_INDEX); 
          errorCode = DNPAUTH_ERROR_AUTHENTFAILED;

          /* 1815-2012 Table 7-8 Row 22 does not say to discard and increment discarded, but
           * DNP SA conformance test test 4.3.2 Step 13 says it is OK to do.
           * Also DNPSA test 4.3.1 Step 3-6 expects it.
           */
          _authSecStatIncrement(pSDNPSession, DNPAUTH_DISCARDED_MSG_INDEX);
        }
        else
        {
          _unexpectedMsgRcvd(pSDNPSession, pAuthInfo->state, event, pRxFragment); 
          errorCode = DNPAUTH_ERROR_AGGRESSNOTPERMIT;
        }
      }
      sdnpsa_sendErrorResponseV7(pSDNPSession, pRxFragment->rxAddress, sequenceNumber, userNumber, errorCode, TMWDEFS_NULL, 0);
      break;
    
    case SDNPAUTH_EVT_KEYCHANGEREQ: 
      /* 1815-2012 Table 7-8, Row 25 and 26
       * if valid,
       *  Store new keys,
       *  Set key status OK,
       *  Transmit key status message 
       *  Reset Max Error Messages Sent
       *  Reset Max Authentication Rekeys
       * if invalid,
       *  Set key status Auth Fail, 
       *  Transmit key status message.
       * October 2012 face to face.  Setting key to AUTH FAIL could cause a denial of service.
       */

      if(_processKeyChangeRequestV6(pSDNPSession, &rxMsg, pUserContext))
      {
        _setKeyStatus(pUserContext, DNPAUTH_KEY_OK);
        
        _resetSecStatMaxValue(pSDNPSession, SDNPAUTH_ERROR_MSG_SENT_MAX_INDEX);
        _resetSecStatMaxValue(pSDNPSession, SDNPAUTH_REKEY_DUETOFAIL_MAX_INDEX);

        /* TMW-not in spec */
        _resetSecStatMaxValue(pSDNPSession, SDNPAUTH_REPLY_TIMEOUT_MAX_INDEX);
        
        /* TMW-not in spec */
        _authSecStatIncrement(pSDNPSession, DNPAUTH_SESKEY_CHANGE_INDEX);
 
        _sendKeyStatusResponseV5(pSDNPSession, pRxFragment->rxAddress, userNumber); 
 
        /* TMW-not in spec 1815-2012 Table 7-8, restart expectedSessionKeyTimer timer */ 
        _startExpectedKeyChangeTimer(pAuthInfo, pUserContext->userNumber, pAuthInfo->keyChangeInterval);
      }
      else
      { 
        /* TMW-not in spec */
        _authSecStatIncrement(pSDNPSession, DNPAUTH_FAILSESKEY_CHANGE_INDEX);

        /* October 2012 face to face.  Setting key to AUTH FAIL could cause a denial of service.
        pUserContext->keyStatus = DNPAUTH_KEY_AUTHFAIL;
        _sendKeyStatusResponseV5(pSDNPSession, pRxFragment->rxAddress, userNumber);
        */
        
      }
      break;

    case SDNPAUTH_EVT_CHALLENGE:
      /* 1815-2012 Table 7-8 row 27 */
      _processChallengeRequestV1(pSDNPSession, &rxMsg, pUserContext);
      break; 
      
      /* 1815-2012 Table 7-8 Row 28 not on outstation */

    default:
      break;
    }

    /* check this after switch, since it would occur in a case above */
    /* According to 1815-2012 Table 7-8, Row 11 and 12 */
    if(authentFailuresStat > pAuthInfo->statsMaxValue[SDNPAUTH_AUTHENT_FAIL_MAX_INDEX])
    {
      /* According to 1815-2012 Table 7-8, Row 11 and 12 
       * If Rekeys Due to Authentication Failure statistic is > Max Authentication Rekeys
       *  Reset Max Authentication Failures
       *  If operating over TCP
       *    Close TCP connection
       *    Log the event
       * Else
       *  Set the current Key Status to AUTH_FAIL. 
       *  Increment the Rekeys Due To Authentication Failure statistic.
       *  Reset Max Authentication Failures
       *  Discard the pending Critical ASDU
       *  Increment Discarded Messages statistic.
       */ 
      _resetSecStatMaxValue(pSDNPSession, SDNPAUTH_AUTHENT_FAIL_MAX_INDEX);
      if(pAuthInfo->statistic[DNPAUTH_REKEY_DUETOFAIL_INDEX]
         > pAuthInfo->statsMaxValue[SDNPAUTH_REKEY_DUETOFAIL_MAX_INDEX])
      {
        /* If over TCP, close and log event */ 
        DNPLINK_CONTEXT *pLinkContext = (DNPLINK_CONTEXT *)pSession->pChannel->pLinkContext;
        if((pLinkContext->networkType == DNPLINK_NETWORK_TCP_ONLY)
          || (pLinkContext->networkType == DNPLINK_NETWORK_TCP_UDP))
        {
          dnplink_closeAndOpen(pSession); 
          sdnpdata_authLogMaxRekeyTCPClose(pSDNPSession->pDbHandle);
        }
        pAuthInfo->state = SDNPAUTH_STATE_IDLE;
      }
      else
      {
        _setKeyStatus(pUserContext, DNPAUTH_KEY_AUTHFAIL);
        _authSecStatIncrement(pSDNPSession, DNPAUTH_REKEY_DUETOFAIL_INDEX); 
        /* reset Max Auth Failures above */
      }
    }
  }
  return(TMWDEFS_NULL);
} 

TMWTYPES_BOOL TMWDEFS_CALLBACK sdnpsa_OKToSend(
  TMWSESN *pSession)
{ 
  SDNPSESN *pSDNPSession = (SDNPSESN *)pSession;
  SDNPAUTH_INFO *pAuthInfo = (SDNPAUTH_INFO*)pSDNPSession->pAuthenticationInfo;
  if(pAuthInfo != TMWDEFS_NULL) 
  {
    if(pAuthInfo->state == SDNPAUTH_STATE_WAITFORREPLY) 
    {
      return TMWDEFS_FALSE;
    }
  }
  return TMWDEFS_TRUE; 
}

void TMWDEFS_CALLBACK sdnpsa_saveLastChallenge(
  TMWSESN_TX_DATA *pTxData)
{
  SDNPAUTH_INFO *pAuthInfo = _getAuthInfo((SDNPSESN*)pTxData->pSession);  
  if(pAuthInfo != TMWDEFS_NULL)
  { 
    if((pTxData->txFlags & TMWSESN_TXFLAGS_UNSOL) == 0)
    {
      /* copy challenge that was actually transmitted */
      if(pTxData->msgLength <= SDNPAUTH_TXCHALLENGEMAXSIZE)
      {
        memcpy(pAuthInfo->lastChallengeSent, pTxData->pMsgBuf, pTxData->msgLength);
        pAuthInfo->lastChallengeSentLength = pTxData->msgLength;
      }
    }
    else
    {
      /* copy unsolicited "prechallenge" that was actually transmitted */
      if(pTxData->msgLength <= SDNPAUTH_TXCHALLENGEMAXSIZE)
      {
        memcpy(pAuthInfo->lastUnsolChallengeSent, pTxData->pMsgBuf, pTxData->msgLength);
        pAuthInfo->lastUnsolChallengeSentLength = pTxData->msgLength;
      }
    }
  }
}


void TMWDEFS_GLOBAL sdnpsa_msgSent(
  TMWSESN *pSession)
{ 
  _authSecStatIncrement((SDNPSESN *)pSession, DNPAUTH_TOTAL_MSG_SENT_INDEX); 
}


#if TMW_PRIVATE_AUTHTEST
TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpsa_forceSessionKeyTimeout( 
  TMWSESN *pSession,
  TMWTYPES_USHORT userNumber)
{
  SDNPSESN *pSDNPSession = (SDNPSESN *)pSession;
  SDNPAUTH_INFO *pAuthInfo = (SDNPAUTH_INFO*)pSDNPSession->pAuthenticationInfo;
  if(pAuthInfo != TMWDEFS_NULL)
  {
    SDNPAUTH_USER *pUserContext = _findUserContext(pAuthInfo, userNumber);  
    if(pUserContext != TMWDEFS_NULL)
    {
      tmwtimer_start(&pUserContext->expectedSessionKeyTimer, 10,
        pSDNPSession->dnp.tmw.pChannel, _expectedKeyChangeTimeout, pUserContext); 
      return(TMWDEFS_TRUE);
    }
  }
  return(TMWDEFS_FALSE);
}   
#endif

#endif /* SDNPDATA_SUPPORT_OBJ120 */
#endif /* SDNPCNFG_SUPPORT_SA_VERSION5 */
