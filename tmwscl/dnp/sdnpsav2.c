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
#include "tmwscl/dnp/sdnpdiag.h"
#include "tmwscl/dnp/sdnpdata.h" 
#include "tmwscl/dnp/sdnpsav2.h"
#include "tmwscl/dnp/sdnpunsl.h"
#include "tmwscl/dnp/sdnputil.h"
    
#if SDNPCNFG_SUPPORT_SA_VERSION2 

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
  else if(algorithm == DNPAUTH_MAC_SHA256_8OCTET)
  {
    return 8;
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
SDNPAUTH_INFO * TMWDEFS_GLOBAL _getAuthInfo(
  SDNPSESN *pSDNPSession)
{
  return((SDNPAUTH_INFO*)pSDNPSession->pAuthenticationInfo);
} 
 
/* function: _findUserContext
 * purpose: Get pointer to per user authentication context
 * arguments: pointer to authentication info structure 
 * returns: pointer to authentication user structure
 */ 
static SDNPAUTH_USER * TMWDEFS_LOCAL _findUserContext(
  SDNPAUTH_INFO *pInfo, 
  TMWTYPES_USHORT userNumber)
{
  int i;
 
  if(userNumber == 0)
    return(TMWDEFS_NULL);

  for(i=0; i<DNPCNFG_AUTHV2_MAX_NUMBER_USERS; i++)
  {
    if(userNumber == pInfo->authenticationContexts[i].userNumber) 
      return((SDNPAUTH_USER*)&pInfo->authenticationContexts[i]);
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
  SDNPAUTH_INFO  *pInfo,
  SDNPAUTH_USER  *pUserContext,
  TMWTYPES_UCHAR *pEncryptedValue,
  TMWTYPES_USHORT encryptedValueLength)
{
  TMWTYPES_UCHAR *valuePtr = pInfo->dataIfBuffer;
  TMWTYPES_USHORT decryptedLength = SDNPAUTH_BUFFERSIZE;
  TMWTYPES_BOOL status = TMWDEFS_FALSE;
  SDNPSESN *pSDNPSession = (SDNPSESN *)pInfo->pSession;

  if(sdnpdata_authDecryptKeyWrapData(pSDNPSession->pDbHandle, pUserContext->userNumber, DNPAUTH_KEYWRAP_AES128,
    pEncryptedValue, encryptedValueLength, valuePtr, &decryptedLength))
  { 
    TMWTYPES_USHORT keyStatusOffset;
    TMWTYPES_USHORT keyLength = valuePtr[0];  

#if TMWCNFG_SUPPORT_DIAG
    DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pSDNPSession, dataTypeKeyData, pEncryptedValue, encryptedValueLength, TMWDIAG_ID_RX);
    if(pInfo->extraDiags)
    {
      DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pSDNPSession, dataTypeSessKeyData, valuePtr, decryptedLength, TMWDIAG_ID_RX);
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
      && (!memcmp(&valuePtr[keyStatusOffset], 
      pUserContext->lastKeyStatus, pUserContext->lastKeyStatusLength)))
    {
      /* Set keys */ 
      memcpy(pUserContext->controlSessionKeyV2.value, &valuePtr[2], keyLength);
      pUserContext->controlSessionKeyV2.length = (TMWTYPES_UCHAR)keyLength; 
      memcpy(pUserContext->monitorSessionKeyV2.value, &valuePtr[keyLength+2], keyLength);
      pUserContext->monitorSessionKeyV2.length = (TMWTYPES_UCHAR)keyLength;

#if TMW_PRIVATE_AUTHTEST && TMWCNFG_SUPPORT_CRYPTO
      /* Save the keys for testing purposes */
      tmwcrypto_setKeyData(pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_USER_CONTROL_SESSION_KEY, (void*)pUserContext->userNumber, &valuePtr[2], keyLength);
      tmwcrypto_setKeyData(pSDNPSession->dnp.pCryptoHandle, TMWCRYPTO_USER_MONITOR_SESSION_KEY, (void*)pUserContext->userNumber, &valuePtr[keyLength + 2], keyLength);
#endif
      status = TMWDEFS_TRUE;
    }
    else
    { 
      SDNPDIAG_AUTHSESKEYFAIL(pInfo->pSession, decryptedLength, (TMWTYPES_USHORT)((keyLength*2) + 2 + pUserContext->lastKeyStatusLength));
    }
  }
  else
  {
    SDNPDIAG_AUTHSESDECRYPTFAIL(pInfo->pSession, DNPAUTH_KEYWRAP_AES128);
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
  SDNPAUTH_INFO    *pInfo,
  TMWTYPES_BOOL     received,
  TMWTYPES_UCHAR    algorithm,
  DNPDATA_AUTH_KEY *pKey,
  TMWTYPES_UCHAR   *challengeMessage,
  TMWTYPES_USHORT   challengeMsgLength,
  TMWTYPES_UCHAR   *criticalMsg,
  TMWTYPES_USHORT   criticalMsgLength,
  TMWTYPES_UCHAR   *pMACValue,
  TMWTYPES_USHORT  *pMACValueLength)
{
  TMWTYPES_USHORT dataLength;
  TMWTYPES_UCHAR *valuePtr = pInfo->dataIfBuffer;

  /* concatenate challenge message and critical message if there is one */
  memcpy(valuePtr, challengeMessage, challengeMsgLength);
  dataLength = challengeMsgLength;
    
  if(criticalMsgLength > 0)
  {
    memcpy(valuePtr+dataLength, criticalMsg, criticalMsgLength);
    dataLength = (TMWTYPES_USHORT)(dataLength + criticalMsgLength);
  }

  DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pInfo->pSession, dataTypePlainData, valuePtr, dataLength, (received) ? TMWDIAG_ID_RX : 0);

  if(sdnpdata_authHMACValue(algorithm, pKey, valuePtr, (TMWTYPES_USHORT)dataLength, 
    pMACValue, pMACValueLength))
  {
    DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pInfo->pSession, dataTypeGenMAC, pMACValue, *pMACValueLength, (received) ? TMWDIAG_ID_RX : 0);
    return TMWDEFS_TRUE;
  } 

  DNPDIAG_ERROR(pInfo->pSession->pChannel, pInfo->pSession, DNPDIAG_AUTH_MACFAIL); 
  return(TMWDEFS_FALSE);
}

/* function: _determineAggrMACValue
 * purpose: Calculate the MAC Value according to the MAC algorithm and key specified.
 * Copy up to the number of bytes allowed by *pMACValueLength into *pMACValue
 * and set *pMACValueLength to the number of bytes copied.
 * arguments:   
 * returns:  
 *  TMWDEFS_TRUE if successful
 *  TMWDEFS_FALSE otherwise
 */ 
static TMWTYPES_BOOL TMWDEFS_LOCAL _determineAggrMACValue(
  SDNPAUTH_INFO    *pInfo,
  TMWTYPES_BOOL     received,
  TMWTYPES_UCHAR    algorithm,
  DNPDATA_AUTH_KEY *pKey,  
  TMWTYPES_UCHAR   *pLastChallengeMsg,
  TMWTYPES_USHORT   lastChallengeLength, 
  TMWTYPES_UCHAR   *dnpMsg,
  TMWTYPES_ULONG    dnpMsgLength,
  TMWTYPES_UCHAR   *pMACValue,
  TMWTYPES_USHORT  *pMACValueLength)
{
  TMWTYPES_USHORT dataLength;
  TMWTYPES_UCHAR *valuePtr = pInfo->dataIfBuffer;

  /* concatenate last challenge message, new CSQ, and dnp message */
  memcpy(valuePtr, pLastChallengeMsg, lastChallengeLength);
  dataLength = lastChallengeLength;
  
  memcpy(valuePtr+dataLength, dnpMsg, dnpMsgLength);
  dataLength = (TMWTYPES_USHORT)(dataLength + dnpMsgLength);

  DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pInfo->pSession, dataTypePlainData, valuePtr, dataLength, (received) ? TMWDIAG_ID_RX : 0);

  if(sdnpdata_authHMACValue(algorithm, pKey, valuePtr, (TMWTYPES_USHORT)dataLength, 
    pMACValue, pMACValueLength))
  {
    DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pInfo->pSession, dataTypeGenMAC, pMACValue, *pMACValueLength, (received) ? TMWDIAG_ID_RX : 0);
    return TMWDEFS_TRUE;
  } 
  
  DNPDIAG_ERROR(pInfo->pSession->pChannel, pInfo->pSession, DNPDIAG_AUTH_MACFAIL); 
  return(TMWDEFS_FALSE);
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
  SDNPAUTH_INFO *pInfo = _getAuthInfo(pSDNPSession);
  
  if(pUserContext->keyStatus != DNPAUTH_KEY_OK)
  {
    DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_KEYNOTOK); 
    return TMWDEFS_FALSE;
  }

  if(rcvdSequenceNumber == pInfo->challengeSequenceNumber) 
  {
    /* included in MAC Value calculation:
     *   challenge message that was sent
     *   if reasonChallengeSent == CRITICAL
     *     challenged ASDU that was received   
     *   padding data 
    */
    if((rcvdValueLength !=  _macLength(pInfo->MACAlgorithm))
      ||(!_determineMACValue(pInfo, TMWDEFS_TRUE,
      pInfo->MACAlgorithm, &pUserContext->controlSessionKeyV2,
      pInfo->lastChallengeSent, pInfo->lastChallengeSentLength, 
      pInfo->pendingRequest.pMsgBuf, pInfo->pendingRequest.msgLength,
      value, &length)))
    {
      status = TMWDEFS_FALSE;
    } 
    else if((length == rcvdValueLength)
      &&(!memcmp(pRcvdValue, value, rcvdValueLength)))
    {
      status = TMWDEFS_TRUE; 
    }
  }

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
  SDNPAUTH_INFO *pInfo,
  TMWTYPES_USHORT userNumber,
  TMWTYPES_ULONG sequenceNumber, 
  SDNPAUTH_RX_MSG *pRxFragment,
  TMWTYPES_USHORT bytesInObject)
{
  TMWTYPES_UCHAR value[32];
  TMWTYPES_USHORT length = 32;
  SDNPAUTH_USER *pUserContext = _findUserContext(pInfo, userNumber);

  DNPDIAG_AUTH_SHOW_DATA(pInfo->pSession, dataTypeRcvdMAC, &pRxFragment->pMsgBuf[pRxFragment->offset], bytesInObject, TMWDIAG_ID_RX);

  if(pUserContext != TMWDEFS_NULL)
  {
    if(pUserContext->keyStatus != DNPAUTH_KEY_OK)
    {
      SDNPSESN *pSDNPSession = (SDNPSESN*)pInfo->pSession;
      DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_KEYNOTOK); 
      return TMWDEFS_FALSE;
    }
    if(bytesInObject == _macLength(pInfo->MACAlgorithm))
    {
      if(sequenceNumber == (pInfo->challengeSequenceNumber + pInfo->aggressiveModeRcvd))
      {
        if(_determineAggrMACValue(pInfo,  TMWDEFS_TRUE,
          pInfo->MACAlgorithm, &pUserContext->controlSessionKeyV2,
          pInfo->lastChallengeSent, pInfo->lastChallengeSentLength,
          pRxFragment->pMsgBuf, pRxFragment->offset,
          value, &length))
        {
          if(!memcmp(value, &pRxFragment->pMsgBuf[pRxFragment->offset], bytesInObject))
          {
           return TMWDEFS_TRUE;
          }
        }
      }
    }
  }

  DNPDIAG_ERROR(pInfo->pSession->pChannel, pInfo->pSession, DNPDIAG_AUTH_AGGRRXFAIL);  
  return TMWDEFS_FALSE;
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
  else
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
  SDNPAUTH_INFO *pInfo = _getAuthInfo((SDNPSESN*)pSession);

  DNPSTAT_AUTH_RESP_TIMEOUT(pSession);
  sdnpsav2_processing(pSession, SDNPAUTH_EVT_REPLYTIMEOUT, pInfo->currentUserNumber, TMWDEFS_NULL); 
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
  sdnpsav2_processing(pSession, SDNPAUTH_EVT_EXPECTEDKEYTIMEOUT, pUserContext->userNumber, TMWDEFS_NULL); 
} 
 
/* function: _startExpectedKeyChangeTimer
 * purpose:  
 * arguments:  
 * returns:   
 *  void
 */ 
static void _startExpectedKeyChangeTimer(
  SDNPAUTH_INFO *pInfo,
  TMWTYPES_USHORT userNumber,
  TMWTYPES_ULONG timeout) 
{
  SDNPAUTH_USER *pUserContext = _findUserContext(pInfo, userNumber); 
  if(pUserContext != TMWDEFS_NULL)
  {
    pUserContext->keyChangeCount = 0; 
    if(timeout > 0)
    {
      tmwtimer_start(&pUserContext->expectedSessionKeyTimer,
        timeout, pInfo->pSession->pChannel, _expectedKeyChangeTimeout, pUserContext); 
    }
  }
}

/* function: _msgReceived
 * purpose:  
 * arguments:  
 * returns:   
 *  void
 */ 
static void TMWDEFS_LOCAL _msgReceived(
 SDNPAUTH_INFO *pInfo,
 TMWTYPES_UCHAR variation,
 TMWTYPES_USHORT userNumber)
{ 
  SDNPAUTH_USER *pUserContext = _findUserContext(pInfo, userNumber); 
  TMWTARG_UNUSED_PARAM(variation);
  DNPSTAT_AUTH_RCVD(pInfo->pSession, variation);

  if(pUserContext != TMWDEFS_NULL)
  {
    pUserContext->keyChangeCount++;
    if(pUserContext->keyChangeCount > pInfo->maxKeyChangeCount)
    {  
      _startExpectedKeyChangeTimer(pInfo, pUserContext->userNumber, 10); 
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
 SDNPAUTH_INFO *pInfo,
 TMWTYPES_UCHAR variation,
 TMWTYPES_USHORT userNumber)
{
  SDNPAUTH_USER *pUserContext = _findUserContext(pInfo, userNumber); 
  TMWTARG_UNUSED_PARAM(variation);
  DNPSTAT_AUTH_SENT(pInfo->pSession, variation); 

  if(pUserContext != TMWDEFS_NULL)
  { 
    pUserContext->keyChangeCount++;
    if(pUserContext->keyChangeCount > pInfo->maxKeyChangeCount)
    {
      _startExpectedKeyChangeTimer(pInfo, pUserContext->userNumber, 10); 
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

  /* Current message length */
  pResponse->msgLength = 4;
  
  DNPDIAG_BUILD_MESSAGE(pResponse->pChannel, (TMWSESN*)pSDNPSession, pResponse->pMsgDescription); 
}

/* function: _sendChallenge
 * purpose: send object group 120 v1 authentication challenge request to master
 * arguments:   
 * returns:   
 */  
static void TMWDEFS_LOCAL _sendChallenge(
  SDNPSESN *pSDNPSession,
  TMWTYPES_USHORT rxAddress,
  TMWTYPES_UCHAR reason)
{ 
  TMWSESN_TX_DATA *pResponse;
  TMWTYPES_USHORT length;
  TMWTYPES_USHORT lengthIndex;
  DNPCHNL *pDNPChannel = (DNPCHNL *)pSDNPSession->dnp.tmw.pChannel;
  SDNPAUTH_INFO *pInfo = _getAuthInfo(pSDNPSession);  

  pResponse = dnpchnl_newTxData((TMWCHNL *)pDNPChannel,
    (TMWSESN*)pSDNPSession, pDNPChannel->txFragmentSize, rxAddress);

  if(pResponse == TMWDEFS_NULL)
  {
    return;
  } 
#if TMWCNFG_SUPPORT_DIAG
  pResponse->pMsgDescription = "Authentication Challenge";
#endif

  _initializeResponse(pSDNPSession, pResponse, pInfo->applSequenceNumber, DNPDEFS_FC_AUTH_RESPONSE);
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
  pInfo->challengeSequenceNumber++;

  pInfo->aggressiveModeRcvd = 0;

  tmwtarg_store32(&pInfo->challengeSequenceNumber, pResponse->pMsgBuf + pResponse->msgLength);
  pResponse->msgLength += 4;

  /* 2 byte user number */
  pResponse->pMsgBuf[pResponse->msgLength++] = 0; /* Outstation always sends 0 for challenge */
  pResponse->pMsgBuf[pResponse->msgLength++] = 0; /* Outstation always sends 0 for challenge */ 

  pResponse->pMsgBuf[pResponse->msgLength++] = pInfo->MACAlgorithm;
  pResponse->pMsgBuf[pResponse->msgLength++] = reason;

  /* Calculate how much room left in message */
  length = (pResponse->maxLength - pResponse->msgLength);
  if (length > DNPAUTH_MAX_CHALLENGE_DATA)
    length = DNPAUTH_MAX_CHALLENGE_DATA;

  if(!sdnpdata_authRandomChallengeData(&pResponse->pMsgBuf[pResponse->msgLength], 4, &length))
  {
    dnpchnl_freeTxData(pResponse);
    return;
  }

  DNPDIAG_SHOW_AUTH_CHALLENGE((TMWSESN*)pSDNPSession, 0, pInfo->challengeSequenceNumber, pInfo->MACAlgorithm, reason, 0);
  DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pSDNPSession, dataTypeGenChallData, &pResponse->pMsgBuf[pResponse->msgLength], length, 0);

  pResponse->msgLength = (TMWTYPES_USHORT)(pResponse->msgLength + length);
 
  /* Update the length in the object prefix. length of challenge data +8 */
  length = length +8;
  tmwtarg_store16(&length, pResponse->pMsgBuf + lengthIndex); 

  sdnpdata_authLogChallTx(pSDNPSession->pDbHandle, 0, pInfo->challengeSequenceNumber, pInfo->MACAlgorithm, reason);  

  /* Set flag so that this challenge will be saved in lastChallengeSent by beforeTxCallback */
  pResponse->txFlags |= (TMWSESN_TXFLAGS_NO_RESPONSE |TMWSESN_TXFLAGS_DNP_AUTH_CHALL);

  /* We do not know what user we are challenging */
  pInfo->currentUserNumber = 0;

  /* start reply timer */
  tmwtimer_start(&pInfo->replyTimer,
    pInfo->replyTimeout,
    pSDNPSession->dnp.tmw.pChannel, _replyTimeout, pSDNPSession);

  /* Send challenge to master*/ 
  if(!dnpchnl_sendFragment(pResponse))
  {
    dnpchnl_freeTxData(pResponse);
  }  

  _msgSent(pInfo, 1, 0);
}  

 void TMWDEFS_GLOBAL sdnpsav2_addPreChallengeV1(
  SDNPSESN *pSDNPSession,
  TMWSESN_TX_DATA *pResponse)
{ 
  TMWTYPES_USHORT length;
  TMWTYPES_USHORT lengthIndex;
  SDNPAUTH_INFO *pInfo = _getAuthInfo(pSDNPSession);  
  
  if(pInfo == TMWDEFS_NULL)
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
  pInfo->challengeSequenceNumber++;

  pInfo->aggressiveModeRcvd = 0;

  tmwtarg_store32(&pInfo->challengeSequenceNumber, pResponse->pMsgBuf + pResponse->msgLength);
  pResponse->msgLength += 4;

  /* 2 byte user number */
  pResponse->pMsgBuf[pResponse->msgLength++] = 0; /* Outstation always sends 0 for challenge */
  pResponse->pMsgBuf[pResponse->msgLength++] = 0; /* Outstation always sends 0 for challenge */ 

  pResponse->pMsgBuf[pResponse->msgLength++] = pInfo->MACAlgorithm;
  pResponse->pMsgBuf[pResponse->msgLength++] = DNPAUTH_REASON_CRITICAL;

  /* Calculate how much room left in message */
  length = (pResponse->maxLength - pResponse->msgLength);
  if (length > DNPAUTH_MAX_CHALLENGE_DATA)
    length = DNPAUTH_MAX_CHALLENGE_DATA;

  if(!sdnpdata_authRandomChallengeData(&pResponse->pMsgBuf[pResponse->msgLength], 4, &length))
  {
    return;
  }

  DNPDIAG_SHOW_AUTH_CHALLENGE((TMWSESN*)pSDNPSession, 0, pInfo->challengeSequenceNumber, pInfo->MACAlgorithm, DNPAUTH_REASON_CRITICAL, 0);
  DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pSDNPSession, dataTypeGenChallData, &pResponse->pMsgBuf[pResponse->msgLength], length, 0);

  pResponse->msgLength = (TMWTYPES_USHORT)(pResponse->msgLength + length);
 
  /* Update the length in the object prefix. length of challenge data +8 */
  length = length +8;
  tmwtarg_store16(&length, pResponse->pMsgBuf + lengthIndex); 
  
  sdnpdata_authLogChallTx(pSDNPSession->pDbHandle, 0, pInfo->challengeSequenceNumber, pInfo->MACAlgorithm, DNPAUTH_REASON_CRITICAL);  

  /* Do not know what user we are challenging */
  pInfo->currentUserNumber = 0;

  /* do not start reply timer, master will send application confirm with aggressive mode objects */ 
 
  /* Set flag so that this challenge will be saved in lastChallengeSent by beforeTxCallback */
  pResponse->txFlags |=  TMWSESN_TXFLAGS_DNP_AUTH_CHALL;
  
  _msgSent(pInfo, 1, 0); 

  /* This prechallenge makes the one challenge response unnecessary */
  pInfo->rcvdAtLeastOneChallengeResponse = TMWDEFS_TRUE;
}  

/* function: _sendChallengeReply
 * purpose: send object group 120 v2 
 * arguments:   
 * returns:   
 */  
static void TMWDEFS_LOCAL _sendChallengeReply(
  SDNPSESN *pSDNPSession,
  TMWTYPES_ULONG challengeSequenceNumber,
  TMWTYPES_USHORT userNumber,
  SDNPAUTH_RX_MSG *pRxFragment)
{ 
  TMWSESN_TX_DATA *pResponse;
  TMWTYPES_BOOL   status;
  TMWTYPES_USHORT length;
  TMWTYPES_USHORT lengthIndex; 
  DNPCHNL *pDNPChannel = (DNPCHNL *)pSDNPSession->dnp.tmw.pChannel;
  SDNPAUTH_INFO *pInfo = _getAuthInfo(pSDNPSession);  
  SDNPAUTH_USER *pUserContext = _findUserContext(pInfo, userNumber); 

  pResponse = dnpchnl_newTxData((TMWCHNL *)pDNPChannel,
    (TMWSESN*)pSDNPSession, pDNPChannel->txFragmentSize, pRxFragment->rxAddress);

  if(pResponse == TMWDEFS_NULL)
  {
    return;
  } 

#if TMWCNFG_SUPPORT_DIAG
  pResponse->pMsgDescription = "Authentication Challenge Reply";
#endif

  _initializeResponse(pSDNPSession, pResponse, pInfo->applSequenceNumber, DNPDEFS_FC_AUTH_RESPONSE);   
  
  pResponse->pMsgBuf[pResponse->msgLength++] = DNPDEFS_OBJ_120_AUTHENTICATION;
  pResponse->pMsgBuf[pResponse->msgLength++] = 2;
  pResponse->pMsgBuf[pResponse->msgLength++] = DNPDEFS_QUAL_16BIT_FREE_FORMAT;
  pResponse->pMsgBuf[pResponse->msgLength++] = 1;
  
  DNPDIAG_SHOW_TX_OBJECT_HDR((TMWSESN*)pSDNPSession, DNPDEFS_OBJ_120_AUTHENTICATION, 2, DNPDEFS_QUAL_16BIT_FREE_FORMAT);
   
  /* Save index for where to put 2 byte length */
  lengthIndex = pResponse->msgLength;
  pResponse->msgLength += 2;

  /* Add object data */ 
  tmwtarg_store32(&challengeSequenceNumber, pResponse->pMsgBuf + pResponse->msgLength);
  pResponse->msgLength += 4;
 
  tmwtarg_store16(&userNumber, pResponse->pMsgBuf + pResponse->msgLength);
  pResponse->msgLength += 2;

  /* Calculate how much room left in message */
  length = (pResponse->maxLength - pResponse->msgLength);
    
  /* MAC value based on challenge message received and last sent message sent */
  status = _determineMACValue(pInfo, TMWDEFS_FALSE,
    pInfo->MACAlgorithmRcvd, &pUserContext->monitorSessionKeyV2, 
    pRxFragment->pMsgBuf, pRxFragment->msgLength,
#if DNPCNFG_MULTI_SESSION_REQUESTS
    pSDNPSession->dnp.lastTxFragment, pSDNPSession->dnp.lastTxFragmentLength,
#else
    pDNPChannel->lastTxFragment, pDNPChannel->lastTxFragmentLength,
#endif
    &pResponse->pMsgBuf[pResponse->msgLength], &length);
  
  if(!status)
  {
    dnpchnl_freeTxData(pResponse);
    return;
  }

  sdnpdata_authLogChallRplyTx(pSDNPSession->pDbHandle, userNumber, challengeSequenceNumber);
  DNPDIAG_SHOW_AUTH_REPLY((TMWSESN*)pSDNPSession, userNumber, challengeSequenceNumber, TMWDEFS_TRUE, 0);
  /* MAC data is already displayed by _determineMACValue */

  pResponse->msgLength = (TMWTYPES_USHORT)(pResponse->msgLength + length);
 
  /* Update the length in the object prefix. length of MAC value data +6 */
  length = length +6;
  tmwtarg_store16(&length, pResponse->pMsgBuf + lengthIndex); 
 
  /* Send reply to master*/ 
  if(!dnpchnl_sendFragment(pResponse))
  {
    dnpchnl_freeTxData(pResponse);
  }
   
  _msgSent(pInfo, 2, userNumber); 
  return;
}
 
/* function: sdnpsav2_addAggressiveMode
 * purpose: add aggressive mode object group 120 v3 to start of message
 * arguments:    
 * returns:   
 *  TMWDEFS_TRUE if successful
 */    
TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpsav2_addAggrModeStart( 
  SDNPSESN *pSDNPSession,
  TMWSESN_TX_DATA *pResponse)
{ 
  SDNPAUTH_INFO *pInfo = _getAuthInfo(pSDNPSession);   
  SDNPAUTH_USER *pUserContext = _findUserContext(pInfo, DNPAUTH_DEFAULT_USERNUMBER);  
  
  /* if no such user or we have not received a challenge, 
   * we cannot send an aggressive mode request 
   */
  if((pUserContext == TMWDEFS_NULL)
    ||(pInfo->lastChallengeRcvdLength == 0))
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
   
  /* This should be challengeSequenceNumber received in last challenge, + number of aggressive mode requests sent +1*/
  pInfo->aggressiveModeTxSequence++;  
  
  /* Add object data */   
  tmwtarg_store32(&pInfo->aggressiveModeTxSequence, pResponse->pMsgBuf + pResponse->msgLength);
  pResponse->msgLength += 4;
  
  tmwtarg_store16(&pUserContext->userNumber, pResponse->pMsgBuf + pResponse->msgLength);
  pResponse->msgLength += 2;

  _msgSent(pInfo, 3, DNPAUTH_DEFAULT_USERNUMBER); 
  
  sdnpdata_authLogAggrTx(pSDNPSession->pDbHandle, DNPAUTH_DEFAULT_USERNUMBER, pInfo->aggressiveModeTxSequence); 
  DNPDIAG_SHOW_AUTH_AGGRESSIVE((TMWSESN*)pSDNPSession, DNPAUTH_DEFAULT_USERNUMBER, pInfo->aggressiveModeTxSequence, 0, TMWDEFS_TRUE, 0);

  pResponse->txFlags |= TMWSESN_TXFLAGS_DNP_AUTH_AGGR;

  return(TMWDEFS_TRUE);
}    

/* function: sdnpsav2_addAggrModeEnd
 * purpose: add aggressive mode object group 120 v9 to end of message
 * arguments:    
 * returns:   
 *  TMWDEFS_TRUE if successful
 */    
TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpsav2_addAggrModeEnd( 
  SDNPSESN *pSDNPSession,
  TMWSESN_TX_DATA *pResponse)
{ 
  TMWTYPES_USHORT length;
  SDNPAUTH_USER *pUserContext;
  SDNPAUTH_INFO *pInfo = _getAuthInfo(pSDNPSession);
  DNPCHNL_TX_DATA *pDNPTxData = (DNPCHNL_TX_DATA*)pResponse;

  pUserContext = _findUserContext(pInfo, DNPAUTH_DEFAULT_USERNUMBER);  
  if(pUserContext == TMWDEFS_NULL)
  {
    return TMWDEFS_FALSE;
  } 

  pResponse->pMsgBuf[pResponse->msgLength++] = DNPDEFS_OBJ_120_AUTHENTICATION;
  pResponse->pMsgBuf[pResponse->msgLength++] = 9;
  pResponse->pMsgBuf[pResponse->msgLength++] = DNPDEFS_QUAL_16BIT_FREE_FORMAT;
  pResponse->pMsgBuf[pResponse->msgLength++] = 1;

  DNPDIAG_SHOW_TX_OBJECT_HDR((TMWSESN*)pSDNPSession, DNPDEFS_OBJ_120_AUTHENTICATION, 9, DNPDEFS_QUAL_16BIT_FREE_FORMAT);
   
  length = _macLength(pInfo->MACAlgorithmRcvd);
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
    if(!_determineAggrMACValue(pInfo, TMWDEFS_FALSE,
      pInfo->MACAlgorithmRcvd, &pUserContext->monitorSessionKeyV2,
      pInfo->lastChallengeRcvd, pInfo->lastChallengeRcvdLength,
      pResponse->pMsgBuf, pResponse->msgLength,
      &pResponse->pMsgBuf[pResponse->msgLength], &length))
    { 
      return TMWDEFS_FALSE;
    }
  }

  pResponse->msgLength = (TMWTYPES_USHORT)(pResponse->msgLength + length); 

  /* Save this length for aggressive mode delay code */
  pDNPTxData->authAggrModeObjLength = (TMWTYPES_UCHAR)(length + 6);

  _msgSent(pInfo, 9, DNPAUTH_DEFAULT_USERNUMBER); 

  DNPDIAG_SHOW_AUTH_AGGRESSIVE((TMWSESN*)pSDNPSession, DNPAUTH_DEFAULT_USERNUMBER, pInfo->aggressiveModeTxSequence, 0, TMWDEFS_TRUE, 0);
  return(TMWDEFS_TRUE);
}

/* function: sdnpsav2_aggrDelay */
/* update time and recalculate hash value, then ask link layer to rechecksum request */
void TMWDEFS_GLOBAL sdnpsav2_aggrDelay(
  TMWSESN_TX_DATA *pResponse,
  TMWTYPES_UCHAR *pDelayBuf)
{
  TMWTYPES_USHORT length;
  TMWTYPES_USHORT totalBytesToTx;
  TMWTYPES_USHORT offset;
  TMWTYPES_USHORT index;
  SDNPAUTH_USER *pUserContext;
  SDNPAUTH_INFO *pInfo;
  DNPCHNL_TX_DATA *pDNPTxData;
  SDNPSESN *pSDNPSession;
  TMWPHYS_TX_DESCRIPTOR *pPhysTxDescriptor;
  TMWTYPES_UCHAR tempBuf[128];

  pSDNPSession = (SDNPSESN*)pResponse->pSession;
  pInfo = _getAuthInfo(pSDNPSession);

  pUserContext = _findUserContext(pInfo, DNPAUTH_DEFAULT_USERNUMBER);
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
    memcpy(&tempBuf[index], pPhysTxDescriptor->pTxBuffer+ offset, bytesToCopy);
    index = (TMWTYPES_USHORT)(index + bytesToCopy);
    offset += bytesToCopy+2;
  }

  pDNPTxData = (DNPCHNL_TX_DATA*)pResponse;
  length =  pDNPTxData->authAggrModeObjLength-6;

  /* MAC value based on last challenge message received, new key and this response so far, including the length field */
  if(!_determineAggrMACValue(pInfo, TMWDEFS_FALSE,
    pInfo->MACAlgorithmRcvd, &pUserContext->monitorSessionKeyV2, 
    pInfo->lastChallengeRcvd, pInfo->lastChallengeRcvdLength,
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
 
/* function: _sendKeyStatusResponse
 * purpose: build and send key status response object group 120 v5 
 * arguments:   
 * returns:   
 */  
static void TMWDEFS_LOCAL _sendKeyStatusResponse(
  SDNPSESN *pSDNPSession,
  TMWTYPES_USHORT rxAddress,
  TMWTYPES_USHORT userNumber)
{
  TMWSESN_TX_DATA *pResponse;
  TMWTYPES_USHORT length;
  TMWTYPES_USHORT lengthIndex;
  TMWTYPES_USHORT challengeLength;
  TMWTYPES_USHORT challengeLengthIndex; 
  TMWTYPES_USHORT macLength = 0;
  TMWSESN *pSession = (TMWSESN*)pSDNPSession;
  DNPCHNL *pDNPChannel = (DNPCHNL*)pSession->pChannel;
  SDNPAUTH_INFO *pInfo = _getAuthInfo(pSDNPSession); 
  SDNPAUTH_USER *pUserContext = _findUserContext(pInfo, userNumber);  

  if (pUserContext == TMWDEFS_NULL)
  {
    return;
  }

  pResponse = dnpchnl_newTxData((TMWCHNL *)pDNPChannel,
    pSession, pDNPChannel->txFragmentSize, rxAddress);

  if(pResponse == TMWDEFS_NULL)
  {
    return;
  } 

#if TMWCNFG_SUPPORT_DIAG
  pResponse->pMsgDescription = "Authentication Key Status";
#endif

  _initializeResponse(pSDNPSession, pResponse, pInfo->applSequenceNumber, DNPDEFS_FC_AUTH_RESPONSE);
 
  pResponse->pMsgBuf[pResponse->msgLength++] = DNPDEFS_OBJ_120_AUTHENTICATION;
  pResponse->pMsgBuf[pResponse->msgLength++] = 5;
  pResponse->pMsgBuf[pResponse->msgLength++] = DNPDEFS_QUAL_16BIT_FREE_FORMAT;
  pResponse->pMsgBuf[pResponse->msgLength++] = 1;
  
  DNPDIAG_SHOW_TX_OBJECT_HDR((TMWSESN*)pSDNPSession, DNPDEFS_OBJ_120_AUTHENTICATION, 5, DNPDEFS_QUAL_16BIT_FREE_FORMAT);

  /* Save index for where to put 2 byte length */
  lengthIndex = pResponse->msgLength;
  pResponse->msgLength += 2;

  /* Add object data */ 
  tmwtarg_store32(&pUserContext->keyChangeSequenceNumber, pResponse->pMsgBuf + pResponse->msgLength);
  pResponse->msgLength += 4;
 
  tmwtarg_store16(&userNumber, pResponse->pMsgBuf + pResponse->msgLength);
  pResponse->msgLength += 2;

  pResponse->pMsgBuf[pResponse->msgLength++] = DNPAUTH_KEYWRAP_AES128;
  pResponse->pMsgBuf[pResponse->msgLength++] = pUserContext->keyStatus;

  /* Of key status is OK then specify MAC algorithim used to calculate MAC value */ 
  if(pUserContext->keyStatus == DNPAUTH_KEY_OK)
    pResponse->pMsgBuf[pResponse->msgLength++] = pInfo->MACAlgorithm;
  else
    pResponse->pMsgBuf[pResponse->msgLength++] = 0;

  challengeLengthIndex = pResponse->msgLength;
  pResponse->msgLength += 2;

  /* Calculate how much room left in message */
  challengeLength = (pResponse->maxLength - pResponse->msgLength);
  if (challengeLength > DNPAUTH_MAX_CHALLENGE_DATA)
    challengeLength = DNPAUTH_MAX_CHALLENGE_DATA;

  if(!sdnpdata_authRandomChallengeData(&pResponse->pMsgBuf[pResponse->msgLength], 4, &challengeLength))
  {
    dnpchnl_freeTxData(pResponse);
    return;
  }

  DNPDIAG_SHOW_KEY_STATUS(pSession, userNumber, pUserContext->keyChangeSequenceNumber,
    DNPAUTH_KEYWRAP_AES128, pUserContext->keyStatus, pInfo->MACAlgorithm, 0);

  DNPDIAG_AUTH_SHOW_DATA(pSession, dataTypeGenChallData, &pResponse->pMsgBuf[pResponse->msgLength], challengeLength, 0);

  pResponse->msgLength = (TMWTYPES_USHORT)(pResponse->msgLength + challengeLength);

  /* Store length of challenge data in the correct place */
  tmwtarg_store16(&challengeLength, pResponse->pMsgBuf + challengeLengthIndex);

  if(pUserContext->keyStatus == DNPAUTH_KEY_OK)
  { 
    macLength = (pResponse->maxLength - pResponse->msgLength); 
 
    if(!_determineMACValue(pInfo, TMWDEFS_FALSE, pInfo->MACAlgorithm, &pUserContext->monitorSessionKeyV2, pUserContext->lastKeyChange, 
      pUserContext->lastKeyChangeLength, TMWDEFS_NULL, 0, &pResponse->pMsgBuf[pResponse->msgLength], &macLength))
    {
      dnpchnl_freeTxData(pResponse);
      return;
    }

    pResponse->msgLength = (TMWTYPES_USHORT)(pResponse->msgLength + macLength); 
  }
  
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

  sdnpdata_authLogKeyStatusTx(pSDNPSession->pDbHandle, userNumber, pUserContext->keyChangeSequenceNumber,
    DNPAUTH_KEYWRAP_AES128, pUserContext->keyStatus, pInfo->MACAlgorithm);   

  /* Send key status to master*/ 
  if(!dnpchnl_sendFragment(pResponse))
  {
    dnpchnl_freeTxData(pResponse);
  }
   
  _msgSent(pInfo, 5, userNumber); 
}
 
/* function: _sendErrorResponse
 * purpose: build and send error message object group 120 v7
 * arguments:   
 * returns:   
 */  
static void TMWDEFS_LOCAL _sendErrorResponse(
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
  SDNPAUTH_INFO *pInfo = _getAuthInfo(pSDNPSession); 

  /* Get the time now in case we need to log but NOT send the error response */
  sdnputil_getDateTime(pSession, &timeStamp);

  pInfo->errorCount++;
  if(pInfo->errorCount > pInfo->maxErrorCount)
  {
    sdnpdata_authLogErrorTx(pSDNPSession->pDbHandle, userNumber, pInfo->assocId, sequenceNumber, errorCode, &timeStamp, TMWDEFS_NULL, 0, TMWDEFS_FALSE);
    return;
  }

  pResponse = dnpchnl_newTxData((TMWCHNL *)pDNPChannel,
    pSession, pDNPChannel->txFragmentSize, rxAddress);

  if(pResponse == TMWDEFS_NULL)
  {
    return;
  } 

#if TMWCNFG_SUPPORT_DIAG
  pResponse->pMsgDescription = "Authentication Error";
#endif

  _initializeResponse(pSDNPSession, pResponse, pInfo->applSequenceNumber, DNPDEFS_FC_AUTH_RESPONSE);

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
  tmwtarg_store16(&pInfo->assocId, pResponse->pMsgBuf + pResponse->msgLength);
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

  sdnpdata_authLogErrorTx(pSDNPSession->pDbHandle, userNumber, pInfo->assocId, sequenceNumber, errorCode, &timeStamp, pErrorText, errorTextLength, TMWDEFS_TRUE);

  DNPDIAG_SHOW_AUTH_ERROR((TMWSESN*)pSDNPSession, userNumber, pInfo->assocId, sequenceNumber, errorCode, &timeStamp, pErrorText, errorTextLength, TMWDEFS_FALSE, 0);

  /* Send error message to master*/ 
  if(!dnpchnl_sendFragment(pResponse))
  {
    dnpchnl_freeTxData(pResponse);
  }

  _msgSent(pInfo, 7, userNumber); 

  return;
}

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

/* function: _processChallengeRequest */
/* process reception of object group 120 v1 */
TMWTYPES_BOOL TMWDEFS_GLOBAL _processChallengeRequest(
  SDNPSESN *pSDNPSession,
  SDNPAUTH_RX_MSG *pRxFragment)
{
  TMWTYPES_ULONG sequenceNumber;
  TMWTYPES_USHORT bytesInObject;
  TMWTYPES_USHORT userNumber; 
  TMWTYPES_UCHAR macAlgorithm; 
  TMWTYPES_UCHAR reasonForChallenge; 
  SDNPAUTH_INFO *pInfo = _getAuthInfo(pSDNPSession);
 
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
  
  /* challenge data length */  
  bytesInObject = bytesInObject - 8;
  DNPDIAG_SHOW_AUTH_CHALLENGE((TMWSESN*)pSDNPSession, userNumber, sequenceNumber, macAlgorithm, reasonForChallenge, TMWDIAG_ID_RX);
  DNPDIAG_AUTH_SHOW_DATA((TMWSESN*)pSDNPSession, dataTypeRcvdChallData, &pRxFragment->pMsgBuf[pRxFragment->offset], bytesInObject, TMWDIAG_ID_RX);

  /* Move past Challenge Data in message */
  pRxFragment->offset = pRxFragment->offset + bytesInObject;
     
  sdnpdata_authLogChallRx(pSDNPSession->pDbHandle, userNumber, sequenceNumber, macAlgorithm, reasonForChallenge);  

  /* Protect against badly formatted message */
  if(!_validateMsgLength((TMWSESN*)pSDNPSession, pRxFragment, 0))
  {
    return(TMWDEFS_FALSE);
  }

#ifdef TMW_SUPPORT_MONITOR
  if(pSDNPSession->dnp.tmw.pChannel->pPhysContext->monitorMode)
    return(TMWDEFS_TRUE);
#endif

  if(sdnpdata_authHMACSupport(macAlgorithm) == 0) 
  {
    _sendErrorResponse(pSDNPSession, pRxFragment->rxAddress, sequenceNumber, userNumber, DNPAUTH_ERROR_MACNOTPERMIT, TMWDEFS_NULL, 0);  
    return(TMWDEFS_FALSE);
  }

  /* make a copy of this challenge request to be used in aggressive mode message */
  if(pRxFragment->msgLength <= SDNPAUTH_RXCHALLENGEMAXSIZE)
  {
    memcpy(pInfo->lastChallengeRcvd, pRxFragment->pMsgBuf, pRxFragment->msgLength);
    pInfo->lastChallengeRcvdLength = pRxFragment->msgLength;
  }
  else
  {
    DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_TOO_BIG);
  }
  pInfo->aggressiveModeTxSequence = sequenceNumber;
  pInfo->MACAlgorithmRcvd = macAlgorithm;
  
  _sendChallengeReply(pSDNPSession, sequenceNumber, userNumber, pRxFragment); 
   
  return(TMWDEFS_TRUE);
}  

/* function: _processChallengeReply */
/* process reception of object group 120 v2 */
TMWTYPES_BOOL TMWDEFS_GLOBAL _processChallengeReply(
  SDNPSESN *pSDNPSession,
  SDNPAUTH_RX_MSG *pRxFragment)
{
  TMWTYPES_BOOL monitorMode;
  TMWTYPES_BOOL status; 
  TMWTYPES_USHORT userNumber;
  TMWTYPES_ULONG sequenceNumber;
  TMWTYPES_USHORT bytesInObject;
  SDNPAUTH_INFO *pInfo = _getAuthInfo(pSDNPSession);

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

  if (!monitorMode)
  {
    /* userNumber has already been validated */
    SDNPAUTH_USER *pUserContext = _findUserContext(pInfo, userNumber);
    if (pUserContext != TMWDEFS_NULL)
    {
      /* When the challenge was sent the user number was 0, so this message was not counted, count it now */
      pUserContext->keyChangeCount++;
      status = _validateChallengeReply(pSDNPSession, pUserContext, &pRxFragment->pMsgBuf[pRxFragment->offset],
        bytesInObject, sequenceNumber);
    }
  }
 
  sdnpdata_authLogChallRplyRx(pSDNPSession->pDbHandle, userNumber, sequenceNumber, status);  
  DNPDIAG_SHOW_AUTH_REPLY((TMWSESN*)pSDNPSession, userNumber, sequenceNumber, status, TMWDIAG_ID_RX);

  pRxFragment->offset = pRxFragment->offset + bytesInObject;
  
  return(status);
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
  TMWTYPES_UCHAR aggrModeMACLength[4] = { 4, 8, 10, 16 };

  for (i = 0; i<4; i++)
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

      sdnpdata_authLogAggrRx(pSDNPSession->pDbHandle, userNumber, sequenceNumber, 1); 
      DNPDIAG_SHOW_AUTH_HEADER((TMWSESN*)pSDNPSession, &hdr);
      DNPDIAG_SHOW_AUTH_AGGRESSIVE((TMWSESN*)pSDNPSession, userNumber, sequenceNumber, 
        0, 1, TMWDIAG_ID_RX);
      return;
    }
    pRxFragment->offset = savedRxOffset;
  }
  return;
}
#endif

/* function: _processAggrModeRequest */
/* process reception of object group 120 v3 */
static TMWTYPES_BOOL TMWDEFS_LOCAL _processAggrModeRequest(
  SDNPSESN *pSDNPSession,
  SDNPAUTH_RX_MSG *pRxFragment)
{    
  TMWTYPES_BOOL status;
  TMWTYPES_ULONG sequenceNumber;
  TMWTYPES_USHORT userNumber;
  SDNPAUTH_USER *pUserContext;
  SDNPAUTH_INFO *pInfo = _getAuthInfo(pSDNPSession);

  /* Protect against badly formatted message */
  if(!_validateMsgLength((TMWSESN*)pSDNPSession, pRxFragment, 6))
  { 
    return(TMWDEFS_FALSE);
  }

  status = TMWDEFS_FALSE;

  tmwtarg_get32(&pRxFragment->pMsgBuf[pRxFragment->offset], &sequenceNumber);
  pRxFragment->offset += 4;

  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &userNumber);
  pRxFragment->offset += 2; 
  
  pInfo->aggressiveModeRcvd++;
  
#ifdef TMW_SUPPORT_MONITOR
  if(pSDNPSession->dnp.tmw.pChannel->pPhysContext->monitorMode) 
  { 
    DNPDIAG_SHOW_AUTH_AGGRESSIVE((TMWSESN*)pSDNPSession, userNumber, sequenceNumber, 0, TMWDEFS_TRUE, TMWDIAG_ID_RX);
    _monitorRemoveAggrEnd(pSDNPSession, pRxFragment, userNumber, sequenceNumber);
    return(TMWDEFS_TRUE);
  }
#endif

  pUserContext = _findUserContext(pInfo, userNumber);
  if(pUserContext != TMWDEFS_NULL)
  { 
    TMWTYPES_USHORT aggrModeMACLength; 
    TMWTYPES_USHORT length; 
    DNPAUTH_OBJECT_HEADER hdr;
 
    /* length of MAC data to be used was specified in last challenge sent to master,
     * so it is possible to start at the end of the message to look for an aggressive
     * mode object 
     */ 
    aggrModeMACLength = sdnpdata_authHMACSupport(pInfo->MACAlgorithm);
     
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
      tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &length);
      pRxFragment->offset = pRxFragment->offset+2;

      DNPDIAG_SHOW_AUTH_HEADER((TMWSESN*)pSDNPSession, &hdr);
   
      status = _validateAggressiveMode(pInfo, userNumber, sequenceNumber, pRxFragment, length);

      /* remove aggressivemode object from message, so rest of stack does not need to parse it */
      pRxFragment->msgLength -= (6+aggrModeMACLength);

      sdnpdata_authLogAggrRx(pSDNPSession->pDbHandle, userNumber, sequenceNumber, status);  
      DNPDIAG_SHOW_AUTH_AGGRESSIVE((TMWSESN*)pSDNPSession, userNumber, sequenceNumber, 
        (pInfo->challengeSequenceNumber + pInfo->aggressiveModeRcvd), status, TMWDIAG_ID_RX);
    }  
  }
  return status;
}
 
/* function: _processKeyStatusRequest */
/* process reception of object group 120 v4 */
static TMWTYPES_BOOL TMWDEFS_LOCAL _processKeyStatusRequest(
  SDNPSESN *pSDNPSession,
  SDNPAUTH_RX_MSG *pRxFragment)
{   
  SDNPAUTH_USER *pUserContext;
  TMWTYPES_USHORT userNumber = 1;
  SDNPAUTH_INFO *pInfo = _getAuthInfo(pSDNPSession);
    
  /* Protect against badly formatted message */
  if(pRxFragment->msgLength < 8)
  { 
    DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_INVALID_SIZE); 
    return(TMWDEFS_FALSE);
  }

  /* [6] is user number */ 
  tmwtarg_get16(&pRxFragment->pMsgBuf[6], &userNumber);
  /* we incremented offset in earlier processing */
   
  sdnpdata_authLogKeyStatRqRx(pSDNPSession->pDbHandle, userNumber);  
  DNPDIAG_SHOW_AUTH_KEYSTATREQ((TMWSESN*)pSDNPSession, userNumber, TMWDIAG_ID_RX);

#ifdef TMW_SUPPORT_MONITOR
  if(pSDNPSession->dnp.tmw.pChannel->pPhysContext->monitorMode) 
  {
    return(TMWDEFS_TRUE);
  }
#endif

  pUserContext = _findUserContext(pInfo, userNumber);  
  if(pUserContext != TMWDEFS_NULL)
    pUserContext->keyChangeSequenceNumber++;

  _sendKeyStatusResponse(pSDNPSession, pRxFragment->rxAddress, userNumber);

  return(TMWDEFS_TRUE);
}

/* function: _processKeyChangeRequest */
/* process reception of object group 120 v6 */
static TMWTYPES_BOOL TMWDEFS_LOCAL _processKeyChangeRequest(
  SDNPSESN *pSDNPSession,
  SDNPAUTH_RX_MSG *pRxFragment,
  TMWTYPES_USHORT *pUserNumber)
{
  SDNPAUTH_USER *pUserContext;
  TMWTYPES_BOOL status;
  TMWTYPES_USHORT userNumber;
  TMWTYPES_USHORT bytesInObject;
  TMWTYPES_ULONG sequenceNumber;
  TMWTYPES_ULONG expectedSequenceNumber = 0;
  SDNPAUTH_INFO *pInfo = _getAuthInfo(pSDNPSession);

  /* Protect against badly formatted message */
  if (!_validateMsgLength((TMWSESN*)pSDNPSession, pRxFragment, 8))
  {
    return(TMWDEFS_FALSE);
  }

  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &bytesInObject);
  pRxFragment->offset += 2;

  tmwtarg_get32(&pRxFragment->pMsgBuf[pRxFragment->offset], &sequenceNumber);
  pRxFragment->offset += 4;

  tmwtarg_get16(&pRxFragment->pMsgBuf[pRxFragment->offset], &userNumber);
  pRxFragment->offset += 2;
  *pUserNumber = userNumber;

  /* Determine length of Encrypted Key Wrap Data in message */
  bytesInObject = bytesInObject - 6;

  /* Protect against badly formatted message */
  if ((pRxFragment->offset + bytesInObject) > pRxFragment->msgLength)
  {
    DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_INVALID_SIZE);
    return(TMWDEFS_FALSE);
  }

#ifdef TMW_SUPPORT_MONITOR
  if (pSDNPSession->dnp.tmw.pChannel->pPhysContext->monitorMode)
  {
    DNPDIAG_MON_AUTH_KEYCHANGE((TMWSESN*)pSDNPSession, userNumber, sequenceNumber);
    return(TMWDEFS_TRUE);
  }
#endif

  status = TMWDEFS_FALSE;
  pUserContext = _findUserContext(pInfo, userNumber);
  if (pUserContext != TMWDEFS_NULL)
  {
    /* Validate request */
    expectedSequenceNumber = pUserContext->keyChangeSequenceNumber++;

    if (sequenceNumber == expectedSequenceNumber)
    {
      if (_verifyAndGetSessionKeys(pInfo, pUserContext,
        &pRxFragment->pMsgBuf[pRxFragment->offset], bytesInObject))
      {
        if (pRxFragment->msgLength <= SDNPAUTH_KEYCHANGEMAXSIZE)
        {
          memcpy(pUserContext->lastKeyChange, pRxFragment->pMsgBuf, pRxFragment->msgLength);
          pUserContext->lastKeyChangeLength = pRxFragment->msgLength;
          pInfo->lastChallengeRcvdLength = 0;
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

  sdnpdata_authLogKeyChangeRx(pSDNPSession->pDbHandle, userNumber, sequenceNumber, status);

  /* in case user does not exist, reuse the variable bytesInObject for key length and init to zero */
  bytesInObject = 0;
  if (pUserContext != TMWDEFS_NULL)
  {
    bytesInObject = pUserContext->controlSessionKeyV2.length;
  }
  DNPDIAG_SHOW_AUTH_KEYCHANGE((TMWSESN*)pSDNPSession, userNumber, bytesInObject, sequenceNumber, expectedSequenceNumber, status, TMWDIAG_ID_RX);

  return(status);
} 

/* function: _processErrorRequest */
/* process reception of object group 120 v7 */
static TMWTYPES_BOOL TMWDEFS_LOCAL _processErrorRequest(
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
  if(pRxFragment->offset > pRxFragment->msgLength)
  { 
    DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_INVALID_SIZE);
    return(TMWDEFS_FALSE);
  }

  *pErrorCode = errorCode;

  return(TMWDEFS_TRUE);
} 


void TMWDEFS_GLOBAL sdnpsav2_getConfig(
  void *pInfo,
  SDNPSESN_AUTH_CONFIG *pConfig)
{
  SDNPAUTH_INFO *pAuthInfo = (SDNPAUTH_INFO *)pInfo;
  if(pAuthInfo != TMWDEFS_NULL)
  {
    SDNPSESN *pSDNPSession = (SDNPSESN*)pAuthInfo->pSession;
    int i;
    pConfig->operateInV2Mode            = TMWDEFS_TRUE;
    pConfig->assocId                    = pAuthInfo->assocId;
    pConfig->MACAlgorithm               = pAuthInfo->MACAlgorithm;
    pConfig->replyTimeout               = pAuthInfo->replyTimeout;
    pConfig->maxApplTimeoutCount        = pAuthInfo->maxApplTimeoutCount; 
    pConfig->keyChangeInterval          = pAuthInfo->keyChangeInterval;
    pConfig->maxKeyChangeCount          = pAuthInfo->maxKeyChangeCount;
    pConfig->aggressiveModeSupport      = pAuthInfo->aggressiveModeSupport;
    pConfig->maxErrorCount              = pAuthInfo->maxErrorCount;
    pConfig->extraDiags                 = pAuthInfo->extraDiags;

    pConfig->authSendAggrResp     = pSDNPSession->authSendAggrResp;
    pConfig->authSendAggrUnsol    = pSDNPSession->authSendAggrUnsol;
    pConfig->preChallengeApplConf = pSDNPSession->preChallengeApplConf;

    for(i=1; i<DNPCNFG_AUTHV2_MAX_NUMBER_USERS; i++)
    { 
      pConfig->authUsers[i].userNumber  = pAuthInfo->authenticationContexts[i].userNumber;
    }
  }
}

void TMWDEFS_GLOBAL sdnpsav2_setConfig( 
  void *pInfo,
  const SDNPSESN_AUTH_CONFIG *pConfig)
{
  int i;
  SDNPAUTH_INFO *pAuthInfo = (SDNPAUTH_INFO *)pInfo;
  SDNPSESN *pSDNPSession = (SDNPSESN*)pAuthInfo->pSession;

  pAuthInfo->assocId                    = pConfig->assocId; 
  pAuthInfo->MACAlgorithm               = pConfig->MACAlgorithm;
  pAuthInfo->replyTimeout               = pConfig->replyTimeout; 
  pAuthInfo->maxApplTimeoutCount        = pConfig->maxApplTimeoutCount; 
  pAuthInfo->keyChangeInterval          = pConfig->keyChangeInterval; 
  pAuthInfo->maxKeyChangeCount          = pConfig->maxKeyChangeCount; 
  pAuthInfo->aggressiveModeSupport      = pConfig->aggressiveModeSupport; 
  pAuthInfo->maxErrorCount              = pConfig->maxErrorCount; 
  pAuthInfo->extraDiags                 = pConfig->extraDiags; 

  pSDNPSession->authSendAggrResp     = pConfig->authSendAggrResp;
  pSDNPSession->authSendAggrUnsol    = pConfig->authSendAggrUnsol;
  pSDNPSession->preChallengeApplConf = pConfig->preChallengeApplConf;

  for(i=1; i<DNPCNFG_AUTHV2_MAX_NUMBER_USERS; i++)
  { 
    pAuthInfo->authenticationContexts[i].userNumber = pConfig->authUsers[i].userNumber;
  }
}

/* function: sdnpsav2_init */
SDNPAUTH_INFO * TMWDEFS_GLOBAL sdnpsav2_init(
  SDNPSESN *pSDNPSession,
  const SDNPSESN_AUTH_CONFIG *pConfig)
{  
  SDNPAUTH_INFO *pAuthInfo = (SDNPAUTH_INFO *)sdnpmem_alloc(SDNPMEM_AUTH_INFO_TYPE);
  if(pAuthInfo != TMWDEFS_NULL)
  { 
    int i;

    pAuthInfo->pSession = (TMWSESN*)pSDNPSession;
    pAuthInfo->state = SDNPAUTH_STATE_IDLE;
    pAuthInfo->currentUserNumber = 0; 

    pAuthInfo->rcvdAtLeastOneChallengeResponse = TMWDEFS_FALSE;

    pAuthInfo->lastChallengeRcvdLength = 0;
    pAuthInfo->aggressiveModeTxSequence = 0;
    pAuthInfo->aggressiveModeRcvd = 0;

    pAuthInfo->challengeSequenceNumber = 0; 
    pAuthInfo->lastChallengeSentLength = 0; 

    /* reply timer */
    tmwtimer_init(&pAuthInfo->replyTimer);

    /* Maximum number of error messages to send */
    pAuthInfo->errorCount        = 0;
    pAuthInfo->applTimeoutCount  = 0;

#ifdef TMW_PRIVATE_AUTHTEST 
    pAuthInfo->forceErrorMessage = TMWDEFS_FALSE;
#endif
     
    /* Init this to zero so we can tell there is no pending request */
    pAuthInfo->pendingRequest.msgLength = 0;

    for(i=0; i<DNPCNFG_AUTHV2_MAX_NUMBER_USERS; i++) 
    {
      SDNPAUTH_USER *pUserContext = &pAuthInfo->authenticationContexts[i];
      pUserContext->userNumber = pConfig->authUsers[i].userNumber;  
      pUserContext->keyChangeSequenceNumber = 0; 
      pUserContext->controlSessionKeyV2.length = 0;
      pUserContext->monitorSessionKeyV2.length = 0;
      pUserContext->keyStatus = DNPAUTH_KEY_NOTINIT;  
      pUserContext->lastKeyStatusLength = 0;
      pUserContext->pAuthInfo = pAuthInfo;

      /* key change timer and count */
      tmwtimer_init(&pUserContext->expectedSessionKeyTimer); 
      pUserContext->keyChangeCount = 0; 
    }

#if TMWCNFG_SUPPORT_CRYPTO
      pSDNPSession->dnp.pCryptoHandle = tmwcrypto_init(pSDNPSession->dnp.pUserHandle);
      if (pSDNPSession->dnp.pCryptoHandle == TMWDEFS_NULL)
        return TMWDEFS_NULL;
#endif

  }
  return(pAuthInfo);
}

/* function: sdnpsav2_close */
void TMWDEFS_GLOBAL sdnpsav2_close(
  void *pInfo)
{ 
  int i;
  SDNPAUTH_INFO *pAuthInfo = (SDNPAUTH_INFO*)pInfo;

  /* cancel all authentication timers */
  tmwtimer_cancel(&pAuthInfo->replyTimer); 
  
  for(i=0; i< DNPCNFG_AUTHV2_MAX_NUMBER_USERS; i++)
  { 
    SDNPAUTH_USER *pUserContext = &pAuthInfo->authenticationContexts[i]; 
    if(pUserContext->userNumber != 0)
      tmwtimer_cancel(&pUserContext->expectedSessionKeyTimer); 
  }

  sdnpmem_free(pAuthInfo);
}

/* function: sdnpsav2_getKeyStatus */
TMWTYPES_UCHAR TMWDEFS_GLOBAL sdnpsav2_getKeyStatus(
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

/* function: _savePendingRequest */
static void _savePendingRequest(
  TMWSESN_RX_DATA *pRxFragment, 
  SDNPAUTH_INFO *pInfo,
  TMWTYPES_UCHAR fc)
{
  pInfo->pendingRequest = *pRxFragment;
  pInfo->pendingRequest.pMsgBuf = pInfo->pendingData;
  pInfo->pendingRequestFc = fc;
  memcpy(pInfo->pendingRequest.pMsgBuf, pRxFragment->pMsgBuf, pRxFragment->msgLength);
}

/* function: _discardPendingRequest */
static void _discardPendingRequest(
  SDNPAUTH_INFO *pInfo,
  TMWTYPES_ULONG event)
{
  pInfo->pendingRequest.msgLength = 0;
  pInfo->state = SDNPAUTH_STATE_IDLE;
  SDNPDIAG_AUTHDISCARDPENDING(pInfo->pSession, event);
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
    DNPDIAG_SHOW_AUTH_HEADER(pSession, &hdr);
    if(!_getUserAndSequence(&rxMsg, hdr.variation, &sequence, &userNumber))
    {
      return TMWDEFS_NULL;
    }
    switch(hdr.variation) 
    {
    case 1:
      _processChallengeRequest((SDNPSESN*)pSession, &rxMsg); 
      pRxFragment = TMWDEFS_NULL;
      break;

    case 2:
      _processChallengeReply((SDNPSESN*)pSession, &rxMsg);
      pRxFragment = TMWDEFS_NULL;
      break;

    case 3: 
      _processAggrModeRequest((SDNPSESN*)pSession, &rxMsg); 

      /* Skip over the aggressive mode request object at the beginning of message. 
       * _processAggrModeRequest() removed object from end of message already.
       * Moving the original application control byte and the function code to the
       * beginning of the message makes normal DNP processing simpler and more efficient
       */ 
      pRxFragment->pMsgBuf[DNPAUTH_OBJ120V3_SIZE]   = pRxFragment->pMsgBuf[DNPDEFS_AH_INDEX_APPL_CTRL];
      pRxFragment->pMsgBuf[DNPAUTH_OBJ120V3_SIZE+1] = pRxFragment->pMsgBuf[DNPDEFS_AH_INDEX_FUNC_CODE];
      pRxFragment->pMsgBuf += DNPAUTH_OBJ120V3_SIZE;
      pRxFragment->msgLength = rxMsg.msgLength-DNPAUTH_OBJ120V3_SIZE;
      break;

    case 4:
      _processKeyStatusRequest((SDNPSESN*)pSession, &rxMsg); 
      pRxFragment = TMWDEFS_NULL;
      break;

    case 6:
      _processKeyChangeRequest((SDNPSESN*)pSession, &rxMsg, &userNumber); 
      pRxFragment = TMWDEFS_NULL;
      break;

    case 7:
      _processErrorRequest((SDNPSESN*)pSession, &rxMsg, &errorCode); 
      pRxFragment = TMWDEFS_NULL;
      break;

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
  int i;
  for(i=0; i<DNPCNFG_AUTHV2_MAX_NUMBER_USERS; i++)
  { 
    pAuthInfo->authenticationContexts[i].keyStatus = status;
  }
}
 
/* function: sdnpsav2_applTimeout
 * purpose: 
 * arguments:    
 * returns:    
 *  void
 */  
void TMWDEFS_GLOBAL sdnpsav2_applTimeout(
  SDNPSESN *pSDNPSession)
{
  SDNPAUTH_INFO *pInfo = _getAuthInfo(pSDNPSession); 
  if(pInfo != TMWDEFS_NULL)
  {
    DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN *)pSDNPSession, DNPDIAG_AUTH_APPLTIMEOUT);

    /* If application response times out, allow for configured value of these before calling it a COMM_FAIL */ 
    pInfo->applTimeoutCount++;
    if(pInfo->applTimeoutCount > pInfo->maxApplTimeoutCount)
    {
      sdnpsav2_processing((TMWSESN *)pSDNPSession, SDNPAUTH_EVT_COMMFAILUREDETECTED, 0, TMWDEFS_NULL);
      pInfo->applTimeoutCount = 0;
    }
  }
}

/* function: sdnpsav2_applConfirm
 * purpose: 
 * arguments:    
 * returns:    
 *  void
 */  
void TMWDEFS_GLOBAL sdnpsav2_applConfirm(
  SDNPSESN *pSDNPSession)
{
  SDNPAUTH_INFO *pInfo = _getAuthInfo(pSDNPSession); 
  if(pInfo != TMWDEFS_NULL)
    pInfo->applTimeoutCount = 0;
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
TMWSESN_RX_DATA *sdnpsav2_processing(
  TMWSESN *pSession,
  TMWTYPES_ULONG event,
  TMWTYPES_USHORT userNumber,
  TMWSESN_RX_DATA *pRxFragment)
{
  SDNPAUTH_INFO *pInfo; 
  TMWTYPES_ULONG sequenceNumber; 
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

  pInfo = _getAuthInfo(pSDNPSession); 
 
  /* init variable to legal but easily noticeable value.
   */
  sequenceNumber = 0xffff;
  errorCode = DNPAUTH_ERROR_NONE;

  /* init these to prevent warnings */
  rxMsg.pMsgBuf = TMWDEFS_NULL;
  rxMsg.fc = 0;
  rxMsg.ac = 0;
 
  /* This could be processing a received message, or another event such as a timeout
   * first check to see if it is a received message.
   */
  if(event == SDNPAUTH_EVT_MSG_RECEIVED) 
  {
    _parseApplHeader(pRxFragment, &rxMsg);

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
          pInfo->applSequenceNumber = (TMWTYPES_UCHAR)(rxMsg.ac & DNPDEFS_AC_SEQUENCE_MASK);
          event = SDNPAUTH_EVT_CHALLENGE;
          break;

        case 2:
          event = SDNPAUTH_EVT_CHALLENGE_REPLY;
          break;

        case 3:
          pInfo->applSequenceNumber = (TMWTYPES_UCHAR)(rxMsg.ac & DNPDEFS_AC_SEQUENCE_MASK);
          event = SDNPAUTH_EVT_AGGRESSIVE_MODE;
          break;

        case 4: 
          pInfo->applSequenceNumber = (TMWTYPES_UCHAR)(rxMsg.ac & DNPDEFS_AC_SEQUENCE_MASK);
          event = SDNPAUTH_EVT_KEYSTATUSREQ;
          break;

        case 6: 
          pInfo->applSequenceNumber = (TMWTYPES_UCHAR)(rxMsg.ac & DNPDEFS_AC_SEQUENCE_MASK);
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

        default:
          userNumberRcvd = TMWDEFS_FALSE;
          /* invalid variation */
          break;
        }
        
        _msgReceived(pInfo, hdr.variation, userNumber);
      }
    }

    /* Check to see if this is an aggressive mode broadcast message */
    if((event == SDNPAUTH_EVT_AGGRESSIVE_MODE) && (pRxFragment->isBroadcast))
    {
      /* discard aggressive broadcast messages, because they will not work properly. */
      SDNPDIAG_ERROR(pInfo->pSession->pChannel, pInfo->pSession, SDNPDIAG_AUTH_BROAD_DISC);
      return(TMWDEFS_NULL);
    }

    /* if event has not been determined yet */
    if(event == SDNPAUTH_EVT_MSG_RECEIVED)
    {
      if (rxMsg.fc == DNPDEFS_FC_CONFIRM && pSDNPSession->preChallengeApplConf)
      {
        /* discard application confirm that was not sent aggressive mode as requested.
         * 1815-2012 7.5.2.3.2 bullets e,f,g
         */
        SDNPDIAG_ERROR(pInfo->pSession->pChannel, pInfo->pSession, SDNPDIAG_AUTH_NOT_AGGR);
        return(TMWDEFS_NULL);
      }

      /* See if it is a critical message */
      rxMsg.offset = 2;
      if(sdnpdata_authIsCriticalReq(pSDNPSession->pDbHandle, rxMsg.fc, rxMsg.pMsgBuf, rxMsg.msgLength)) 
      { 
        if(pRxFragment->isBroadcast)
        {
          /* discard critical broadcast messages, because we cannot challenge them. */
          SDNPDIAG_ERROR(pInfo->pSession->pChannel, pInfo->pSession, SDNPDIAG_AUTH_BROAD_DISC);
          
          /* Perform the normal broadcast IIN bit and application confirm request behavior?  
           * pSDNPSession->iin |= DNPDEFS_IIN_ALL_STATIONS;
           * if(pRxFragment->rxAddress == DNPDEFS_BROADCAST_ADDR_CON)
           * {
           *   pSDNPSession->allStationsConfirmRequired = TMWDEFS_TRUE;
           * } 
           */
          return(TMWDEFS_NULL);
        }

        pInfo->applSequenceNumber = (TMWTYPES_UCHAR)(rxMsg.ac & DNPDEFS_AC_SEQUENCE_MASK);
        event = SDNPAUTH_EVT_CRITICAL_RCVD;
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
  pUserContext = _findUserContext(pInfo, userNumber); 
  if(userNumberRcvd && (pUserContext == TMWDEFS_NULL) && (event != SDNPAUTH_EVT_ERRORREQ))
  {
    DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_BADUSER); 
    return TMWDEFS_NULL;
  }

   SDNPDIAG_AUTHEVENT((TMWSESN*)pSDNPSession, pInfo->state, event);

  if(pInfo->state == SDNPAUTH_STATE_WAITFORREPLY)
  {
    switch(event)
    {
    case SDNPAUTH_EVT_NONCRITICAL_RCVD:
      /* Table 6 row 2, noncritical
       * Discard ASDU pending authentication, 
       * Increment error count
       * Cancel reply timer
       * If error count is less than MAX, process this noncritical ASDU
       * If error count equals MAX, transmit error message
       * If error count exceeds MAX, behave according to MAX INVALID REPLIES event
       * TMW-No user number for this event
       * TMW-If unsolicited application confirm allow it.
       */ 
      if((rxMsg.msgLength ==2) 
        && ((rxMsg.ac & DNPDEFS_AC_UNSOLICITED) == DNPDEFS_AC_UNSOLICITED))
      { 
        return(pRxFragment);
      }

      _discardPendingRequest(pInfo, SDNPAUTH_EVT_NONCRITICAL_RCVD); 
      tmwtimer_cancel(&pInfo->replyTimer);

      pInfo->errorCount++;
      if(pInfo->errorCount < pInfo->maxErrorCount)
      {
        return(pRxFragment);
      }
      else if (pInfo->errorCount == pInfo->maxErrorCount)
      {  
        /* need to decrement errorCount, since sendErrorMsg increments it */
        pInfo->errorCount--;
        _sendErrorResponse(pSDNPSession, pRxFragment->rxAddress, pInfo->challengeSequenceNumber, 0, DNPAUTH_ERROR_UNEXPECTEDREPLY, TMWDEFS_NULL, 0);   
      }
     
      /* We do not know what user we are challenging, so pUserContext is NULL 
       * In version 4 we would no longer set this to AUTHFAIL because it could be an attack
       * pUserContext->keyStatus = DNPAUTH_KEY_AUTHFAIL;
       */ 
      break;

    case SDNPAUTH_EVT_CRITICAL_RCVD:
      /* Table 6 row 3, critical, discard previous ASDU pending authentication, 
       * Increment the error count
       * If error count is less than MAX, increment CSQ,
       * Create and transmit a challenge request to outstation, 
       * Start reply timer,
       * Queue this critical ASDU for execution later.
       * TMW-user number was determined by sdnpdata_authIsCriticalReq() 
       * If error count equals MAX, transmit error message
       * If error count exceeds MAX, behave according to MAX INVALID REPLIES event
       * TMW-No user number for this event
       */ 
      _discardPendingRequest(pInfo, SDNPAUTH_EVT_CRITICAL_RCVD); 
      tmwtimer_cancel(&pInfo->replyTimer);

      pInfo->errorCount++;
      if(pInfo->errorCount < pInfo->maxErrorCount)
      { 
        pInfo->state = SDNPAUTH_STATE_WAITFORREPLY;
        _sendChallenge(pSDNPSession, pRxFragment->rxAddress, DNPAUTH_REASON_CRITICAL); 

        /* save this message to be processed after challenge reply */
        _savePendingRequest(pRxFragment, pInfo, rxMsg.fc); 
      }  
      else if (pInfo->errorCount == pInfo->maxErrorCount)
      { 
        /* need to decrement errorCount, since sendErrorMsg increments it */
        pInfo->errorCount--;
        _sendErrorResponse(pSDNPSession, pRxFragment->rxAddress, pInfo->challengeSequenceNumber, 0, DNPAUTH_ERROR_UNEXPECTEDREPLY, TMWDEFS_NULL, 0);  
      } 
       
      /* We do not know what user we are challenging, so pUserContext is NULL 
       * In version 4 we would no longer set this to AUTHFAIL because it could be an attack
       * pUserContext->keyStatus = DNPAUTH_KEY_AUTHFAIL;
       */ 

      break; 

    case SDNPAUTH_EVT_CHALLENGE_REPLY:
      /* Table 6, Row 5 and 6
       * if valid, process queued ASDU, 
       *   Cancel reply timer
       *   Reset error count to zero
       * if invalid, increment error count
       *   Discard ASDU that was queued pending authentication 
       *   Send error message reason 1 Auth Failed
       *   Cancel the reply timer
       *   If max errors exceeded behave as MAXINVALIDRESPONSES event
       * TMW-User number for this event, but do not check it, authentication would fail if wrong...
       */
      tmwtimer_cancel(&pInfo->replyTimer);
      pInfo->state = SDNPAUTH_STATE_IDLE; 

#ifdef TMW_PRIVATE_AUTHTEST
      if(pInfo->forceErrorMessage)
      {
        pInfo->forceErrorMessage = TMWDEFS_FALSE; 
        DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_FORCEDERROR);
        _sendErrorResponse(pSDNPSession, pRxFragment->rxAddress, pInfo->challengeSequenceNumber, pInfo->currentUserNumber, DNPAUTH_ERROR_AUTHENTFAILED, "forced error message for testing", 32);
        return TMWDEFS_NULL;
      }
#endif
      if(_processChallengeReply(pSDNPSession, &rxMsg))
      {      
        pInfo->rcvdAtLeastOneChallengeResponse = TMWDEFS_TRUE;
        pInfo->errorCount = 0;
        if(pInfo->pendingRequest.msgLength > 0)
        {
          /* ask database if this user is allowed to issue this request */  
          if(sdnpdata_authRequestAllowed(pSDNPSession->pDbHandle, userNumber, pInfo->pendingRequestFc, pInfo->pendingRequest.pMsgBuf, pInfo->pendingRequest.msgLength))
          {
            return(&pInfo->pendingRequest);
          }
          else
          {
            _discardPendingRequest(pInfo, SDNPAUTH_EVT_CHALLENGE_REPLY);
            _sendErrorResponse(pSDNPSession, pRxFragment->rxAddress, pInfo->challengeSequenceNumber, userNumber, DNPAUTH_ERROR_AUTHORFAILED, TMWDEFS_NULL, 0);
          }
        }
      } 
      else
      {
        _discardPendingRequest(pInfo, SDNPAUTH_EVT_CHALLENGE_REPLY);
        _sendErrorResponse(pSDNPSession, pRxFragment->rxAddress, pInfo->challengeSequenceNumber, userNumber, DNPAUTH_ERROR_AUTHENTFAILED, TMWDEFS_NULL, 0);
        if(pInfo->errorCount > pInfo->maxErrorCount)
        {
          _setKeyStatus(pUserContext, DNPAUTH_KEY_AUTHFAIL);
        }
      }   
      break; 

    case SDNPAUTH_EVT_REPLYTIMEOUT:
      /* Table 6, Row 7, 
       *   Increment error count
       *   Cancel reply timer, (it already timed out)
       *   Discard ASDU that was queued pending authentication 
       *   Send error reason 3 No Reply
       *   If max error count exceeded, behave as MAXINVALIDREPLIES event
       *   TMW-user number is unknown on outstation challenge, zero does not have a user context.
       */
      _discardPendingRequest(pInfo,SDNPAUTH_EVT_REPLYTIMEOUT); 
      _sendErrorResponse(pSDNPSession, pSDNPSession->dnp.tmw.destAddress, pInfo->challengeSequenceNumber, 0, DNPAUTH_ERROR_NOREPLY, TMWDEFS_NULL, 0);  
      break;

    case SDNPAUTH_EVT_MAXINVALIDREPLIES:
      /* Table 6, Row 9, 
       * Discard ASDU that was queued pending authentication
       * set current key status to Auth Fail
       * set state to Idle 
       * TMW-only the current user could have max invalid retries, only affects current user.
       *  but as always we don't know what user.
       */ 
      _discardPendingRequest(pInfo, SDNPAUTH_EVT_MAXINVALIDREPLIES);
      _setKeyStatus(pUserContext, DNPAUTH_KEY_AUTHFAIL);
      break;

    case SDNPAUTH_EVT_COMMFAILUREDETECTED: 
      /* Table 6, Row 9, set current key status to Auth Fail
       * set state to Idle
       * TMW-No user. Affects ALL users. Set them to COMMFAIL
       */ 
      _discardPendingRequest(pInfo, SDNPAUTH_EVT_COMMFAILUREDETECTED);  

      _setAllUsersKeyStatus(pInfo, DNPAUTH_KEY_COMMFAIL); 

      /* currentUserNumber is always zero, we don't know who we are challenging  
       * pUserContext = _findUserContext(pInfo, pInfo->currentUserNumber); 
       * if(pUserContext != TMWDEFS_NULL)
       * pUserContext->keyStatus = DNPAUTH_KEY_AUTHFAIL;
       */
      break;

    case SDNPAUTH_EVT_ERRORREQ:
      /* Table 6, Row 9, Log the error message, 
       * if error code is 5 MAC algorithm not permitted
       * use a different algorithm next challenge.
       * Discard ASDU that was queued pending authentication and cancel reply timer.
       * TMW-User number present, but dont check.
       */ 
      if(_processErrorRequest(pSDNPSession, &rxMsg, &errorCode))
      {
        tmwtimer_cancel(&pInfo->replyTimer);
        if(errorCode == DNPAUTH_ERROR_MACNOTPERMIT)
        {
          /* if code == 5 use a different algorithm for next challenge  */
          DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_MACDEFAULT);  
          pInfo->MACAlgorithm = DNPAUTH_MAC_SHA1_10OCTET; 
        }
        _discardPendingRequest(pInfo, SDNPAUTH_EVT_ERRORREQ); 
      }
      break;

    case SDNPAUTH_EVT_EXPECTEDKEYTIMEOUT:
      /* Table 6 row 12 and 13, 
       * set key status NOT INIT and invalidate session keys  
       * if this timeout is for this user, 
       *  Discard ASDU that was queued pending authentication and cancel reply timer. 
       */  
      if(pUserContext != TMWDEFS_NULL)
      {
        pUserContext->keyStatus = DNPAUTH_KEY_NOTINIT;
        pUserContext->controlSessionKeyV2.length = 0;
        pUserContext->monitorSessionKeyV2.length = 0;
      }
      /* currentUserNumber is always zero, we don't know who we are challenging 
       * if(userNumber == pInfo->currentUserNumber)
       * {
       *   pUserContext->controlSessionKeyV2.length = 0;
       *   pUserContext->monitorSessionKeyV2.length = 0;
       *   tmwtimer_cancel(&pInfo->replyTimer);
       *   _discardPendingRequest(pInfo, SDNPAUTH_EVT_EXPECTEDKEYTIMEOUT);
       * }
       */
      break;

    case SDNPAUTH_EVT_KEYSTATUSREQ: 
      /* Table 6, Row 14 
       * Discard ASDU pending authentication
       * Transmit key status message containing current key status  
       * Cancel the reply timer.
       * go to Idle state
       * TMW-user number for this event, use it for key status response.
       */ 
      tmwtimer_cancel(&pInfo->replyTimer);
      _discardPendingRequest(pInfo, SDNPAUTH_EVT_KEYSTATUSREQ);
      _processKeyStatusRequest(pSDNPSession, &rxMsg);
      break;
 
    case SDNPAUTH_EVT_AGGRESSIVE_MODE:
      /* According to Table 6, Row 15, 16, and 17
       * In all cases discard ASDU pending authentication and cancel reply timer
       * If valid, and aggressive mode enabled, process this aggressive mode message
       * If valid and aggressive mode disabled, send error message Aggressive Mode not supported
       * If invalid send error message with UnexpectedReply or Aggressive Mode not supported.
       * TMW-user number present, discarding message, do not check.
       */
      tmwtimer_cancel(&pInfo->replyTimer);
      _discardPendingRequest(pInfo, SDNPAUTH_EVT_AGGRESSIVE_MODE);

      errorCode = DNPAUTH_ERROR_NONE;

      if(!pInfo->aggressiveModeSupport)
      {
        errorCode = DNPAUTH_ERROR_AGGRESSNOTPERMIT;
      } 
      else if((!pInfo->rcvdAtLeastOneChallengeResponse)
        ||(!_processAggrModeRequest(pSDNPSession, &rxMsg))) 
      {
        errorCode = DNPAUTH_ERROR_UNEXPECTEDREPLY;
      } 
      else
      {
        /* to make static code checker happy */
        if (rxMsg.pMsgBuf != TMWDEFS_NULL)
        {
          /* Skip over the aggressive mode request object at the beginning of message. 
           * _processAggrModeRequest() removed object from end of message already.
           * Moving the original application control byte and the function code to the
           * beginning of the message makes normal DNP processing simpler and more efficient
           */ 
          pRxFragment->pMsgBuf[DNPAUTH_OBJ120V3_SIZE]   = pRxFragment->pMsgBuf[DNPDEFS_AH_INDEX_APPL_CTRL];
          pRxFragment->pMsgBuf[DNPAUTH_OBJ120V3_SIZE+1] = pRxFragment->pMsgBuf[DNPDEFS_AH_INDEX_FUNC_CODE];
          pRxFragment->pMsgBuf += DNPAUTH_OBJ120V3_SIZE;
          pRxFragment->msgLength = rxMsg.msgLength-DNPAUTH_OBJ120V3_SIZE;

          /* ask database if this user is allowed to issue this request */
          if (sdnpdata_authRequestAllowed(pSDNPSession->pDbHandle, userNumber, rxMsg.fc, pRxFragment->pMsgBuf, pRxFragment->msgLength))
          {
            return(pRxFragment);
          }
          else
          {
            errorCode = DNPAUTH_ERROR_AUTHORFAILED;
          }
        }
      } 
      _sendErrorResponse(pSDNPSession, pSDNPSession->dnp.tmw.destAddress, pInfo->challengeSequenceNumber, userNumber, errorCode, TMWDEFS_NULL, 0);
      break; 

    case SDNPAUTH_EVT_KEYCHANGEREQ:
      /* Table 6, Row 18 and 19
       * If Valid Key Change
       *  Discard ASDU pending authentication
       *  Store new Keys, set Key Status OK
       *  Transmit Key Status Message
       *  Cancel Reply timer
       *  Reset Error count to zero 
       * If invalid Key Change 
       *   Discard invalid key change message
       *     Could be denial of service, 
       *     Do not send error message
       *     Do not discard ASDU pending authentication
       *   Stay in wait for reply state  
       * TMW-user number received, use for key change and status response.
       */
      if(_processKeyChangeRequest(pSDNPSession, &rxMsg, &userNumber))
      {  
        tmwtimer_cancel(&pInfo->replyTimer);
        _discardPendingRequest(pInfo, SDNPAUTH_EVT_KEYCHANGEREQ);
        if (pUserContext != TMWDEFS_NULL)
        {
          pUserContext->keyStatus = DNPAUTH_KEY_OK;
          pInfo->errorCount = 0;
          _startExpectedKeyChangeTimer(pInfo, pUserContext->userNumber, pInfo->keyChangeInterval);
        }
        _sendKeyStatusResponse(pSDNPSession, pRxFragment->rxAddress, userNumber); 
      }
      break;

    case SDNPAUTH_EVT_CHALLENGE:   
      /* According to Table 6, Row 20
       * Discard ASDU pending authentication 
       * Cancel reply timer 
       * Send error message with UnexpectedReply
       * if maximum error count has been exceeded 
       *   act according to MAXINVALIDREPLIES
       * TMW-user number received, send back in error response
       */
      tmwtimer_cancel(&pInfo->replyTimer);
       _discardPendingRequest(pInfo, SDNPAUTH_EVT_CHALLENGE);
      _sendErrorResponse(pSDNPSession, pSDNPSession->dnp.tmw.destAddress, pInfo->challengeSequenceNumber, userNumber, DNPAUTH_ERROR_UNEXPECTEDREPLY, TMWDEFS_NULL, 0);

      if(pInfo->errorCount > pInfo->maxErrorCount)
      {
        /* same as max invalid replies event */ 
        _setKeyStatus(pUserContext, DNPAUTH_KEY_AUTHFAIL);
      }
      break;

    default:
      break;
    }
  }
  else  /* pInfo->state == SDNPAUTH_STATE_IDLE */ 
  { 
    switch(event)
    {
    case SDNPAUTH_EVT_NONCRITICAL_RCVD:
      /* Table 6, Row 2 rx noncritical, 
       * Process the Non-Critical ASDU and transmit response as required by protocol. 
       * Pass it on to rest of DNP stack
       */ 
      return(pRxFragment);
      break;

    case SDNPAUTH_EVT_CRITICAL_RCVD:
      /* Table 6, Row 3, Rx Critical, 
       * Increment Challenge Sequence Number, 
       * Create and transmit a challenge message
       * Start reply timer, 
       * Queue critical ASDU for execution later 
       * Go to WaitForReply state
       */
      pInfo->state = SDNPAUTH_STATE_WAITFORREPLY;
      _sendChallenge(pSDNPSession, pRxFragment->rxAddress, DNPAUTH_REASON_CRITICAL); 

      /* save this message to be processed after challenge reply */
      _savePendingRequest(pRxFragment, pInfo, rxMsg.fc); 
      break;

    case SDNPAUTH_EVT_CHALLENGE_REPLY:
      /* Table 6, Row 5 and 6, discard challenge reply message, stay in idle state */ 
      break;

    case SDNPAUTH_EVT_REPLYTIMEOUT:
      /* Table 6, Row 7, Should not occur, stay in idle state */
      break;

    case SDNPAUTH_EVT_MAXINVALIDREPLIES:   
      /* Table 6, Row 9, Set key status to NOT INIT, stay in idle state
       * TMW-MAXINVALIDREPLIES cannot happen when IDLE
       * Let code set all users to NOT INIT.
       */
      _setAllUsersKeyStatus(pInfo, DNPAUTH_KEY_NOTINIT); 
      break;
  
    case SDNPAUTH_EVT_COMMFAILUREDETECTED:  
      _setAllUsersKeyStatus(pInfo, DNPAUTH_KEY_COMMFAIL); 
      break;

    case SDNPAUTH_EVT_ERRORREQ:
      /* Table 6, Row 10, 
       * log the error message, noting it was unexpected 
       * TMW-Now that there are only two states on outstation, this error
       *  might not be unexpected.
       */ 
      if(_processErrorRequest(pSDNPSession, &rxMsg, &errorCode))
      {
        if(errorCode == DNPAUTH_ERROR_KEYWRAPNOTPERMIT)
        { 
          /* use default key wrap algorithm */
          DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_KEYWRAPDEFAULT); 
        }
      }
    break;
      
    case SDNPAUTH_EVT_EXPECTEDKEYTIMEOUT:
      /* Table 6, Row 12,
       * Set key status NOT INIT, invalidate current session keys 
       * Stay in Idle state.
       */  
      if (pUserContext != TMWDEFS_NULL)
      {
        pUserContext->keyStatus = DNPAUTH_KEY_NOTINIT;
        pUserContext->controlSessionKeyV2.length = 0;
        pUserContext->monitorSessionKeyV2.length = 0;
      }
      break;

    case SDNPAUTH_EVT_KEYSTATUSREQ:  
      /* Table 6, Row 14,
       * Transmit a key status message with current key status
       */ 
      _processKeyStatusRequest(pSDNPSession, &rxMsg);
      break;
      
    case SDNPAUTH_EVT_AGGRESSIVE_MODE:
      /* Table 6, Row 15, 16 and 17
       * If aggressive mode is not enabled send error
       * If aggressive mode is supported, but it fails
       *   send error
       * If aggressive mode is supported and it succeeds process ASDU.
      */
#ifdef TMW_PRIVATE_AUTHTEST
      if(pInfo->forceErrorMessage)
      {
        pInfo->forceErrorMessage = TMWDEFS_FALSE;         
        DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_FORCEDERROR);
        _sendErrorResponse(pSDNPSession, pRxFragment->rxAddress, pInfo->challengeSequenceNumber, pInfo->currentUserNumber, DNPAUTH_ERROR_AUTHENTFAILED, "forced error message for testing", 32);
        return TMWDEFS_NULL;
      }
#endif
      if(!pInfo->aggressiveModeSupport)
      { 
        errorCode = DNPAUTH_ERROR_AGGRESSNOTPERMIT;
      }      
      else if((!pInfo->rcvdAtLeastOneChallengeResponse)
        ||(!_processAggrModeRequest(pSDNPSession, &rxMsg))) 
      {
        errorCode = DNPAUTH_ERROR_AUTHENTFAILED;
      }
      else
      {
        /* to make static code checker happy */
        if (rxMsg.pMsgBuf != TMWDEFS_NULL)
        {
          /* remove aggressive mode objects from beginning of message
           * _processAggrModeRequest() removed object from end of message already.
           *  Removing these makes normal DNP processing simpler and more efficient
           */
          memcpy(&pRxFragment->pMsgBuf[2], &rxMsg.pMsgBuf[12], rxMsg.msgLength - 10);
          pRxFragment->msgLength = rxMsg.msgLength - 10;

          /* ask database if this user is allowed to issue this request */
          if (sdnpdata_authRequestAllowed(pSDNPSession->pDbHandle, userNumber, rxMsg.fc, pRxFragment->pMsgBuf, pRxFragment->msgLength))
          {
            return(pRxFragment);
          }
          else
          {
            errorCode = DNPAUTH_ERROR_AUTHORFAILED;
          }
        }
      } 
      _sendErrorResponse(pSDNPSession, pRxFragment->rxAddress, sequenceNumber, userNumber, errorCode, TMWDEFS_NULL, 0);
      break;
    
    case SDNPAUTH_EVT_KEYCHANGEREQ: 
      /* Table 6, Row 18 and 19
       * if valid,
       *  Store new keys,
       *  Set key status OK,
       *  Transmit key status message
       *  Set error count to zero
       * if invalid,
       *  Set key status Auth Fail, 
       *  Transmit key status message.
       */
#ifdef TMW_PRIVATE_AUTHTEST
      if(pInfo->forceErrorMessage)
      {
        pInfo->forceErrorMessage = TMWDEFS_FALSE;         
        DNPDIAG_ERROR(pSDNPSession->dnp.tmw.pChannel, (TMWSESN*)pSDNPSession, DNPDIAG_AUTH_FORCEDERROR); 
        _setKeyStatus(pUserContext, DNPAUTH_KEY_AUTHFAIL);
        _sendKeyStatusResponse(pSDNPSession, pRxFragment->rxAddress, userNumber); 
        return TMWDEFS_NULL;
      }
#endif
      if(_processKeyChangeRequest(pSDNPSession, &rxMsg, &userNumber))
      {
        _setKeyStatus(pUserContext, DNPAUTH_KEY_OK);
        pInfo->errorCount = 0; 
        _sendKeyStatusResponse(pSDNPSession, pRxFragment->rxAddress, userNumber); 
 
        /* restart expectedSessionKeyTimer timer */ 
        _startExpectedKeyChangeTimer(pInfo, pUserContext->userNumber, pInfo->keyChangeInterval);  
      }
      else
      {
        _setKeyStatus(pUserContext, DNPAUTH_KEY_AUTHFAIL);
        _sendKeyStatusResponse(pSDNPSession, pRxFragment->rxAddress, userNumber); 
      }
      break;

    case SDNPAUTH_EVT_CHALLENGE:  
      /* Table 6 row 20 */
      _processChallengeRequest(pSDNPSession, &rxMsg); 
      break; 

    default:
      break;
    }
  }
  return(TMWDEFS_NULL);
} 


TMWTYPES_BOOL TMWDEFS_CALLBACK sdnpsav2_OKToSend(
  TMWSESN *pSession)
{ 
  SDNPSESN *pSDNPSession = (SDNPSESN *)pSession;
  SDNPAUTH_INFO *pInfo = (SDNPAUTH_INFO*)pSDNPSession->pAuthenticationInfo;
  if(pInfo != TMWDEFS_NULL) 
  {
    if(pInfo->state == SDNPAUTH_STATE_WAITFORREPLY) 
    {
      return TMWDEFS_FALSE;
    }
  }
  return TMWDEFS_TRUE; 
}

void TMWDEFS_CALLBACK sdnpsav2_saveLastChallenge(
  TMWSESN_TX_DATA *pTxData)
{
  SDNPAUTH_INFO *pInfo = _getAuthInfo((SDNPSESN*)pTxData->pSession);
  if(pInfo!=TMWDEFS_NULL)
  {
    /* copy challenge that was actually transmitted */
    if(pTxData->msgLength <= SDNPAUTH_TXCHALLENGEMAXSIZE)
    {
      memcpy(pInfo->lastChallengeSent, pTxData->pMsgBuf, pTxData->msgLength);
      pInfo->lastChallengeSentLength = pTxData->msgLength;
    }
    else
    {
      DNPDIAG_ERROR(pTxData->pSession->pChannel, pTxData->pSession, DNPDIAG_AUTH_TOO_BIG);
    }
  }
}

#ifdef TMW_PRIVATE_AUTHTEST

TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpsav2_forceSessionKeyTimeout( 
  TMWSESN *pSession,
  TMWTYPES_USHORT userNumber)
{
  SDNPSESN *pSDNPSession = (SDNPSESN *)pSession;
  SDNPAUTH_INFO *pInfo = (SDNPAUTH_INFO*)pSDNPSession->pAuthenticationInfo;
  if(pInfo != TMWDEFS_NULL)
  {
    SDNPAUTH_USER *pUserContext = _findUserContext(pInfo, userNumber);  
    if(pUserContext != TMWDEFS_NULL)
    {
      tmwtimer_start(&pUserContext->expectedSessionKeyTimer, 10,
        pSDNPSession->dnp.tmw.pChannel, _expectedKeyChangeTimeout, pUserContext); 
      return(TMWDEFS_TRUE);
    }
  }
  return(TMWDEFS_FALSE);
}  

TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpsav2_forceErrorMessage(
  TMWSESN *pSession)
{ 
  SDNPSESN *pSDNPSession = (SDNPSESN *)pSession;
  SDNPAUTH_INFO *pInfo = (SDNPAUTH_INFO*)pSDNPSession->pAuthenticationInfo;
  if(pInfo != TMWDEFS_NULL)
  {
    pInfo->forceErrorMessage = TMWDEFS_TRUE;
  }
  return TMWDEFS_TRUE;
}
#endif

#endif /* SDNPDATA_SUPPORT_OBJ120 */

