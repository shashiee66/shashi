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

/* file: sdnpo120.c
 * description: DNP Slave functionality for Object 120 Secure Authentication
 */
#include "tmwscl/dnp/dnpdiag.h"
#include "tmwscl/dnp/sdnpdiag.h"
#include "tmwscl/utils/tmwtarg.h"

#include "tmwscl/dnp/sdnpo120.h"
#include "tmwscl/dnp/sdnpdata.h"
#include "tmwscl/dnp/sdnpsesn.h"
#include "tmwscl/dnp/sdnputil.h"
#include "tmwscl/dnp/dnpdtime.h"
#include "tmwscl/dnp/sdnpevnt.h"
#if SDNPCNFG_SUPPORT_SA_VERSION5
#include "tmwscl/dnp/sdnpsa.h"
#endif

#if SDNPDATA_SUPPORT_OBJ120
  
TMWTYPES_BOOL TMWDEFS_CALLBACK sdnpo120_readObj120Var7(
  SDNPEVNT *pEvent,
  TMWSESN_TX_DATA *pResponse,
  TMWDEFS_CLASS_MASK classMask)
{ 
  TMWTYPES_USHORT lengthIndex;   
  TMWTYPES_USHORT length;
  TMWTYPES_MS_SINCE_70 msSince70;
  SDNPEVNT_0120_EVENT *p120Event = (SDNPEVNT_0120_EVENT *)pEvent;

  if((p120Event->sdnp.classMask & classMask) != 0)
  {
    /* Save index for where to put 2 byte length */
    lengthIndex = pResponse->msgLength;
    pResponse->msgLength += 2;
      
    /* Add object data */ 
    tmwtarg_store32(&p120Event->sequenceNumber, pResponse->pMsgBuf + pResponse->msgLength);
    pResponse->msgLength += 4;

      /* User Number */
    tmwtarg_store16(&p120Event->sdnp.point, pResponse->pMsgBuf + pResponse->msgLength);
    pResponse->msgLength += 2;

    /* Link Id */
    tmwtarg_store16(&p120Event->assocId, pResponse->pMsgBuf + pResponse->msgLength);
    pResponse->msgLength += 2;

    pResponse->pMsgBuf[pResponse->msgLength++] = p120Event->errorCode;
    
    /* Write 48 bit event time */ 
    dnpdtime_dateTimeToMSSince70(&msSince70, &p120Event->sdnp.timeStamp);

    dnpdtime_writeMsSince70(&pResponse->pMsgBuf[pResponse->msgLength], &msSince70);
    pResponse->msgLength += 6;
    
    /* Optional error text
     * Make sure there is room
     */
    if(p120Event->errorTextLength > 0)
    {
      if ((pResponse->msgLength + p120Event->errorTextLength) > pResponse->maxLength)
      {
        /* If this would not even fit as the first object of a fragment, then truncate the string 
         * so it will fit in this response fragment
         */
        if ((17 + p120Event->errorTextLength) > pResponse->maxLength)
        {
          p120Event->errorTextLength = pResponse->maxLength - pResponse->msgLength;
        }
        else
        {
          pResponse->msgLength -= 17;
          return(TMWDEFS_FALSE);
        }
      }
 
      memcpy(&pResponse->pMsgBuf[pResponse->msgLength], p120Event->errorTextBuf, p120Event->errorTextLength);
      pResponse->msgLength = pResponse->msgLength + p120Event->errorTextLength;
    }

    /* Update the length in the object prefix. length of error text data +15 */
    length = p120Event->errorTextLength + 15;
    tmwtarg_store16(&length, pResponse->pMsgBuf + lengthIndex);
      
    /* Diagnostics */
    DNPDIAG_SHOW_AUTH_ERROR(p120Event->sdnp.pSession, p120Event->sdnp.point, p120Event->assocId, p120Event->sequenceNumber, p120Event->errorCode, &p120Event->sdnp.timeStamp, (TMWTYPES_CHAR*)p120Event->errorTextBuf, p120Event->errorTextLength, TMWDEFS_TRUE, 0);
        
    return(TMWDEFS_TRUE);
  }
 
  return(TMWDEFS_FALSE);
}

/* function: _initEventDesc */
static void TMWDEFS_LOCAL _initEventDesc(
  TMWSESN *pSession,
  SDNPEVNT_DESC *pDesc)
{
  SDNPSESN *pSDNPSession = (SDNPSESN *)pSession;
  pDesc->pSession = pSession;
  pDesc->group = DNPDEFS_OBJ_120_AUTHENTICATION;
  pDesc->quantity = 0;
  pDesc->eventMemType = SDNPMEM_OBJECT120_EVENT_TYPE;
  pDesc->pEventList = &pSDNPSession->obj120Events;

  /* G120V7 says only the most recent Auth Error event object shall be buffered */
  pDesc->eventMode = TMWDEFS_EVENT_MODE_MOST_RECENT;
  pDesc->maxEvents = 1; 

#if SDNPDATA_SUPPORT_EVENT_SCAN
  pDesc->pGetPointAndClass = TMWDEFS_NULL;
  pDesc->pChangedFunc = TMWDEFS_NULL;
#endif
#if SDNPDATA_SUPPORT_EVENT_VAR_POINT
  pDesc->pGetPointAndDefault = TMWDEFS_NULL;
  pDesc->pSetVariationInfo = TMWDEFS_NULL;
#endif
#if SDNPDATA_SUPPORT_EVENT_MODE_POINT
  pDesc->pGetPointAndEventMode = TMWDEFS_NULL;
#endif
  pDesc->variation = 7; 
  pDesc->readVariation = 7;

  /* At least room for mandatory elements */
  pDesc->sizeInBytes = 17;
}

/* function: sdnpo120_init */
void TMWDEFS_GLOBAL sdnpo120_init(
  TMWSESN *pSession)
{
  SDNPSESN *pSDNPSession = (SDNPSESN *)pSession;
  sdnpevnt_init(
    TMWDEFS_NULL, 
    &pSDNPSession->obj120Events);
}

/* function: sdnpo120_close */
void TMWDEFS_GLOBAL sdnpo120_close(
  TMWSESN *pSession)
{
  SDNPSESN *pSDNPSession = (SDNPSESN *)pSession;
  sdnpevnt_close(&pSDNPSession->obj120Events);
}

void TMWDEFS_GLOBAL sdnpo120_sendErrorResponseV7(
  TMWSESN         *pSession,   
  TMWTYPES_USHORT  rxAddress,
  TMWTYPES_USHORT  userNumber,
  TMWTYPES_ULONG   sequenceNumber,
  TMWTYPES_UCHAR   errorCode,
  TMWTYPES_CHAR   *pErrorText,
  TMWTYPES_USHORT   errorTextLength)
{
#if SDNPCNFG_SUPPORT_SA_VERSION5
  sdnpsa_sendErrorResponseV7((SDNPSESN *)pSession, rxAddress, sequenceNumber, 
    userNumber, errorCode, pErrorText, errorTextLength); 
#else
  TMWTARG_UNUSED_PARAM(pSession);
  TMWTARG_UNUSED_PARAM(rxAddress);
  TMWTARG_UNUSED_PARAM(userNumber);
  TMWTARG_UNUSED_PARAM(sequenceNumber);
  TMWTARG_UNUSED_PARAM(errorCode);
  TMWTARG_UNUSED_PARAM(pErrorText);
  TMWTARG_UNUSED_PARAM(errorTextLength);
#endif
}

/* function: sdnpo120_addEvent */
void TMWDEFS_GLOBAL sdnpo120_addEvent(
  TMWSESN         *pSession, 
  TMWTYPES_USHORT  userNumber,
  TMWTYPES_USHORT  assocId,
  TMWTYPES_ULONG   sequenceNumber,
  TMWTYPES_UCHAR   errorCode,
  TMWDTIME        *pTimeStamp,
  TMWTYPES_CHAR   *pErrorText,
  TMWTYPES_USHORT  errorTextLength)
{
  TMWDEFS_CLASS_MASK eventClass;
  SDNPSESN *pSDNPSession = (SDNPSESN *)pSession;
#if TMWCNFG_SUPPORT_THREADS
  TMWDEFS_RESOURCE_LOCK *pLock = &pSession->pChannel->lock;
#endif
  SDNPEVNT_DESC desc;
  SDNPDATA_ADD_EVENT_VALUE value;

  _initEventDesc(pSession, &desc);

  TMWTARG_LOCK_SECTION(pLock);
  value.authError.assocId = assocId;
  value.authError.errorCode = errorCode;
  value.authError.errorTextLength = errorTextLength;
  value.authError.pErrorText = pErrorText;
  value.authError.sequenceNumber =  sequenceNumber;
 
  eventClass = sdnpdata_authErrorEventClass(pSDNPSession->pDbHandle); 
  sdnpevnt_addEvent(pSession, userNumber, 0, eventClass, pTimeStamp, &desc, &value);

  TMWTARG_UNLOCK_SECTION(pLock);
}

/* function: sdnpo120_countEvents */
TMWTYPES_USHORT TMWDEFS_GLOBAL sdnpo120_countEvents(
  TMWSESN *pSession, 
  TMWDEFS_CLASS_MASK classMask,
  TMWTYPES_BOOL countAll,
  TMWTYPES_USHORT threshold)
{
  SDNPEVNT_DESC desc;
  _initEventDesc(pSession, &desc);
  return(sdnpevnt_countEvents(pSession, classMask, &desc, countAll, threshold));
}

/* function: sdnpo120_cleanupEvents() */
TMWTYPES_BOOL TMWDEFS_GLOBAL sdnpo120_cleanupEvents(
  TMWSESN *pSession, 
  TMWTYPES_BOOL deleteEvents)
{
  SDNPEVNT_DESC desc;
  _initEventDesc(pSession, &desc);
  return(sdnpevnt_cleanupEvents(deleteEvents, &desc));
}

/* function: sdnpo120_readObj120ByClass */
SDNPSESN_READ_STATUS TMWDEFS_CALLBACK sdnpo120_readObj120ByClass(
  TMWSESN *pSession,
  DNPUTIL_RX_MSG *pRequest,
  TMWSESN_TX_DATA *pResponse, 
  DNPUTIL_OBJECT_HEADER *pObjHeader,
  TMWDEFS_CLASS_MASK classMask)
{
  SDNPEVNT_DESC desc;
  TMWTARG_UNUSED_PARAM(pRequest);

  _initEventDesc(pSession, &desc);  
   
  return(sdnpevnt_readEvents(pSession, pResponse, pObjHeader, classMask, &desc));
}

#if SDNPDATA_SUPPORT_ASSIGN
/* function: sdnpo120_assignClass */
TMWTYPES_BOOL TMWDEFS_CALLBACK sdnpo120_assignClass(
  TMWSESN *pSession,
  DNPUTIL_RX_MSG *pRxFragment,
  DNPUTIL_OBJECT_HEADER *pObjHeader,
  TMWDEFS_CLASS_MASK classMask)
{
  SDNPSESN *pSDNPSession = (SDNPSESN *)pSession;
  TMWTARG_UNUSED_PARAM(pRxFragment);
  TMWTARG_UNUSED_PARAM(pObjHeader);
  
  /* Only qualfier ALL makes sense, since there are no points for authentication events. */
  if(pObjHeader->qualifier == DNPDEFS_QUAL_ALL_POINTS)
    return(sdnpdata_authAssignClass(pSDNPSession->pDbHandle, classMask));
  else
    return TMWDEFS_FALSE;
}
#endif 
#endif /* SDNPDATA_SUPPORT_OBJ120 */
