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

/* file: sdnpo050.c
 * description: DNP Slave functionality for Object 50 Time and Date
 */
#include "tmwscl/dnp/dnpdiag.h"
#include "tmwscl/dnp/sdnpdiag.h"
#include "tmwscl/utils/tmwtarg.h"
#include "tmwscl/utils/tmwtimer.h"

#include "tmwscl/dnp/sdnpo050.h"
#include "tmwscl/dnp/sdnpdata.h"
#include "tmwscl/dnp/sdnpsesn.h"
#include "tmwscl/dnp/dnpdtime.h"

#if SDNPDATA_SUPPORT_OBJ50
static void TMWDEFS_CALLBACK _clockValidTimeout(
  void *pParam)
{
  SDNPSESN *pSDNPSession = (SDNPSESN *)pParam;
  if(pSDNPSession->respondNeedTime == TMWDEFS_TRUE)
    pSDNPSession->iin |= DNPDEFS_IIN_NEED_TIME;
}
#endif

#if SDNPDATA_SUPPORT_OBJ50_V1
/* function: sdnpo050_readObj50v1 */
SDNPSESN_READ_STATUS TMWDEFS_CALLBACK sdnpo050_readObj50v1(
  TMWSESN *pSession, 
  DNPUTIL_RX_MSG *pRequest,
  TMWSESN_TX_DATA *pResponse, 
  DNPUTIL_OBJECT_HEADER *pObjHeader,
  SDNPSESN_QUAL qualifier)
{
  TMWTYPES_MS_SINCE_70 msSince70;
  TMWDTIME dateTime;

  TMWTARG_UNUSED_PARAM(pRequest);
  TMWTARG_UNUSED_PARAM(pObjHeader);

  if(qualifier != SDNPSESN_QUAL_BUILD_RESPONSE)
    return(SDNPSESN_READ_COMPLETE);

  /* Make sure we'll fit */
  if((pResponse->msgLength + 10) > pResponse->maxLength)
    return(SDNPSESN_READ_MORE_DATA);

  /* Store object group, variation, and qualifier */
  pResponse->pMsgBuf[pResponse->msgLength++] = DNPDEFS_OBJ_50_TIME_AND_DATE;
  pResponse->pMsgBuf[pResponse->msgLength++] = 1;
  pResponse->pMsgBuf[pResponse->msgLength++] = 7;
  pResponse->pMsgBuf[pResponse->msgLength++] = 1;

  /* Get current date and time */
  tmwdtime_getDateTime(pSession, &dateTime); 

  /* Diagnostics */
  DNPDIAG_SHOW_TIME_AND_DATE_SENT(pSession, &dateTime);

  /* Convert to milliseconds since 1970 */
  dnpdtime_dateTimeToMSSince70(&msSince70, &dateTime);

  /* Write into response */
  dnpdtime_writeMsSince70(pResponse->pMsgBuf + pResponse->msgLength, &msSince70);
  pResponse->msgLength += 6;

  return(SDNPSESN_READ_COMPLETE);
}

/* function: sdnpo050_writeObj50v1 */
TMWTYPES_BOOL TMWDEFS_CALLBACK sdnpo050_writeObj50v1(
  TMWSESN *pSession,
  DNPUTIL_RX_MSG *pRxFragment,
  TMWSESN_TX_DATA *pResponse,
  DNPUTIL_OBJECT_HEADER *pObjHeader)
{
  SDNPSESN *pSDNPSession = (SDNPSESN *)pSession;
  TMWTYPES_MS_SINCE_70 msSince70;
  TMWTYPES_MILLISECONDS deltaTime;
  TMWDTIME tmwtime;

  TMWTARG_UNUSED_PARAM(pResponse);
  TMWTARG_UNUSED_PARAM(pObjHeader);

  /* Validate qualifier */
  if(pObjHeader->qualifier != DNPDEFS_QUAL_8BIT_LIMITED_QTY)
  {
    SDNPDIAG_ERROR(pSession->pChannel, pSession, SDNPDIAG_50_QUAL);
    return(TMWDEFS_FALSE);
  }

  /* Validate quantity */
  if(pObjHeader->numberOfPoints != 1)
  {
    SDNPDIAG_ERROR(pSession->pChannel, pSession, SDNPDIAG_50_QUANT);
    return(TMWDEFS_FALSE);
  }

  tmwtime.pSession = pSession;

  /* Reset clock valid timer */
  tmwtimer_cancel(&pSDNPSession->clockValidTimer);

  /* Read time from message */
  dnpdtime_readMsSince70(&msSince70, pRxFragment->pMsgBuf + pRxFragment->offset);
  pRxFragment->offset = pRxFragment->offset + 6;

  /* Convert DNP time to TMWDTIME */
  dnpdtime_msSince70ToDateTime(&tmwtime, &msSince70);
 
#if TMWCNFG_SUPPORT_DIAG
  /* Diagnostics */
  DNPDIAG_SHOW_TIME_AND_DATE(pSession, &tmwtime, "Time and Date Received");
#endif

  /* Calculate time based on time in request + (G (current time)- F (time first bit received))*/
  deltaTime = tmwtarg_getMSTime() - pRxFragment->firstByteTime;
  tmwdtime_addOffset(&tmwtime, deltaTime);

#ifdef TMW_SUPPORT_MONITOR 
  /* If in monitor mode, do not set the time */
  if(!pSession->pChannel->pPhysContext->monitorMode)
#endif
  /* Set the current date and time */
  sdnpdata_setTime(pSDNPSession->pDbHandle, &tmwtime);

  /* Clear need time IIN bit */
  pSDNPSession->iin &= ~DNPDEFS_IIN_NEED_TIME;

  /* Start clock valid timer */
  if(pSDNPSession->clockValidPeriod != 0)
  {
    tmwtimer_start(&pSDNPSession->clockValidTimer,
      pSDNPSession->clockValidPeriod, pSession->pChannel,
      _clockValidTimeout, pSession);
  }
  
  return(TMWDEFS_TRUE);
}
#endif

#if SDNPDATA_SUPPORT_OBJ50_V3
/* function: sdnpo050_writeObj50v3 */
TMWTYPES_BOOL TMWDEFS_CALLBACK sdnpo050_writeObj50v3(
  TMWSESN *pSession,
  DNPUTIL_RX_MSG *pRxFragment,
  TMWSESN_TX_DATA *pResponse,
  DNPUTIL_OBJECT_HEADER *pObjHeader)
{
  SDNPSESN *pSDNPSession = (SDNPSESN *)pSession;
  TMWTYPES_MILLISECONDS deltaTime;
  TMWTYPES_MS_SINCE_70 msSince70;
  TMWDTIME tmwtime;

  TMWTARG_UNUSED_PARAM(pResponse);
  TMWTARG_UNUSED_PARAM(pObjHeader);
  
  /* get current time right away */
  deltaTime = tmwtarg_getMSTime();
  
  dnpdtime_readMsSince70(&msSince70, pRxFragment->pMsgBuf + pRxFragment->offset);
  dnpdtime_msSince70ToDateTime(&tmwtime, &msSince70);
  pRxFragment->offset = pRxFragment->offset + 6;

#if TMWCNFG_SUPPORT_DIAG
  /* Diagnostics */
  DNPDIAG_SHOW_TIME_AND_DATE(pSession, &tmwtime, "Time and Date Received");
#endif

  if(!pSDNPSession->recordedCurrentTime)
  {
    /* The master has not sent the record current time function code */
    SDNPDIAG_ERROR(pSession->pChannel, pSession, SDNPDIAG_50_NORECORD);
    return(TMWDEFS_FALSE);
  }

#ifdef TMW_SUPPORT_MONITOR 
  /* If in monitor mode, do not calculate or set the time */
  if(pSession->pChannel->pPhysContext->monitorMode) 
    return(TMWDEFS_TRUE);
#endif

  /* Reset clock valid timer */
  tmwtimer_cancel(&pSDNPSession->clockValidTimer);

  /* Now calculate delta time */
  deltaTime = deltaTime - pSDNPSession->recordCurrentTime;
  tmwdtime_addOffset(&tmwtime, deltaTime);
 
#if TMWCNFG_SUPPORT_DIAG
  /* Diagnostics */
  DNPDIAG_SHOW_TIME_AND_DATE(pSession, &tmwtime, "New Time and Date");
#endif

  /* Set the current date and time */
  sdnpdata_setTime(pSDNPSession->pDbHandle, &tmwtime);

  /* Clear need time IIN bit */
  pSDNPSession->iin &= ~DNPDEFS_IIN_NEED_TIME;

  /* Start clock valid timer */
  if(pSDNPSession->clockValidPeriod != 0)
  {
    tmwtimer_start(&pSDNPSession->clockValidTimer,
      pSDNPSession->clockValidPeriod, pSession->pChannel,
      _clockValidTimeout, pSession);
  }

  pSDNPSession->recordedCurrentTime = TMWDEFS_FALSE;  
  return(TMWDEFS_TRUE);
}
#endif /* SDNPDATA_SUPPORT_OBJ50_V3 */

#if SDNPDATA_SUPPORT_OBJ50
void TMWDEFS_GLOBAL sdnpo050_restartClockValidTime(TMWSESN *pSession)
{
  SDNPSESN *pSDNPSession = (SDNPSESN *)pSession;
 
  /* Clear need time IIN bit */
  pSDNPSession->iin &= ~DNPDEFS_IIN_NEED_TIME;
 
  /* Start clock valid timer */
  if(pSDNPSession->clockValidPeriod != 0)
  {
    tmwtimer_start(&pSDNPSession->clockValidTimer,
      pSDNPSession->clockValidPeriod, pSession->pChannel,
      _clockValidTimeout, pSession);
  }
}
#endif
