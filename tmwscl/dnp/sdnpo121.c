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

/* file: sdnpo121.c
 * description: DNP3 Slave support for Object 121 Security Statistics
 */
#include "tmwscl/dnp/dnpdiag.h"
#include "tmwscl/dnp/dnpdefs.h"
#include "tmwscl/dnp/sdnpo121.h"
#include "tmwscl/dnp/sdnpdata.h"
#include "tmwscl/dnp/sdnputil.h"
#include "tmwscl/dnp/dnputil.h"

#include "tmwscl/utils/tmwtarg.h"

#if SDNPCNFG_SUPPORT_SA_VERSION5
#if SDNPDATA_SUPPORT_OBJ120

/* function: _readv1 */
static SDNPSESN_READ_STATUS TMWDEFS_CALLBACK _readv1(
  TMWSESN *pSession,
  TMWSESN_TX_DATA *pResponse,
  TMWTYPES_USHORT messageIndex,
  TMWTYPES_USHORT pointNum,
  void *pPoint,
  SDNPUTIL_STATIC_DESC *pDesc)
{
  TMWTYPES_ULONG value; 
  TMWTYPES_USHORT assocId;
  TMWTYPES_UCHAR flags;

  TMWTARG_UNUSED_PARAM(pDesc);
  TMWTARG_UNUSED_PARAM(messageIndex);

  assocId = 0;
 
  /* Read current value */
  sdnpdata_authSecStatRead(pPoint, &value, &flags);

  /* Diagnostics */
  DNPDIAG_SHOW_AUTH_SECURITY_STAT(pSession, 0, pointNum, value, flags, TMWDEFS_FALSE, TMWDEFS_NULL); 

  /* Store flags */
  pResponse->pMsgBuf[pResponse->msgLength++] = flags;
  
  tmwtarg_store16(&assocId, &pResponse->pMsgBuf[pResponse->msgLength]);
  pResponse->msgLength += 2;

  /* Store value */
  tmwtarg_store32(&value, &pResponse->pMsgBuf[pResponse->msgLength]);
  pResponse->msgLength += 4;

  return(SDNPSESN_READ_COMPLETE);
}

/* function: sdnpo121_readObj121 */
SDNPSESN_READ_STATUS TMWDEFS_CALLBACK sdnpo121_readObj121(
  TMWSESN *pSession,
  DNPUTIL_RX_MSG *pRequest,
  TMWSESN_TX_DATA *pResponse, 
  DNPUTIL_OBJECT_HEADER *pObjHeader,
  SDNPSESN_QUAL qualifier)
{
  SDNPSESN *pSDNPSession;
  SDNPUTIL_STATIC_DESC desc;
  
  pSDNPSession = (SDNPSESN *)pSession;
  if(!pSDNPSession->authenticationEnabled || pSDNPSession->dnp.operateInV2Mode)
  {
    /* No points, return NULL response */
    return (SDNPSESN_READ_COMPLETE);
  }

  if((pObjHeader->variation != 0)
    &&(pObjHeader->variation != 1))
  {    
    pSDNPSession->iin |= DNPDEFS_IIN_OBJECT_UNKNOWN;
    return (SDNPSESN_READ_FAILED);
  }
  
  desc.group = 121;
  desc.readVariation = 1;  
  desc.variation = 1;
  desc.pReadIntoRespFunc = _readv1;
  desc.sizeInBytes = 7;
  desc.readBits = TMWDEFS_FALSE;
  desc.pQuantityFunc = sdnpdata_authSecStatQuantity;
  desc.pGetPointFunc = sdnpdata_authSecStatGetPoint;
  desc.alreadySwitchedVariation = TMWDEFS_FALSE;
#if SDNPDATA_SUPPORT_CLASS0_POINT
  desc.pIsInClass0Func = sdnpdata_authSecStatIsClass0;
#endif

  return(sdnputil_readStatic(pSession,
    pRequest, pResponse, pObjHeader, qualifier, &desc));
}

#if SDNPDATA_SUPPORT_ASSIGN
/* function: sdnpo121_assignClass */
TMWTYPES_BOOL TMWDEFS_CALLBACK sdnpo121_assignClass(
  TMWSESN *pSession,
  DNPUTIL_RX_MSG *pRxFragment,
  DNPUTIL_OBJECT_HEADER *pObjHeader,
  TMWDEFS_CLASS_MASK classMask)
{
  SDNPSESN *pSDNPSession;
  TMWTYPES_BOOL status;
  TMWTYPES_USHORT index;

  pSDNPSession = (SDNPSESN *)pSession;
  if(!pSDNPSession->authenticationEnabled || pSDNPSession->dnp.operateInV2Mode)
  {
    return (TMWDEFS_FALSE);
  }

  /* limit requested number of points to quantity in database 
   * if status == TMWDEFS_FALSE IN2.2 will be set in response.
   */
  status = sdnputil_validateAssignQualifier(pObjHeader, sdnpdata_authSecStatQuantity(pSDNPSession->pDbHandle));

  for(index = 0; index < pObjHeader->numberOfPoints; index++)
  {
    void *pPoint;
    TMWTYPES_USHORT pointNumber;
    dnputil_getPointNumber(pRxFragment, pObjHeader, index, &pointNumber);

    pPoint = sdnpdata_authSecStatGetPoint(pSDNPSession->pDbHandle, pointNumber);
    if(pPoint == TMWDEFS_NULL)
    {
      /* Failure of any point for startstop or indexed qualifiers should set IIN2.2 in response */
      if((pObjHeader->qualifier < DNPDEFS_QUAL_ALL_POINTS)
        ||(pObjHeader->qualifier > DNPDEFS_QUAL_16BIT_LIMITED_QTY))
      {
        status = TMWDEFS_FALSE;
      }
      continue;
    }

    if(!sdnpdata_authSecStatAssignClass(pPoint, classMask))
      status = TMWDEFS_FALSE;
  }

  return(status);
}
#endif 

#endif /* SDNPDATA_SUPPORT_OBJ120 */
#endif /* SDNPCNFG_SUPPORT_SA_VERSION5 */ 

