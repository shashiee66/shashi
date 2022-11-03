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

/* file: dnpauth.h
 * description: DNP Secure Authentication
 */
#include "tmwscl/dnp/dnpdiag.h" 
#include "tmwscl/dnp/dnpauth.h" 

 
/* Determine what TMWCRYPTO algorithm define to use based on the key wrap algorithm */
TMWTYPES_ULONG TMWDEFS_GLOBAL dnpauth_keyWraptoTMWCryptoAlgo(TMWTYPES_UCHAR algorithm)
{
  if(algorithm == DNPAUTH_KEYWRAP_AES128)
    return TMWCRYPTO_ALG_KEYWRAP_AES128; 

  if(algorithm == DNPAUTH_KEYWRAP_AES256)
    return TMWCRYPTO_ALG_KEYWRAP_AES256; 

  else
    return TMWCRYPTO_ALG_UNDEFINED;
}

/* Determine what TMWCRYPTO algorithm define to use based on the MAC algorithm */
TMWTYPES_ULONG TMWDEFS_GLOBAL dnpauth_MACtoTMWCryptoAlgo(TMWTYPES_UCHAR algorithm)
{
  switch(algorithm)
  {
  case DNPAUTH_HMAC_SHA1_4OCTET:
  case DNPAUTH_MAC_SHA1_8OCTET:
  case DNPAUTH_MAC_SHA1_10OCTET:
    return TMWCRYPTO_ALG_MAC_SHA1;

  case DNPAUTH_MAC_SHA256_8OCTET: 
  case DNPAUTH_MAC_SHA256_16OCTET:
    return TMWCRYPTO_ALG_MAC_SHA256;
    
  case DNPAUTH_MAC_AESGMAC_12OCTET:
    return TMWCRYPTO_ALG_MAC_AESGMAC;
  }
  return TMWCRYPTO_ALG_UNDEFINED;
}


/* Determine what length MAC to use based on the MAC algorithm from the spec. */
TMWTYPES_UCHAR TMWDEFS_GLOBAL dnpauth_MACtoLength(TMWTYPES_UCHAR algorithm)
{
  switch(algorithm)
  {
  case DNPAUTH_HMAC_SHA1_4OCTET:
    return 4;

  case DNPAUTH_MAC_SHA1_10OCTET:
    return 10;

  case DNPAUTH_MAC_SHA1_8OCTET:
  case DNPAUTH_MAC_SHA256_8OCTET: 
    return 8;

  case DNPAUTH_MAC_SHA256_16OCTET:
    return 16;

  case DNPAUTH_MAC_AESGMAC_12OCTET:
    return 12;
 
  default: 
    return 0;
  }
}


/* determine the number of octets to use in the g120v11 and g120v12 */
TMWTYPES_UCHAR TMWDEFS_GLOBAL dnpauth_methodChallengeLength(TMWTYPES_UCHAR keyChangeMethod)
{
  switch(keyChangeMethod)
  {
    case DNPAUTH_KEYCH_SYMAES128_SHA1:
    case DNPAUTH_KEYCH_ASYM_RSA1024_SHA1:
    case DNPAUTH_KEYCH_ASYM_RSA1024_RSA_SHA1:
      return 20;
    case DNPAUTH_KEYCH_SYMAES256_SHA256:
    case DNPAUTH_KEYCH_SYMAES256_GMAC:
    case DNPAUTH_KEYCH_ASYM_RSA2048_SHA256:
    case DNPAUTH_KEYCH_ASYM_RSA3072_SHA256: 
    case DNPAUTH_KEYCH_ASYM_RSA2048_SHA256_GMAC:
    case DNPAUTH_KEYCH_ASYM_RSA3072_SHA256_GMAC:
    case DNPAUTH_KEYCH_ASYM_RSA2048_RSA_SHA256:
    case DNPAUTH_KEYCH_ASYM_RSA3072_RSA_SHA256:
    case DNPAUTH_KEYCH_ASYM_RSA2048_RSA_SHA256_GMAC:
    case DNPAUTH_KEYCH_ASYM_RSA3072_RSA_SHA256_GMAC:
      return 32;

  }

  /* spm may need to call a database function for private key change methods */
  return 32;
}

TMWTYPES_UCHAR TMWDEFS_GLOBAL dnpauth_getUpdateKeyLength(TMWTYPES_UCHAR keyChangeMethod)
{
  if((keyChangeMethod == DNPAUTH_KEYCH_SYMAES128_SHA1)
    || (keyChangeMethod == DNPAUTH_KEYCH_ASYM_RSA1024_SHA1)
    || (keyChangeMethod == DNPAUTH_KEYCH_ASYM_RSA1024_RSA_SHA1))
  {
    return 16;
  }
  return 32;
}

/* determine what mac algorithm g120v15 to use for specified keyChangeMethod 
 */
TMWTYPES_ULONG TMWDEFS_GLOBAL dnpauth_methodToTMWMacAlgo(TMWTYPES_UCHAR keyChangeMethod)
{
  switch(keyChangeMethod)
  {
    case DNPAUTH_KEYCH_SYMAES128_SHA1:
    case DNPAUTH_KEYCH_ASYM_RSA1024_SHA1:
    case DNPAUTH_KEYCH_ASYM_RSA1024_RSA_SHA1:
      return TMWCRYPTO_ALG_MAC_SHA1;

    case DNPAUTH_KEYCH_SYMAES256_SHA256:
    case DNPAUTH_KEYCH_ASYM_RSA2048_SHA256:
    case DNPAUTH_KEYCH_ASYM_RSA3072_SHA256:
    case DNPAUTH_KEYCH_ASYM_RSA2048_RSA_SHA256:
    case DNPAUTH_KEYCH_ASYM_RSA3072_RSA_SHA256:
      return TMWCRYPTO_ALG_MAC_SHA256;
   
    case DNPAUTH_KEYCH_SYMAES256_GMAC:
    case DNPAUTH_KEYCH_ASYM_RSA2048_SHA256_GMAC:
    case DNPAUTH_KEYCH_ASYM_RSA3072_SHA256_GMAC:
    case DNPAUTH_KEYCH_ASYM_RSA2048_RSA_SHA256_GMAC:
    case DNPAUTH_KEYCH_ASYM_RSA3072_RSA_SHA256_GMAC:
      return TMWCRYPTO_ALG_MAC_AESGMAC;

  default: 
    return TMWCRYPTO_ALG_UNDEFINED;
  }
}
 
/* determine what key transport algorithm to use for specified keyChangeMethod 
 */
TMWTYPES_ULONG TMWDEFS_GLOBAL dnpauth_methodToKeyTransAlgorithm(TMWTYPES_UCHAR keyChangeMethod)
{
  switch(keyChangeMethod)
  {
  case DNPAUTH_KEYCH_SYMAES128_SHA1:
    return TMWCRYPTO_ALG_KEYWRAP_AES128;

  case DNPAUTH_KEYCH_SYMAES256_SHA256:
  case DNPAUTH_KEYCH_SYMAES256_GMAC:
    return TMWCRYPTO_ALG_KEYWRAP_AES256;

 case DNPAUTH_KEYCH_ASYM_RSA1024_SHA1:
 case DNPAUTH_KEYCH_ASYM_RSA1024_RSA_SHA1:
    return(TMWCRYPTO_ALG_ASYM_RSAESOAEP1024);

  case DNPAUTH_KEYCH_ASYM_RSA2048_SHA256:
  case DNPAUTH_KEYCH_ASYM_RSA2048_SHA256_GMAC:
  case DNPAUTH_KEYCH_ASYM_RSA2048_RSA_SHA256:
  case DNPAUTH_KEYCH_ASYM_RSA2048_RSA_SHA256_GMAC:
    return(TMWCRYPTO_ALG_ASYM_RSAESOAEP2048);
    
  case DNPAUTH_KEYCH_ASYM_RSA3072_SHA256:
  case DNPAUTH_KEYCH_ASYM_RSA3072_SHA256_GMAC:
  case DNPAUTH_KEYCH_ASYM_RSA3072_RSA_SHA256:
  case DNPAUTH_KEYCH_ASYM_RSA3072_RSA_SHA256_GMAC:
    return(TMWCRYPTO_ALG_ASYM_RSAESOAEP3072);

  default: 
    return TMWCRYPTO_ALG_UNDEFINED;
  }
}

/* determine what digital signature algorithm to use for specified keyChangeMethod 
 * This only applies to the asymmetric methods
 */
TMWTYPES_ULONG TMWDEFS_GLOBAL dnpauth_methodToSignatureAlgorithm(TMWTYPES_UCHAR keyChangeMethod)
{
  switch(keyChangeMethod)
  {
  case DNPAUTH_KEYCH_ASYM_RSA1024_SHA1:
    return (TMWCRYPTO_ALG_SIGN_DSA_1024_SHA1);

  case DNPAUTH_KEYCH_ASYM_RSA2048_SHA256:
  case DNPAUTH_KEYCH_ASYM_RSA2048_SHA256_GMAC:
    return (TMWCRYPTO_ALG_SIGN_DSA_2048_SHA256);

  case DNPAUTH_KEYCH_ASYM_RSA3072_SHA256:
  case DNPAUTH_KEYCH_ASYM_RSA3072_SHA256_GMAC:
    return (TMWCRYPTO_ALG_SIGN_DSA_3072_SHA256);
    
  case DNPAUTH_KEYCH_ASYM_RSA1024_RSA_SHA1:
    return (TMWCRYPTO_ALG_SIGN_RSA_1024_SHA1);
 
  case DNPAUTH_KEYCH_ASYM_RSA2048_RSA_SHA256:
  case DNPAUTH_KEYCH_ASYM_RSA2048_RSA_SHA256_GMAC:
    return (TMWCRYPTO_ALG_SIGN_RSA_2048_SHA256);

  case DNPAUTH_KEYCH_ASYM_RSA3072_RSA_SHA256:
  case DNPAUTH_KEYCH_ASYM_RSA3072_RSA_SHA256_GMAC:
    return (TMWCRYPTO_ALG_SIGN_RSA_3072_SHA256);
  default:
    return TMWCRYPTO_ALG_UNDEFINED;
  }
}
 
/* function: dnpauth_getAuthSecStatDefaultThreshold */
TMWTYPES_USHORT TMWDEFS_GLOBAL dnpauth_getAuthSecStatDefaultThreshold(
  TMWTYPES_USHORT  index)
{
  switch(index)
  {
  case  DNPAUTH_UNEXPECTED_MSG_INDEX:       
    return DNPAUTH_UNEXPECTED_MSG_THRESHOLD;

  case  DNPAUTH_AUTHOR_FAIL_INDEX:       
    return DNPAUTH_AUTHOR_FAIL_THRESHOLD;

  case  DNPAUTH_AUTHENT_FAIL_INDEX:        
    return DNPAUTH_AUTHENT_FAIL_THRESHOLD;

  case  DNPAUTH_REPLY_TIMEOUT_INDEX:        
    return DNPAUTH_REPLY_TIMEOUT_THRESHOLD;

  case  DNPAUTH_REKEY_DUETOFAIL_INDEX:        
    return DNPAUTH_REKEY_THRESHOLD;   

  case  DNPAUTH_TOTAL_MSG_SENT_INDEX:        
    return DNPAUTH_TOTAL_MSG_SENT_THRESHOLD; 

  case  DNPAUTH_TOTAL_MSG_RCVD_INDEX:        
    return DNPAUTH_TOTAL_MSG_RCVD_THRESHOLD;

  case  DNPAUTH_CRIT_MSG_SENT_INDEX:        
    return DNPAUTH_CRIT_MSG_SENT_THRESHOLD;

  case  DNPAUTH_CRIT_MSG_RCVD_INDEX:        
    return DNPAUTH_CRIT_MSG_RCVD_THRESHOLD;  

  case  DNPAUTH_DISCARDED_MSG_INDEX:        
    return DNPAUTH_DISCARDED_MSG_THRESHOLD;

  case  DNPAUTH_ERROR_MSG_SENT_INDEX:        
    return DNPAUTH_ERROR_MSG_SENT_THRESHOLD;   

  case  DNPAUTH_ERROR_MSG_RCVD_INDEX:        
    return DNPAUTH_ERROR_MSG_RCVD_THRESHOLD;  

  case  DNPAUTH_SUCCESS_AUTHENT_INDEX:      
    return DNPAUTH_SUCCESS_AUTHENT_THRESHOLD; 

  case  DNPAUTH_SESKEY_CHANGE_INDEX:        
    return DNPAUTH_SESKEY_CHANGE_THRESHOLD;    

  case  DNPAUTH_FAILSESKEY_CHANGE_INDEX:        
    return DNPAUTH_FAILSESKEY_CHANGE_THRESHOLD;    

  case  DNPAUTH_UPDKEY_CHANGE_INDEX:        
    return DNPAUTH_UPDKEY_CHANGE_THRESHOLD;  

  case  DNPAUTH_FAILUPDKEY_CHANGE_INDEX:        
    return DNPAUTH_FAILUPDKEY_CHANGE_THRESHOLD; 

  case  DNPAUTH_REKEY_DUE_RESTART_INDEX:        
    return DNPAUTH_REKEY_DUE_RESTART_THRESHOLD;    
  }
  return(0);
}
