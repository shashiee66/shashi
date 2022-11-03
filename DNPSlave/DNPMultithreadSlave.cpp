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

/* DNPMultithreadSlave.cpp : Sample multithreaded DNP Outstation console application. 
 * This sample will use a thread per channel each on a separate application context.
 * The define TMWCNFG_MULTIPLE_TIMER_QS will compile in the timer queue per channel
 * code in the SCL so that timers on each channel can be called from a separate context.
 * This will allow events and received data for each channel to be processed on a separate
 * thread as well as timers for each channel to run on separate threads.
 * WinIoTarg and LinIoTarg contains code to use separate system timers for each
 * channel.If you are using another Operating System may want to implement
 * tmwtarg_initMultiTimer, tmwtarg_setMultiTimer, and tmwtarg_deleteMultiTimer
 * in addition to the other tmwtarg_xxx functionality.
 */
#if defined(TMW_WTK_TARGET)
#include "StdAfx.h"
#endif

extern "C" {
#include "tmwscl/utils/tmwtarg.h"
#include "tmwscl/utils/tmwappl.h"
#include "tmwscl/utils/tmwdb.h"
#include "tmwscl/utils/tmwphys.h"
#include "tmwscl/utils/tmwpltmr.h"
 
#include "tmwscl/dnp/dnpchnl.h"
#include "tmwscl/dnp/sdnpsesn.h"
#include "tmwscl/dnp/sdnputil.h"
#include "tmwscl/dnp/sdnpo002.h"
#include "tmwscl/dnp/sdnpo022.h"

#include "tmwtargio.h"
}

/* The USE_POLLED_MODE constant is used here to demonstrate how the library
 * can be used to configure the target layer to support polled mode vs.
 * event driven. The Linux and Windows TCP channels shipped with the SCL
 * support both. If porting the library, only one configuration is required.
 */
#define USE_POLLED_MODE TMWDEFS_FALSE
#define USE_TLS         TMWDEFS_FALSE

/* If Multiple Timer Queues is configured, use this file */
#if TMWCNFG_MULTIPLE_TIMER_QS

/* Number of channels and therefore channel threads */
#define NUMBER_CHANNELS 3
/* Number of sessions per channel */
#define NUMBER_SESSIONS 1

/* Sample application configuration */
#define ALIVE_CHECK_INTERVAL       20000
#define EVENT_INTERVAL             10000

/* Simple application structure for controlling generation of events */
typedef struct myRequestInfo
{
  TMWTYPES_MILLISECONDS  eventInterval;
  TMWTYPES_MILLISECONDS  lastEvent;    
} MY_REQUEST_INFO;

static MY_REQUEST_INFO *myInitRequests(void);
static void             myStartThread(size_t i);
static TMWTYPES_BOOL    myTimeToSendEvent(TMWTYPES_MILLISECONDS *lastTime, TMWTYPES_MILLISECONDS interval); 

/* Diagnostics */
static void             myLogOutput(char *pBuf);
static void             myPutDiagString(const TMWDIAG_ANLZ_ID *pAnlzId, const TMWTYPES_CHAR *pString);

static TMW_ThreadDecl   myChannelThreadDNP(void *pParam);
 
/*
 * Begin the main loop
 */
int main(int argc, char* argv[])
{
  TMWTYPES_USHORT i;
  char logBuf[256];
  TMWTARG_UNUSED_PARAM(argc);
  TMWTARG_UNUSED_PARAM(argv);

#if TMWCNFG_SUPPORT_DIAG 
  /* Register function to display diagnostic strings to console 
   * This is only necessary if using the Windows or Linux target layer.
   * If implementing a new target layer, tmwtarg_putDiagString()
   * should be modified if diagnostic output is desired.
   */
  tmwtargp_registerPutDiagStringFunc(myPutDiagString);
#endif

   /*
   * Initialize the source code library.
   */
  tmwappl_initSCL();

  /* Start the channel threads */
  for(i=0; i<NUMBER_CHANNELS; i++)
  {
   sprintf(logBuf, "starting dnp outstation thread %d\n", i);
    myLogOutput(logBuf);
    
    myStartThread(i);
  }

  /*  Loop forever. This simple example has nothing else to do
   */
  while(1)
  {
    /* sleep for 10000 milliseconds */
    tmwtarg_sleep(10000);
  }

  return(0);
}

/* Per Channel Thread */
TMW_ThreadDecl myChannelThreadDNP(void *pParam)
{
  int  i;
  TMWAPPL *pThreadApplContext;
  MY_REQUEST_INFO *pMyRequests;
  TMWCHNL *pSclChannel;
  TMWSESN *pSclSession[NUMBER_SESSIONS];

  /* Configuration */
  TMWTARGIO_CONFIG IOCnfg;
  TMWPHYS_CONFIG  physConfig;
  TMWTARG_CONFIG  targConfig;
  DNPCHNL_CONFIG  DNPConfig;
  DNPLINK_CONFIG  linkConfig;
  DNPTPRT_CONFIG  tprtConfig;
  SDNPSESN_CONFIG sesnConfig;
  char logBuf[256];
  bool run = true;
  TMWTYPES_ULONG pollInterval = 1000;

  size_t channelNumber = (size_t)pParam;

  /* Create separate application context per channel thread 
   * This is not required, all channels can exist on a single application context.
   */
  pThreadApplContext = tmwappl_initApplication();

  pMyRequests = myInitRequests();

  /*
   * Initialize all configuration structures to defaults
   */
  tmwtarg_initConfig(&targConfig);

  dnpchnl_initConfig(&DNPConfig, &tprtConfig, &linkConfig, &physConfig); 
  linkConfig.networkType = DNPLINK_NETWORK_TCP_UDP;
 
  /* Initialize the common target IO configuration structure.
  * Call tmwtargio_initConfig to initialize default values, then overwrite
  * specific values as needed.
  */
  tmwtargio_initConfig(&IOCnfg);
  IOCnfg.type = TMWTARGIO_TYPE_TCP;

  /* name displayed in analyzer window */
  sprintf(IOCnfg.targTCP.chnlName, "DNPslave%zu", channelNumber);

  /* IP address to accept connections from */
  /* *.*.*.* allows any client to connect */
  strcpy(IOCnfg.targTCP.ipAddress, "*.*.*.*");

  /* IP port to listen on */
  IOCnfg.targTCP.ipPort = (TMWTYPES_USHORT)(20000 + channelNumber);
  IOCnfg.targTCP.polledMode = USE_POLLED_MODE;
  IOCnfg.targTCP.mode = TMWTARGTCP_MODE_SERVER;

  IOCnfg.targTCP.localUDPPort = (TMWTYPES_USHORT)(20000 + channelNumber);
  IOCnfg.targTCP.disconnectOnNewSyn = TMWDEFS_FALSE;
  IOCnfg.targTCP.role = TMWTARGTCP_ROLE_OUTSTATION;

  /* TLS Configuration */
  IOCnfg.targTCP.useTLS = USE_TLS;
#if TMWTARG_SUPPORT_TLS
    if (USE_TLS)
    {
      /* The default TMW configuration sets up the client's certificate files.
       * Because the file names are the same length but the values for
       * Linux and Windows differ, this sample application simply updates
       * the path to the server's certificates.
       */
      char *clientPtr;
      char serverString[] = "server";
      clientPtr = strstr(IOCnfg.targTCP.tlsRsaCertificateId, "client");
      if (clientPtr)
      {
        /* Copy without NULL terminator */
        memcpy(clientPtr, serverString, sizeof(serverString)-1);
      }
      clientPtr = strstr(IOCnfg.targTCP.tlsRsaPrivateKeyFile, "client");
      if (clientPtr)
      {
        /* Copy without NULL terminator */
        memcpy(clientPtr, serverString, sizeof(serverString)-1);
      }
    }
#endif

  sdnpsesn_initConfig(&sesnConfig);
  
  // If using TCP the DNP Spec requires keep alives to be configured in order to detect disconnects.
  sesnConfig.linkStatusPeriod = 30000;

  /*
   * Open the Channel, Sessions, and Sectors
   */
  sprintf(logBuf, "opening DNP channel %zu\n", channelNumber);
  myLogOutput(logBuf);
  
  pSclChannel = dnpchnl_openChannel(pThreadApplContext, &DNPConfig, &tprtConfig, 
    &linkConfig, &physConfig, &IOCnfg, &targConfig);

  if(pSclChannel == TMWDEFS_NULL)
  {
    /* Failed to open */
    printf("Failed to open channel, exiting program \n");
    
    /* Sleep for 10 seconds before exiting */
    tmwtarg_sleep(10000);
    return (0);
  }

  for (i = 0; i < NUMBER_SESSIONS; i++)
  {
    sprintf(logBuf, "opening DNP session %d\n", i);
    myLogOutput(logBuf);
    
    sesnConfig.destination = (unsigned short)(3 + i);
    sesnConfig.source = (unsigned short)(4 + i);
    pSclSession[i] = (TMWSESN *)sdnpsesn_openSession(pSclChannel, &sesnConfig, TMWDEFS_NULL);
    if(pSclSession[i] == TMWDEFS_NULL)
    {
      /* Failed to open */
      printf("Failed to open session, exiting program \n");
    
      /* Sleep for 10 seconds before exiting */
      tmwtarg_sleep(10000);
      return (0);
    }
  }

  if (USE_POLLED_MODE)
  {
    /* If running in polled mode, tmwappl_checkForInput needs to be called every 50ms. */
    pollInterval = 50;
  }

  /*
   * Now that everything is set up, start a "main loop"
   * that looks for received data and sends events.
   */
  while (run)
  {
    /*
     * Process any data sent by the master for the channel on this application context.
     */
    /* If the target layer is configured to be event driven, there
     * is no need for the application to check for received data.
     */
    if (USE_POLLED_MODE)
    {
      tmwappl_checkForInput(pThreadApplContext);
    }
   
    if(myTimeToSendEvent(&pMyRequests->lastEvent, pMyRequests->eventInterval))
    {
      for (int i = 0; i < NUMBER_SESSIONS; i++)
      {
        TMWDTIME timeStamp;
        sprintf(logBuf, "Sending event for Channel %zu, Session %d\n", channelNumber, i);;
        myLogOutput(logBuf);

        sdnputil_getDateTime(pSclSession[i], &timeStamp);
        sdnpo002_addEvent(pSclSession[i], 4, 0x02, &timeStamp);
        sdnpo022_addEvent(pSclSession[i], 4, 100, 0x02, &timeStamp);
      }
    }
    tmwtarg_sleep(pollInterval);
  }

  /* Close sessions and channel */
  for (i = 0; i < NUMBER_SESSIONS; i++)
  {
    sprintf(logBuf, "closing DNP session %d\n", i);
    myLogOutput(logBuf);
    sdnpsesn_closeSession(pSclSession[i]);
  }

  sprintf(logBuf, "closing DNP channel %zu\n", channelNumber);
  myLogOutput(logBuf);
  dnpchnl_closeChannel(pSclChannel);
  delete pMyRequests;
  tmwappl_closeApplication(pThreadApplContext, TMWDEFS_FALSE);

  return (0);
}

/*
 * myInitRequests
 * Initialize sample application request structure
 */
MY_REQUEST_INFO * myInitRequests(void)
{
  MY_REQUEST_INFO *p;
  p = new myRequestInfo;
  p->eventInterval = EVENT_INTERVAL; 
  p->lastEvent = tmwtarg_getMSTime();

  return p;
}

/*
 * myTimeToSendEvent
 * See if it is time to send a request
 *
 * Note that this simplified example does not take into account
 * the fact that the lastGI field could roll over.
 */
TMWTYPES_BOOL myTimeToSendEvent(TMWTYPES_MILLISECONDS *pLastTime, TMWTYPES_MILLISECONDS interval) 
{
  TMWTYPES_MILLISECONDS currentTime;
  TMWTYPES_BOOL returnVal;

  currentTime = tmwtarg_getMSTime();
  if (currentTime >= (*pLastTime + interval))
  {
    *pLastTime = currentTime;
    returnVal = TMWDEFS_TRUE;
  }
  else
  {
    returnVal = TMWDEFS_FALSE;
  }
  return (returnVal);
}
 

/* Sample function to start either Windows or Linux thread */
static void myStartThread(size_t i)
{
  TMW_ThreadId threadId;
  TMW_ThreadCreate(&threadId, myChannelThreadDNP, (TMW_ThreadArg) i, 0, 0);
}

/* Simple output function for log messages */
void myLogOutput(char *pBuf)
{
  /* to stdout */
  printf("%s",pBuf);
}

#if TMWCNFG_SUPPORT_DIAG
/* Simple diagnostic output function, registered with the Source Code Library */
void myPutDiagString(const TMWDIAG_ANLZ_ID *pAnlzId,const TMWTYPES_CHAR *pString)
{
  TMWDIAG_ID id = pAnlzId->sourceId;

  if((TMWDIAG_ID_ERROR & id) 
    ||(TMWDIAG_ID_APPL & id)
    ||(TMWDIAG_ID_USER & id))
  {
    myLogOutput((char *)pString);  
    return;
  }

  /* Comment this out to turn off verbose diagnostics */
  /* For now print everything */
  /* myLogOutput((char *)pString); */
}
#endif
#endif
