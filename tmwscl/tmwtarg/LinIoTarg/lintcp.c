
/*****************************************************************************/
/* Triangle MicroWorks, Inc.                         Copyright (c) 2008-2011 */
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


/* file: linTCP.cpp
* description: Implementation of TCP/IP target routines for Linux
*/

#include "tmwscl/utils/tmwcnfg.h"
#include "tmwscl/utils/tmwtarg.h"
#include "tmwscl/utils/tmwpltmr.h"
#include "lintls.h"
#include "tmwtargio.h"

#if TMWTARG_SUPPORT_TCP
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include "lintcp.h"
#include "liniodiag.h"

static TMWDEFS_RESOURCE_LOCK _tcpSemaphore  = TMWDEFS_NULL;
static TCP_LISTENER         *_pTcpListeners = TMWDEFS_NULL;

#if TMWTARG_SUPPORT_UDP
static TMWTYPES_BOOL _setupUDP(TCP_IO_CHANNEL *pTcpChannel);
static void _inputUdpData(TCP_IO_CHANNEL *pTcpChannel);
static TMWTYPES_USHORT _UDPReceive(TCP_IO_CHANNEL  *pTcpChannel, TMWTYPES_UCHAR  *pBuff, TMWTYPES_ULONG  maxBytes);
#endif

/* function: linTCP_initChannel */
void * TMWDEFS_GLOBAL linTCP_initChannel(
  const void *pUserConfig,
  TMWTARG_CONFIG *pTmwConfig,
  TMWTARG_IO_CHANNEL *pTargIoChannel)
{
  TMWTARGIO_CONFIG *pIOConfig = (TMWTARGIO_CONFIG *) pUserConfig;
  TCP_IO_CHANNEL *pTcpChannel;

  if (_tcpSemaphore == TMWDEFS_NULL)
  {
    TMWTARG_LOCK_INIT(&_tcpSemaphore);
  }

  pTcpChannel = (TCP_IO_CHANNEL *) malloc(sizeof(TCP_IO_CHANNEL));
  if (pTcpChannel == NULL)
    return TMWDEFS_NULL;

  memset(pTcpChannel, 0, sizeof(TCP_IO_CHANNEL));

  /* Store the channel configuration */
  pTcpChannel->chnlConfig = pIOConfig->targTCP;

  pTcpChannel->dataSocket = INVALID_SOCKET;
  pTcpChannel->udpSocket = INVALID_SOCKET;
  pTcpChannel->pipeFd[0] = INVALID_SOCKET;
  pTcpChannel->pipeFd[1] = INVALID_SOCKET;
  pTcpChannel->pollFds[SOCKET_INDEX_DATA].fd = INVALID_SOCKET;
  pTcpChannel->pollFds[SOCKET_INDEX_DATA].events = POLLIN;
  pTcpChannel->pollFds[SOCKET_INDEX_UDP].fd = INVALID_SOCKET;
  pTcpChannel->pollFds[SOCKET_INDEX_UDP].events = POLLIN;
  pTcpChannel->pollFds[SOCKET_INDEX_LISTEN].fd = INVALID_SOCKET;
  pTcpChannel->pollFds[SOCKET_INDEX_LISTEN].events = POLLIN;

  pTcpChannel->newConnectionRcvd = TMWDEFS_FALSE;

  pTcpChannel->afInet = AF_INET;
  if (pIOConfig->targTCP.ipVersion == TMWTARG_IPV6)
  {
    pTcpChannel->afInet = AF_INET6;
  }

  /* Set up the Channel Callback Functions */
  pTargIoChannel->pChannelCallback      = pTmwConfig->pChannelCallback;
  pTargIoChannel->pChannelCallbackParam = pTmwConfig->pCallbackParam;
  pTargIoChannel->pChannelReadyCallback = pTmwConfig->pChannelReadyCallback;
  pTargIoChannel->pChannelReadyCbkParam = pTmwConfig->pChannelReadyCbkParam;
  pTcpChannel->connectRetry             = pTmwConfig->connectRetry;

  /* Ensure that this is not set to zero to avoid a busy loop */
  if (pTcpChannel->connectRetry == 0)
    pTcpChannel->connectRetry = 500;

  /* Set up the Channel Operation Functions */
  pTargIoChannel->pOpenFunction       = linTCP_openChannel;
  pTargIoChannel->pXmitReadyFunction  = linTCP_getTransmitReady;
  pTargIoChannel->pXmitFunction       = linTCP_transmit;
  pTargIoChannel->pRecvFunction       = linTCP_receive;
  pTargIoChannel->pCheckInputFunction = linTCP_checkForInputFunction;
  pTargIoChannel->pCloseFunction      = linTCP_closeChannel;
  pTargIoChannel->pDeleteFunction     = linTCP_deleteChannel;
  
  pTargIoChannel->polledMode = pTcpChannel->chnlConfig.polledMode;
  if (pipe(pTcpChannel->pipeFd) == -1)
  {
    LINIODIAG_ERRORMSG("TCP(%s), Unable to create pipe", pTcpChannel->chnlConfig.chnlName);
    return TMWDEFS_NULL;
  }

  sprintf(pTargIoChannel->chanInfoBuf,"Nic: %s Port: %s:%d",
    pTcpChannel->chnlConfig.nicName,
    pTcpChannel->chnlConfig.ipAddress,
    pTcpChannel->chnlConfig.ipPort);
  pTargIoChannel->pChannelName = pTcpChannel->chnlConfig.chnlName;

  if (pTcpChannel->chnlConfig.useTLS)
  {
#if TMWTARG_SUPPORT_TLS
    lintls_initChannel(pTcpChannel);
#else
    LINIODIAG_ERRORMSG("TCP(%s), TMWTARG_SUPPORT_TLS must be defined to enable TLS",
                       pTcpChannel->chnlConfig.chnlName);
    return TMWDEFS_NULL;
#endif
  }
  TMWTARG_LOCK_INIT(&pTcpChannel->tcpChannelLock);

#if TMWTARG_SUPPORT_UDP
  pTargIoChannel->pXmitUdpFunction   = linTCP_transmitUDP;
  TMWTARG_LOCK_INIT(&pTcpChannel->udpBufferLock);
#endif

  return pTcpChannel;
}

/* function: linTCP_deleteChannel */
void TMWDEFS_GLOBAL linTCP_deleteChannel(TMWTARG_IO_CHANNEL *pTargIoChannel)
{
  TCP_IO_CHANNEL *pTcpChannel = (TCP_IO_CHANNEL *) pTargIoChannel->pChannelInfo;
  /*linTCP_closeChannel(pTargIoChannel); */

  LINIODIAG_MSG("TCP(%s), deleteChannel ", pTcpChannel->chnlConfig.chnlName);

  /* If this was using a listener, see if any other channels still need that listener */
  if (pTcpChannel->pTcpListener)
  {
    TMWTARG_LOCK_SECTION(&_tcpSemaphore);
    if (((TCP_LISTENER *)pTcpChannel->pTcpListener)->numIoChannels == 1)
    {
      /* This is the only channel using this listener, delete it. */
      TCP_LISTENER *pTcpListener = _pTcpListeners;
      TCP_LISTENER **pListenerAnchor = &_pTcpListeners;
      TCP_LISTENER *pTemp;

      while (pTcpListener != NULL)
      {
        if (pTcpListener == pTcpChannel->pTcpListener)
        { 
          /* Close the listener socket */
          close(pTcpListener->listenSocket);
          pTcpListener->listenSocket = INVALID_SOCKET;

          /* Remove the listener from the list and free it */
          *pListenerAnchor = pTcpListener->pNext;
          pTemp = pTcpListener;
          pTcpListener = pTcpListener->pNext;
          free(pTemp);
          break;
        }
        pListenerAnchor = &pTcpListener->pNext;
        pTcpListener = pTcpListener->pNext;
      }
    }
    else /* Additional channels using this listener */
    {
      /* Search for this Tcp channel in the listener's list & remove it. */
      int tcpChannelIndex;
      TCP_LISTENER *pTcpListener = pTcpChannel->pTcpListener;
      for (tcpChannelIndex = 0; tcpChannelIndex < MAX_LISTENING_CHANNELS; tcpChannelIndex++)
      {
        if (pTargIoChannel == pTcpListener->ioChannelPtrs[tcpChannelIndex])
        {
          pTcpListener->ioChannelPtrs[tcpChannelIndex] = TMWDEFS_NULL;
          pTcpListener->numIoChannels--;
          break;
        }
      }
    }
    TMWTARG_UNLOCK_SECTION(&_tcpSemaphore);
  }

  if (pTcpChannel->pipeFd[0] != INVALID_SOCKET)
  {
    close(pTcpChannel->pipeFd[0]);
  }
  if (pTcpChannel->pipeFd[1] != INVALID_SOCKET)
  {
    close(pTcpChannel->pipeFd[1]);
  }
  TMWTARG_LOCK_DELETE(&pTcpChannel->tcpChannelLock);

#if TMWTARG_SUPPORT_UDP
  TMWTARG_LOCK_DELETE(&pTcpChannel->udpBufferLock);
#endif

#if TMWTARG_SUPPORT_TLS
  if (pTcpChannel->chnlConfig.useTLS)
  {
    lintls_delete(pTcpChannel);
  }
#endif

  free(pTcpChannel);
}

/* function: _isChannelOpen 
 *  Returns true if this channel is currently open
 */
static TMWTYPES_BOOL _isChannelOpen(TCP_IO_CHANNEL *pTcpChannel)
{
#if TMWTARG_SUPPORT_UDP
  if (pTcpChannel->chnlConfig.mode == TMWTARGTCP_MODE_UDP)
    return (pTcpChannel->udpSocket != INVALID_SOCKET);
#endif

  return (pTcpChannel->dataSocket != INVALID_SOCKET);
}

/* function: _connect 
 *  Send a TCP connect request to the server
 */
TMWTYPES_BOOL _connect(TCP_IO_CHANNEL *pTcpChannel)
{
  struct addrinfo     *pAddrInfo;
  struct addrinfo     hints;
  char                portName[10];
  struct sockaddr_in6 localAddr;
  SOCKET              dataSocket;
#if TMWTARG_SUPPORT_POLL
  struct pollfd       pollFd[2];
#else
  struct timeval      timeout;
  fd_set              writeFds;
  fd_set              readFds;
  int                 numFds;
#endif
  int                 result;
  int                 error;
  socklen_t           length;

  if (pTcpChannel->dataSocket != INVALID_SOCKET)
  {
    /* Already connected */
    LINIODIAG_MSG("TCP(%s), connect already connected", pTcpChannel->chnlConfig.chnlName);
    return(TMWDEFS_TRUE);
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_flags = 0;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_family = pTcpChannel->afInet;
  hints.ai_addrlen = 0;
  hints.ai_addr = NULL;
  hints.ai_canonname = NULL;
  hints.ai_next = NULL;
 
  sprintf(portName, "%d", pTcpChannel->chnlConfig.ipPort); 
  result = getaddrinfo(pTcpChannel->chnlConfig.ipAddress, portName, &hints, &pAddrInfo);
  if (result != 0)
  {
    LINIODIAG_ERRORMSG("TCP(%s), address resolution failed with %d",
                       pTcpChannel->chnlConfig.chnlName, result);
    return(TMWDEFS_FALSE);
  }
 
  LINIODIAG_MSG("TCP(%s), Connecting to %s %s", pTcpChannel->chnlConfig.chnlName,
                pTcpChannel->chnlConfig.ipAddress, portName);

  dataSocket = socket(pTcpChannel->afInet, SOCK_STREAM, IPPROTO_TCP);
  if (dataSocket == INVALID_SOCKET)
  {
    LINIODIAG_ERRORMSG("TCP(%s), socket failed", pTcpChannel->chnlConfig.chnlName);
    return(TMWDEFS_FALSE);
  }

/*
  MAKE_SOCKET_REUSEADDR(dataSocket, result);
  if (result != 0)
  {
    liniotarg_diagErrorMsg("TCP reuse address failed");
    close(dataSocket);
    return(TMWDEFS_FALSE);
  }
*/

  memset(&localAddr, 0, sizeof(localAddr));
  localAddr.sin6_family = pTcpChannel->afInet;
  localAddr.sin6_port = htons(0);
  localAddr.sin6_addr = in6addr_any;

  if (bind(dataSocket, (struct sockaddr *) &localAddr, sizeof(localAddr)) != 0)
  {
    LINIODIAG_ERRORMSG("TCP(%s), connect socket bind failed, %s",
                       pTcpChannel->chnlConfig.chnlName, strerror(errno));
    close(dataSocket);
    return(TMWDEFS_FALSE);
  }

  MAKE_SOCKET_NON_BLOCKING(dataSocket, result);
  if (result != 0)
  {
    LINIODIAG_ERRORMSG("TCP(%s), non-blocking failed", pTcpChannel->chnlConfig.chnlName);
    close(dataSocket);
    return(TMWDEFS_FALSE);
  }

  MAKE_SOCKET_NO_DELAY(dataSocket, result);
  if (result != 0)
  {
    LINIODIAG_ERRORMSG("TCP(%s), no-delay failed", pTcpChannel->chnlConfig.chnlName);
    close(dataSocket);
    return(TMWDEFS_FALSE);
  }

  MAKE_SOCKET_KEEPALIVE(dataSocket, result);
  if (result != 0)
  {
    LINIODIAG_ERRORMSG("TCP(%s), connect set keepalive failed", pTcpChannel->chnlConfig.chnlName);
    close(dataSocket);
    return(TMWDEFS_FALSE);
  }

  if (pTcpChannel->chnlConfig.mode == TMWTARGTCP_MODE_DUAL_ENDPOINT)
  {
    struct sockaddr_in *pSockAddrIn = (struct sockaddr_in *) pAddrInfo->ai_addr;
    pSockAddrIn->sin_port = htons(pTcpChannel->chnlConfig.dualEndPointIpPort);
  }

  result = connect(dataSocket, (struct sockaddr *) pAddrInfo->ai_addr, pAddrInfo->ai_addrlen);
  if (result != 0)
  {
    result = errno;
    if ((result != EWOULDBLOCK) && (result != EINPROGRESS))
    { 
      LINIODIAG_ERRORMSG("TCP(%s), connect bad return code %s",
                         pTcpChannel->chnlConfig.chnlName, strerror(result));
      close(dataSocket);
      return(TMWDEFS_FALSE);
    }
    LINIODIAG_MSG("TCP(%s), connect started", pTcpChannel->chnlConfig.chnlName);
  }
  freeaddrinfo(pAddrInfo);

  /* Wait for connection to come up */
#if TMWTARG_SUPPORT_POLL
  pollFd[0].fd = dataSocket;
  pollFd[0].events = POLLOUT;
  pollFd[1].fd = pTcpChannel->pipeFd[0];
  pollFd[1].events = POLLIN;
  result = poll(pollFd, 2, pTcpChannel->chnlConfig.ipConnectTimeout * 1000);
  if (result == SOCKET_ERROR)
  {
    LINIODIAG_ERRORMSG("TCP(%s), poll failed waiting for connection, %s",
                       pTcpChannel->chnlConfig.chnlName, strerror(errno));
    close(dataSocket);
    return(TMWDEFS_FALSE);
  }

  if ((pollFd[1].revents & POLLIN))
  {
    /* The channel was disconnected and a character written to the pipe to wake up the channel thread */
    /* simply read the character to clear empty the pipe and return. */
    char tempChar;
    read(pTcpChannel->pipeFd[0], &tempChar, 1);
    return(TMWDEFS_FALSE);
  }
 
  /* If no error, see if activity on the correct file descriptor */
  if (!(pollFd[0].revents & POLLOUT))
  {
    LINIODIAG_ERRORMSG("TCP(%s), connect failed, closing socket", pTcpChannel->chnlConfig.chnlName);
    close(dataSocket);
    return(TMWDEFS_FALSE);
  }
#else
  timeout.tv_sec = 0;
  timeout.tv_usec = pTcpChannel->chnlConfig.ipConnectTimeout * 1000;
  FD_ZERO(&writeFds);
  FD_ZERO(&readFds);
  FD_SET(dataSocket, &writeFds);
  FD_SET(pTcpChannel->pipeFd[0], &readFds);
  if (dataSocket > pTcpChannel->pipeFd[0])
  {
    numFds = dataSocket + 1;
  }
  else
  {
    numFds = pTcpChannel->pipeFd[0] + 1;
  }
  result = select(numFds, &readFds, &writeFds, NULL, &timeout);
  if (result == SOCKET_ERROR)
  {
    LINIODIAG_ERRORMSG("TCP(%s), select failed waiting for connection, %s",
                       pTcpChannel->chnlConfig.chnlName, strerror(errno));
    close(dataSocket);
    return(TMWDEFS_FALSE);
  }

  if(FD_ISSET(pTcpChannel->pipeFd[0], &readFds))
  {
    /* The channel was disconnected and a character written to the pipe to wake up the channel thread */
    /* simply read the character to clear empty the pipe and return. */
    char tempChar;
    read(pTcpChannel->pipeFd[0], &tempChar, 1);
    return(TMWDEFS_FALSE);
  }

  /* If no error, see if activity on the correct file descriptor */
  if(!FD_ISSET(dataSocket, &writeFds))
  {
    LINIODIAG_ERRORMSG("TCP(%s), connect failed, closing socket", pTcpChannel->chnlConfig.chnlName);
    close(dataSocket);
    return(TMWDEFS_FALSE);
  }
#endif

  /*if SO_ERROR == 0 then it connected successfully */
  length = sizeof(error);
  result = getsockopt(dataSocket, SOL_SOCKET, SO_ERROR, (void*) &error, &length);
  if(error !=0)
  { 
    LINIODIAG_ERRORMSG("TCP(%s), connect - IP = %s: port = %d failed, %s",
      pTcpChannel->chnlConfig.chnlName, pTcpChannel->chnlConfig.ipAddress,
      pTcpChannel->chnlConfig.ipPort, strerror(errno));
    close(dataSocket);
    return(TMWDEFS_FALSE);
  }

#if TMWTARG_SUPPORT_TLS
  /* Check TLS configuration */
  if (pTcpChannel->chnlConfig.useTLS)
  {
    if (!lintls_connect(pTcpChannel, dataSocket))
    {
      close(dataSocket);
      return(TMWDEFS_FALSE);
    }
  }
#endif

  pTcpChannel->clientConnected = TMWDEFS_TRUE;
  pTcpChannel->pollFds[SOCKET_INDEX_DATA].fd = dataSocket;
  pTcpChannel->dataSocket = dataSocket;

  return(TMWDEFS_TRUE);
}

/* function: _disconnect 
 *  disconnect the socket connection
 */
TMWTYPES_BOOL _disconnect(TCP_IO_CHANNEL *pTcpChannel)
{
  /* Ensure exclusive access to the channel before */
  /* closing the data socket.                      */
  TMWTARG_LOCK_SECTION(&pTcpChannel->tcpChannelLock);

  close(pTcpChannel->dataSocket);
  pTcpChannel->dataSocket = INVALID_SOCKET;
  pTcpChannel->pollFds[SOCKET_INDEX_DATA].fd = INVALID_SOCKET;
  pTcpChannel->clientConnected = TMWDEFS_FALSE;

  TMWTARG_UNLOCK_SECTION(&pTcpChannel->tcpChannelLock);

  /* If the channel thread is waiting for a connection, write
   * to the pipe to wake it up immediately instead of waiting
   * for a timeout to occur.
   */
  if (pTcpChannel->pipeFd[1] != INVALID_SOCKET)
  {
    write(pTcpChannel->pipeFd[1], "x", 1);
  }

  return TMWDEFS_TRUE;
}

/* function: _listen */
static TMWTYPES_BOOL _listen(TMWTARG_IO_CHANNEL *pTargIoChannel)
{
  TCP_IO_CHANNEL *pTcpChannel = (TCP_IO_CHANNEL *) pTargIoChannel->pChannelInfo;
  TCP_LISTENER *pTcpListener;
  struct sockaddr_in6  localAddr;
  SOCKET       listenSocket;
  int          result;
  struct ifreq ifr;

  /* if there is already a listener on this port, don't listen again */
  if (pTcpChannel->pTcpListener)
  {
    return TMWDEFS_TRUE;
  }

  TMWTARG_LOCK_SECTION(&_tcpSemaphore);
  pTcpListener = _pTcpListeners;
  while (pTcpListener != NULL)
  {
    if ((pTcpListener->listenPort == pTcpChannel->chnlConfig.ipPort) &&
        (memcmp(&pTcpListener->listenAddr, &pTcpChannel->ipAddr, sizeof(struct in6_addr)) == 0))
    {
      /* already listening on this port, add this Tcp channel to the listener's list */
      int tcpChannelIndex;
      TMWTYPES_BOOL channelAdded = TMWDEFS_FALSE;
      for (tcpChannelIndex = 0; tcpChannelIndex < MAX_LISTENING_CHANNELS; tcpChannelIndex++)
      {
        if (pTcpListener->ioChannelPtrs[tcpChannelIndex] == TMWDEFS_NULL)
        {
          pTcpListener->ioChannelPtrs[tcpChannelIndex] = pTargIoChannel;
          pTcpListener->numIoChannels++;
          channelAdded = TMWDEFS_TRUE;
          break;
        }
      }
      TMWTARG_UNLOCK_SECTION(&_tcpSemaphore);
      return channelAdded;
    }
    pTcpListener = pTcpListener->pNext;
  } 
  TMWTARG_UNLOCK_SECTION(&_tcpSemaphore);

  memset(&localAddr, 0, sizeof(localAddr));
  localAddr.sin6_family = pTcpChannel->afInet;
  localAddr.sin6_port = htons(pTcpChannel->chnlConfig.ipPort);
  localAddr.sin6_addr = in6addr_any;

  if ((strcmp(pTcpChannel->chnlConfig.localIpAddress, "*.*.*.*") != 0) && (pTcpChannel->afInet == AF_INET))
  {
    struct sockaddr_in *in = (struct sockaddr_in*)&localAddr;
    inet_pton(pTcpChannel->afInet, pTcpChannel->chnlConfig.localIpAddress, &in->sin_addr);
    memcpy(&pTcpChannel->ipAddr, &in->sin_addr, sizeof(struct in_addr));
  }

  listenSocket = socket(pTcpChannel->afInet, SOCK_STREAM, IPPROTO_TCP);
  if (listenSocket == INVALID_SOCKET)
  {
    LINIODIAG_ERRORMSG("TCP(%s), listen socket failed", pTcpChannel->chnlConfig.chnlName);
    return(TMWDEFS_FALSE);
  }

  MAKE_SOCKET_REUSEADDR(listenSocket, result);
  if (result != 0)
  {
    LINIODIAG_ERRORMSG("TCP(%s), reuse address failed", pTcpChannel->chnlConfig.chnlName);
    close(listenSocket);
    return(TMWDEFS_FALSE);
  }

  if(strcmp(pTcpChannel->chnlConfig.nicName, "") != 0) {
    char *p_char;
    int   nic_name_len;
    int   alias_len;
    struct ifaddrs *ifa, *ifa_tmp;
    memset(&ifr, 0, sizeof(ifr));       
    nic_name_len = strlen(pTcpChannel->chnlConfig.nicName);
    p_char = strchr(pTcpChannel->chnlConfig.nicName, ':');
    if (p_char == NULL) {
      alias_len = 0;
    } else {
      alias_len = strlen(p_char);
    } 
    /*If the nicName contain an alias (eth0:5), only copy the interface part (eth0) */
    strncpy(&ifr.ifr_name[0], &pTcpChannel->chnlConfig.nicName[0], nic_name_len - alias_len);
    result = setsockopt(listenSocket, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr));
    if (result != 0) {
      LINIODIAG_ERRORMSG("TCP(%s), listen socket bind to interface(%s) failed, %s",
                         pTcpChannel->chnlConfig.chnlName, ifr.ifr_name, strerror(errno));
      close(listenSocket);
      return(TMWDEFS_FALSE);
    }

    if (getifaddrs(&ifa) == -1) {
      LINIODIAG_ERRORMSG("TCP(%s), listen socket getifaddrs failed, %s",
                         pTcpChannel->chnlConfig.chnlName, strerror(errno));
      return(TMWDEFS_FALSE);
    }

    ifa_tmp = ifa;
    while (ifa_tmp) {
      if ((ifa_tmp->ifa_addr) && (ifa_tmp->ifa_addr->sa_family == pTcpChannel->afInet) &&
        (strncmp(pTcpChannel->chnlConfig.nicName, ifa_tmp->ifa_name, TMWTARG_IF_NAME_LENGTH) == 0)) {
        if (ifa_tmp->ifa_addr->sa_family == AF_INET) {
          /* store IPv4 addresss */
          struct sockaddr_in *in = (struct sockaddr_in*) ifa_tmp->ifa_addr;
          memcpy(&pTcpChannel->ipAddr, &in->sin_addr, sizeof(struct in_addr));
        }
        else
        { 
          /* store IPv6 address */
          struct sockaddr_in6 *in6 = (struct sockaddr_in6*) ifa_tmp->ifa_addr;
          memcpy(&pTcpChannel->ipAddr, &in6->sin6_addr, sizeof(struct in6_addr));
        }
#if defined(DEBUG_LINIOTARG)
        char addr[50];
        inet_ntop(pTcpChannel->afInet, &pTcpChannel->ipAddr, addr, sizeof(addr));
        printf("name = %s\n", ifa_tmp->ifa_name);
        printf("addr = %s\n", addr);
#endif
        break;
      }
      ifa_tmp = ifa_tmp->ifa_next;
    }
  } 

  if (bind(listenSocket, (struct sockaddr *) &localAddr, sizeof(localAddr)) != 0)
  {
    LINIODIAG_ERRORMSG("TCP(%s), listen socket bind failed, %s",
                       pTcpChannel->chnlConfig.chnlName, strerror(errno));
    close(listenSocket);
    return(TMWDEFS_FALSE);
  }

  if (listen(listenSocket, LINTCP_BACKLOG) != 0)
  {
    LINIODIAG_ERRORMSG("TCP(%s), listen failed", pTcpChannel->chnlConfig.chnlName);
    close(listenSocket);
    return(TMWDEFS_FALSE);
  }

  MAKE_SOCKET_NON_BLOCKING(listenSocket, result);
  if (result != 0)
  {
    LINIODIAG_ERRORMSG("TCP(%s), non-blocking listen failed", pTcpChannel->chnlConfig.chnlName);
    close(listenSocket);
    return(TMWDEFS_FALSE);
  }

  pTcpListener = malloc(sizeof(TCP_LISTENER));
  if (pTcpListener == NULL)
  {
    LINIODIAG_ERRORMSG("TCP(%s), listen could not malloc", pTcpChannel->chnlConfig.chnlName);
    close(listenSocket);
    return TMWDEFS_FALSE;
  }

  memset(pTcpListener, 0, sizeof(TCP_LISTENER));
  pTcpListener->listenSocket = listenSocket;
  pTcpListener->listenPort = pTcpChannel->chnlConfig.ipPort;
  pTcpListener->listenAddr = pTcpChannel->ipAddr;
  pTcpListener->numIoChannels = 1;
  pTcpListener->ioChannelPtrs[0] = pTargIoChannel;
  pTcpChannel->pTcpListener = (void *)pTcpListener;

  TMWTARG_LOCK_SECTION(&_tcpSemaphore);

  /* Put this on the list of listeners */
  pTcpListener->pNext = _pTcpListeners;
  _pTcpListeners = pTcpListener;

  TMWTARG_UNLOCK_SECTION(&_tcpSemaphore);

  LINIODIAG_MSG("TCP(%s), listening on port %d",
    pTcpChannel->chnlConfig.chnlName, pTcpChannel->chnlConfig.ipPort);

  return(TMWDEFS_TRUE);
}

/* function: _accept */
TMWTYPES_BOOL _accept(TCP_LISTENER *pTcpListener)
{
  int                 result;
  SOCKET              acceptSocket;
  struct sockaddr_in  remoteAddr;
  socklen_t           remoteAddrLen;
  TCP_IO_CHANNEL      *pTcpChannel;
  TCP_IO_CHANNEL      *pUseThisTcpChannel;
  TMWTARG_IO_CHANNEL  *pUseThisIoChannel = TMWDEFS_NULL;
  int                 tcpChannelIndex = 0;

  remoteAddrLen = sizeof(remoteAddr);
  acceptSocket = accept(pTcpListener->listenSocket,
    (struct sockaddr *) &remoteAddr, &remoteAddrLen);
  if (acceptSocket == INVALID_SOCKET)
  {
    LINIODIAG_ERRORMSG("TCP: accept failed");
    return(TMWDEFS_FALSE);
  }

#if defined(DEBUG_LINIOTARG)
  {
    int a,b,c,d;
    unsigned long temp = remoteAddr.sin_addr.s_addr;
    a = (temp >> 24);
    temp = temp << 8;
    b = (temp >> 24);
    temp = temp << 8;
    c = (temp >> 24);
    temp = temp << 8;
    d = (temp >> 24);
    LINIODIAG_MSG("TCP: Accept received connect request from IP address %d.%d.%d.%d", d,c,b,a);
  }
#endif

  /* We have a new connection, set up socket parameters for TCP */
  MAKE_SOCKET_NON_BLOCKING(acceptSocket, result);
  if (result != 0)
  {
    LINIODIAG_ERRORMSG("MAKE_SOCKET_N_BLOCKING returned %d", result);
    close(acceptSocket);
    return(TMWDEFS_FALSE);
  }

  MAKE_SOCKET_NO_DELAY(acceptSocket, result);
  if (result != 0)
  { 
    LINIODIAG_ERRORMSG("MAKE_SOCKET_NO_DELAY returned %d", result);
    close(acceptSocket);
    return(TMWDEFS_FALSE);
  }

  MAKE_SOCKET_KEEPALIVE(acceptSocket, result);
  if (result != 0)
  {
    LINIODIAG_ERRORMSG("TCP accept set keepalive failed");
    close(acceptSocket);
    return(TMWDEFS_FALSE);
  }

  pUseThisTcpChannel = TMWDEFS_NULL;

  /* Look for a matching channel */
  for (tcpChannelIndex = 0; tcpChannelIndex < MAX_LISTENING_CHANNELS; tcpChannelIndex++)
  {
    TMWTARG_IO_CHANNEL *pTargIoChannel = pTcpListener->ioChannelPtrs[tcpChannelIndex];
    if (!pTargIoChannel)
    {
      continue;
    }
    pTcpChannel = (TCP_IO_CHANNEL *) pTargIoChannel->pChannelInfo;
    if (pTcpChannel
      &&((pTcpChannel->chnlConfig.mode == TMWTARGTCP_MODE_SERVER)
        ||(pTcpChannel->chnlConfig.mode == TMWTARGTCP_MODE_DUAL_ENDPOINT)))
    {
      /* See if the address and port matches */
      if(((strcmp(pTcpChannel->chnlConfig.ipAddress, "*.*.*.*") == 0)
        ||(inet_addr(pTcpChannel->chnlConfig.ipAddress) == remoteAddr.sin_addr.s_addr))
        && (pTcpChannel->chnlConfig.ipPort == pTcpListener->listenPort))
      { 
        /* If channel is not yet connected */
        if (pTcpChannel->dataSocket == INVALID_SOCKET)
        {
#if TMWTARG_SUPPORT_TLS
          if (lintls_listen(pTcpChannel, acceptSocket))
          {
            pUseThisTcpChannel = pTcpChannel;
            pUseThisIoChannel = pTargIoChannel;
            break;
          }
          else
          {
            LINIODIAG_MSG("TCP: lintls_listen failed");
          }
#else
          pUseThisTcpChannel = pTcpChannel;
          pUseThisIoChannel = pTargIoChannel;
          break;
#endif
        }
        else /* already connected */
        {
          if (pTcpChannel->chnlConfig.disconnectOnNewSyn)
          {
            /* this is for IEC protocols, not DNP */ 
            LINIODIAG_MSG("TCP: Accept previously connected to this ip address and a new connection has come in");

            /* Keep looking for available channel, but save this channel to use if an unconnected channel is not found. */
            /* If this channel needs to be disconnected the code to start this process is below */
            pUseThisTcpChannel = pTcpChannel;
          }

          /* If this is a DNP dual end point outstation, 
           * close the existing connection and accept the new one 
           */
          else if ((pTcpChannel->chnlConfig.mode == TMWTARGTCP_MODE_DUAL_ENDPOINT)
                &&(pTcpChannel->chnlConfig.role == TMWTARGTCP_ROLE_OUTSTATION)
                &&(pTcpChannel->clientConnected))
          {  
            /* Close existing connection and accept the new connection.*/
            LINIODIAG_MSG("TCP: Accept Dual End Point outstation, previously connected to this ip address and a new connection has come in");
            _disconnect(pTcpChannel);
            pUseThisTcpChannel = pTcpChannel;
            break;
          } 
          /* this channel is busy, look at the next one */
        }
      }
    }
  } 

  if(pUseThisTcpChannel != TMWDEFS_NULL)
  {
    /* if a new connection came in when already connected, mark old channel for disconnect and ignore new connection
     * The next linTCP_receive() will see that newConnectionRcvd is true, 
     * calling channel callback to inform the SCL the connection has closed with reason TMWDEFS_TARG_OC_NEW_CONNECTION
     * The SCL will call tmwtarg_closeChannel() which will result in old connection being closed.
     * Then the next SYN will connect and result in a channel callback indicating the new connection.
     * If new connection comes in before next linTCP_receive(), the old connection has not closed yet so same thing happens again
     * until linTCP_receive() sees newConnectionRcvd is true.
     */
    if (pUseThisTcpChannel->dataSocket != INVALID_SOCKET)
    {
      LINIODIAG_MSG("TCP: Mark old connection for disconnect so it can receive next connect"); 
      pUseThisTcpChannel->newConnectionRcvd = TMWDEFS_TRUE;;

      close(acceptSocket);
      return(TMWDEFS_FALSE);
    }

    LINIODIAG_MSG("TCP: Accept this connection");
#if TMWTARG_SUPPORT_UDP
    /* If configured for it, save the address from the master to
     * be used for comparing with src address in UDP requests.
     */
    if(pUseThisTcpChannel->chnlConfig.validateUDPAddress)
    {
      pUseThisTcpChannel->validUDPAddress = remoteAddr.sin_addr.s_addr;
    }
#endif

    if (pUseThisIoChannel->pChannelCallback != TMWDEFS_NULL)
    {
      pUseThisIoChannel->pChannelCallback(pUseThisIoChannel->pChannelCallbackParam,
        TMWDEFS_TRUE, /* open */
        TMWDEFS_TARG_OC_SUCCESS);

      pTcpChannel->clientConnected = TMWDEFS_FALSE;
      pUseThisTcpChannel->dataSocket = acceptSocket;
      pUseThisTcpChannel->pollFds[SOCKET_INDEX_DATA].fd = acceptSocket;
    }
  }
  else
  {
    /* No one interested so close the socket */
    close(acceptSocket);
    return(TMWDEFS_FALSE);
  }

  return(TMWDEFS_TRUE);
}

/* function: _checkListener 
 *  check for activity on a listen on a socket
 */
static TMWTYPES_BOOL _checkListener(TCP_IO_CHANNEL *pTcpChannel, TMWTYPES_MILLISECONDS timeout)
{
  TCP_LISTENER   *pTcpListener = (TCP_LISTENER *)pTcpChannel->pTcpListener;
  if (pTcpListener == TMWDEFS_NULL)
  {
    tmwtarg_sleep(timeout);
    return TMWDEFS_FALSE;
  }

#if TMWTARG_SUPPORT_POLL
  struct pollfd   pollFd;
  pollFd.fd     = pTcpListener->listenSocket;
  pollFd.events = POLLIN;

  if (poll(&pollFd, 1, timeout) > 0)
#else
  fd_set          rfds;
  struct timeval  tv;

  tv.tv_sec = 0;
  tv.tv_usec = timeout * 1000;
  FD_ZERO(&rfds);
  FD_SET(pTcpListener->listenSocket, &rfds);

  if (select(pTcpListener->listenSocket + 1, &rfds, NULL, NULL, &tv) > 0)
#endif
  {
    return (_accept(pTcpListener));
  }
  return TMWDEFS_FALSE;
}

/* function: _chanThread_sleep
 *  sleep function implemented for the channel thread.
 *  It supports preemption using poll/select in the case that the channel is shutdown.
 */
static void _chanThread_sleep(TCP_IO_CHANNEL *pTcpChannel, TMWTYPES_MILLISECONDS timeout)
{
#if TMWTARG_SUPPORT_POLL
  struct pollfd pollFd;
  pollFd.fd     = pTcpChannel->pipeFd[0];
  pollFd.events = POLLIN;

  if (poll(&pollFd, 1, timeout) == 1)
#else
  struct timeval  timeval_out;
  fd_set          readFds;

  timeval_out.tv_sec = 0;
  timeval_out.tv_usec = timeout * 1000;
  FD_ZERO(&readFds);
  FD_SET(pTcpChannel->pipeFd[0], &readFds);
  if (select(pTcpChannel->pipeFd[0]+1, &readFds, NULL, NULL, &timeval_out) == 1)
#endif
  {
    /* The channel was disconnected and a character written to the pipe to wake up */
    /* the channel thread simply read the character to clear empty the pipe.       */
    char tempChar;
    read(pTcpChannel->pipeFd[0], &tempChar, 1);
  }
}

/* function: linTCP_openChannel */
TMWTYPES_BOOL linTCP_openChannel(TMWTARG_IO_CHANNEL *pTargIoChannel)
{
  TCP_IO_CHANNEL *pTcpChannel = (TCP_IO_CHANNEL *) pTargIoChannel->pChannelInfo;
  TMWTYPES_BOOL   status = TMWDEFS_FALSE;

  LINIODIAG_MSG("TCP(%s), openChannel ", pTcpChannel->chnlConfig.chnlName);
#if TMWTARG_SUPPORT_TLS
  TMWTYPES_BOOL   tlsOpenStatus;

  TMWTARG_LOCK_SECTION(&_tcpSemaphore);
  tlsOpenStatus = lintls_open(pTcpChannel);
  TMWTARG_UNLOCK_SECTION(&_tcpSemaphore);
  if (!tlsOpenStatus)
    return status;
#endif

#if TMWTARG_SUPPORT_UDP
  /* Check TLS configuration */
  if (!pTcpChannel->chnlConfig.useTLS)
  {
    /* Check for UDP configured */
    if (pTcpChannel->chnlConfig.localUDPPort != TMWTARG_UDP_PORT_NONE)
    { 
      /* This is tolerant of failure, if TCP AND UDP. may want to catch this
       * The problem is both master and slave use 20000 by default...
       */
      status = _setupUDP(pTcpChannel); 
    }
  }
#endif

  /* If configured for UDP only, don't listen or connect, return success or failure */
  if (pTcpChannel->chnlConfig.mode != TMWTARGTCP_MODE_UDP)
  { 
    if (pTcpChannel->chnlConfig.mode == TMWTARGTCP_MODE_SERVER)
    {
      status = _listen(pTargIoChannel);
    
      if(status == TMWDEFS_TRUE)
      {
        /* listening, is it connected yet? */
        if (pTcpChannel->dataSocket == INVALID_SOCKET)
        {
          status = TMWDEFS_FALSE;
          /* If there is a channel thread running, _checkListener will be called in its
           * context. Otherwise, it must be called here from the library's context.
           */
          if (pTargIoChannel->chanThreadState == TMWTARG_THREAD_IDLE)
          {
            _checkListener(pTcpChannel, 0);
          }
        }
      }
    }

    else if (pTcpChannel->chnlConfig.mode == TMWTARGTCP_MODE_CLIENT)
    {
      /* connected or not? */
      if (pTcpChannel->dataSocket == INVALID_SOCKET)
      {
        status = TMWDEFS_FALSE;
        /* If there is a channel thread running, _connect will be
         * called in its context since it can cause delays. Otherwise,
         * it must be called from the library's context.
         */
        if (pTargIoChannel->chanThreadState == TMWTARG_THREAD_IDLE)
        {
          _connect(pTcpChannel);
        }
      }
      else
      {
        status = TMWDEFS_TRUE;
      }
    }

    else if (pTcpChannel->chnlConfig.mode == TMWTARGTCP_MODE_DUAL_ENDPOINT)
    {
      /* Setup listener.
       * Return true even though not connected yet
       * so that SCL will attempt to send data when needed
       * which will cause a connection to be attempted.
       */
      
      status = _listen(pTargIoChannel);
      if (status == TMWDEFS_TRUE)
      {
        TCP_LISTENER   *pTcpListener = (TCP_LISTENER *)pTcpChannel->pTcpListener;
        pTcpChannel->pollFds[SOCKET_INDEX_LISTEN].fd = pTcpListener->listenSocket;
      }
    }
  }

  return(status);
}

/* function: linTCP_closeChannel */
void TMWDEFS_GLOBAL linTCP_closeChannel(TMWTARG_IO_CHANNEL *pTargIoChannel)
{
  TCP_IO_CHANNEL *pTcpChannel = (TCP_IO_CHANNEL *) pTargIoChannel->pChannelInfo;

  LINIODIAG_MSG("TCP(%s), closeChannel ", pTcpChannel->chnlConfig.chnlName);

  /* Check TLS configuration */
  if (pTcpChannel->chnlConfig.useTLS)
  {
#if TMWTARG_SUPPORT_TLS
    lintls_close(pTcpChannel);
#endif
  }
  else
  {
    _disconnect(pTcpChannel);

    if (pTcpChannel->udpSocket != INVALID_SOCKET)
    {
      close(pTcpChannel->udpSocket);
      pTcpChannel->udpSocket = INVALID_SOCKET;
      pTcpChannel->pollFds[SOCKET_INDEX_UDP].fd = INVALID_SOCKET;
    }
  }
}

/* function: linTCP_getTransmitReady */
TMWTYPES_MILLISECONDS TMWDEFS_GLOBAL linTCP_getTransmitReady(TMWTARG_IO_CHANNEL *pTargIoChannel)
{
  TCP_IO_CHANNEL *pTcpChannel = (TCP_IO_CHANNEL *) pTargIoChannel->pChannelInfo;
  if ((pTcpChannel->chnlConfig.mode == TMWTARGTCP_MODE_UDP)
    && (pTcpChannel->udpSocket != INVALID_SOCKET))
    return(0);

  if (pTcpChannel->dataSocket != INVALID_SOCKET)
    return(0);

  if ((pTcpChannel->chnlConfig.mode == TMWTARGTCP_MODE_DUAL_ENDPOINT)
    && (pTcpChannel->dataSocket == INVALID_SOCKET))
  {
    /* Retry connection */
    if (!_connect(pTcpChannel))
      return(1000);
  }
  return(500);    /* Wait for things to happen */
}

/* function: linTCP_receive, this also receives UDP data */
TMWTYPES_USHORT TMWDEFS_GLOBAL linTCP_receive(
  TMWTARG_IO_CHANNEL *pTargIoChannel,
  TMWTYPES_UCHAR *pBuff,
  TMWTYPES_USHORT maxBytes,
  TMWTYPES_MILLISECONDS maxTimeout,
  TMWTYPES_BOOL *pInterCharTimeoutOccurred)
{
  TCP_IO_CHANNEL    *pTcpChannel = (TCP_IO_CHANNEL *) pTargIoChannel->pChannelInfo;
  int               result;
  TMWTARG_UNUSED_PARAM(maxTimeout);
  TMWTARG_UNUSED_PARAM(pInterCharTimeoutOccurred);
  
  /* A new connect attempt was received so this connection was marked for disconnect */
  if (pTcpChannel->newConnectionRcvd)
  {
    pTcpChannel->newConnectionRcvd = TMWDEFS_FALSE;

    /* This close() is not necessary, the callback would cause the library to call tmwtarg_close()
     * but this consistedn with what is done throughout this file
     */
    _disconnect(pTcpChannel);

    if (pTargIoChannel->pChannelCallback != TMWDEFS_NULL)
    {
      pTargIoChannel->pChannelCallback(pTargIoChannel->pChannelCallbackParam,
        TMWDEFS_FALSE, /* close */
        TMWDEFS_TARG_OC_NEW_CONNECTION);
    }
    return(0);
  }

  /* first see if there are any bytes received on the UDP socket 
   * Currently only for DNP Networking.
   */
#if TMWTARG_SUPPORT_UDP
  if(pTcpChannel->udpSocket != INVALID_SOCKET)
  {
    TMWTYPES_USHORT numReceived;
    numReceived = _UDPReceive(pTcpChannel, pBuff, maxBytes);
    if(numReceived > 0)
    {  
      LINIODIAG_MSG("TCP(%s), Received %d bytes of UDP data",
                    pTcpChannel->chnlConfig.chnlName, numReceived);
      return(numReceived);
    }
  }
#endif

  if (pTcpChannel->dataSocket == INVALID_SOCKET)
    return(0);

  if (pTcpChannel->chnlConfig.useTLS)
  {
#if TMWTARG_SUPPORT_TLS
    result = lintls_read(pTcpChannel, pBuff, maxBytes);
    if (result >= 0)
    {
      return((TMWTYPES_USHORT)result);
    }
#endif
  }
  else
  {
    result = recv(pTcpChannel->dataSocket, pBuff, maxBytes, LINTCP_RECV_FLAGS);
    if ((result == -1) && ((errno == EAGAIN) || (errno == EWOULDBLOCK)))
    {
      /* if errno indicates there is no data available, simply return 0. */
      return((TMWTYPES_USHORT) 0);
    }
    if (result >= 0)
    {
      return((TMWTYPES_USHORT)result);
    }
  }

  _disconnect(pTcpChannel);

  if (pTargIoChannel->pChannelCallback != TMWDEFS_NULL)
    pTargIoChannel->pChannelCallback(pTargIoChannel->pChannelCallbackParam,
    TMWDEFS_FALSE, /* close */
    TMWDEFS_TARG_OC_FAILURE);

  return((TMWTYPES_USHORT) 0);
}

/* function: linTCP_transmit */
TMWTYPES_BOOL TMWDEFS_GLOBAL linTCP_transmit(
  TMWTARG_IO_CHANNEL *pTargIoChannel,
  TMWTYPES_UCHAR *pBuff,
  TMWTYPES_USHORT numBytes)
{
  TCP_IO_CHANNEL *pTcpChannel = (TCP_IO_CHANNEL *) pTargIoChannel->pChannelInfo;
  int result;

  /* Check TLS configuration */
#if TMWTARG_SUPPORT_TLS
  if (pTcpChannel->chnlConfig.useTLS)
  {
    result = lintls_transmit(pTcpChannel, pBuff, numBytes);
    if (result != 0)
    {
      return(TMWDEFS_TRUE); 
    }
    return(TMWDEFS_FALSE);
  }
#endif

  /* This function is called from the library's context, take the */
  /* channel's lock to ensure the polling thread does no update   */
  /* the socket's state until the send has been completed.        */
  TMWTARG_LOCK_SECTION(&pTcpChannel->tcpChannelLock);
  if (pTcpChannel->dataSocket != INVALID_SOCKET)
  {
    result = send(pTcpChannel->dataSocket, (char *) pBuff, numBytes, 0);
    if (result <= 0)
    {
      /* If send fails with EAGAIN or EWOULDBLOCK, retry the send to avoid an immediate disconnect */
      if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
      {
        struct timeval      timeout;
        fd_set              writeFds;
        timeout.tv_sec = 0;
        timeout.tv_usec = pTcpChannel->chnlConfig.ipConnectTimeout * 1000;
        FD_ZERO(&writeFds);
        FD_SET(pTcpChannel->dataSocket, &writeFds);
        result = select(pTcpChannel->dataSocket + 1, NULL, &writeFds, NULL, &timeout);
        if (result != SOCKET_ERROR)
        {
          result = send(pTcpChannel->dataSocket, (char *) pBuff, numBytes, 0);
        }
      }
      if (result <= 0)
      {
        _disconnect(pTcpChannel);
        if (pTargIoChannel->pChannelCallback != TMWDEFS_NULL)
        {
          pTargIoChannel->pChannelCallback(pTargIoChannel->pChannelCallbackParam,
            TMWDEFS_FALSE,
            TMWDEFS_TARG_OC_FAILURE);
        }
        TMWTARG_UNLOCK_SECTION(&pTcpChannel->tcpChannelLock);
        return(TMWDEFS_FALSE);
      }
    }
  }
  TMWTARG_UNLOCK_SECTION(&pTcpChannel->tcpChannelLock);
  return(TMWDEFS_TRUE);
}

void TMWDEFS_GLOBAL linTCP_checkForInputFunction(TMWTARG_IO_CHANNEL *pTargIoChannel, TMWTYPES_MILLISECONDS timeout)
{
  TCP_IO_CHANNEL *pTcpChannel = (TCP_IO_CHANNEL *)pTargIoChannel->pChannelInfo;
  int             nfds;

#if !TMWTARG_SUPPORT_POLL
  struct timeval  timeval_out;
  fd_set          readFds;
  int             result;
  TCP_LISTENER   *pTcpListener = NULL;
#endif

  if (_isChannelOpen(pTcpChannel))
  {
#if TMWTARG_SUPPORT_TLS
    if (pTcpChannel->chnlConfig.useTLS)
    {
      if (lintls_checkChannel(pTcpChannel))
      {
        pTargIoChannel->pReceiveCallbackFunc(pTargIoChannel->pCallbackParam);
      }
      tmwtarg_sleep(50);
      return;
    }
#endif
#if TMWTARG_SUPPORT_POLL
    nfds = poll(pTcpChannel->pollFds, SOCKET_INDEX_MAX, timeout);
    if (nfds > 0)
    {
#if TMWTARG_SUPPORT_UDP
      if (pTcpChannel->pollFds[SOCKET_INDEX_UDP].revents != 0)
      {
        _inputUdpData(pTcpChannel);
      }
#endif
      if (pTcpChannel->pollFds[SOCKET_INDEX_LISTEN].revents != 0)
      {
        _accept(pTcpChannel->pTcpListener);
      }
      pTargIoChannel->pReceiveCallbackFunc(pTargIoChannel->pCallbackParam);
    }
    else if (nfds < 0)
    {
      LINIODIAG_ERRORMSG("TCP(%s), checkInput: poll returned error %d", pTcpChannel->chnlConfig.chnlName, errno);
    }
#else /* !TMWTARG_SUPPORT_POLL */
    timeval_out.tv_sec = 0;
    timeval_out.tv_usec = timeout * 1000;
    FD_ZERO(&readFds);
    FD_SET(pTcpChannel->dataSocket, &readFds);
    nfds = pTcpChannel->dataSocket + 1;
    if (pTcpChannel->udpSocket != INVALID_SOCKET)
    {
      FD_SET(pTcpChannel->udpSocket, &readFds);
      if (pTcpChannel->udpSocket > pTcpChannel->dataSocket)
      {
        nfds = pTcpChannel->udpSocket + 1;
      }
    }
    if ((pTcpChannel->chnlConfig.mode == TMWTARGTCP_MODE_DUAL_ENDPOINT) && (pTcpChannel->pTcpListener))
    {
      pTcpListener = (TCP_LISTENER *)pTcpChannel->pTcpListener;
      FD_SET(pTcpListener->listenSocket, &readFds);
      if (nfds < (pTcpListener->listenSocket + 1))
      {
        nfds = pTcpListener->listenSocket + 1;
      }
    }
    result = select(nfds, &readFds, NULL, NULL, &timeval_out);
    if (result > 0)
    {
#if TMWTARG_SUPPORT_UDP
      if (FD_ISSET(pTcpChannel->udpSocket, &readFds))
      {
        _inputUdpData(pTcpChannel);
      }
#endif
      pTargIoChannel->pReceiveCallbackFunc(pTargIoChannel->pCallbackParam);
      if ((pTcpListener) && (FD_ISSET(pTcpListener->listenSocket, &readFds)))
      {
        _accept(pTcpListener);
      }
    }
#endif /* TMWTARG_SUPPORT_POLL */
  }
  else
  {
    /* LINIODIAG_MSG("TCP(%s), checkInput: timeout = %d\n",
                  pTcpChannel->chnlConfig.chnlName, timeout);*/
    switch (pTcpChannel->chnlConfig.mode) {

    case TMWTARGTCP_MODE_SERVER:
    case TMWTARGTCP_MODE_DUAL_ENDPOINT:
      _checkListener(pTcpChannel, timeout);
      break;

    case TMWTARGTCP_MODE_CLIENT:
      if ((_connect(pTcpChannel)) && (pTargIoChannel->chanThreadState == TMWTARG_THREAD_RUNNING))
      {
        pTargIoChannel->pChannelCallback(pTargIoChannel->pChannelCallbackParam,
          TMWDEFS_TRUE, /* open */
          TMWDEFS_TARG_OC_SUCCESS);
      }
      else
      {
        if (pTargIoChannel->chanState == TMWTARG_CHANNEL_OPENED)
        {
          _chanThread_sleep(pTcpChannel, pTcpChannel->connectRetry);
        }
      }
      break;

    case TMWTARGTCP_MODE_UDP: /* connectionless, no action required */
    default: 
      _chanThread_sleep(pTcpChannel, pTcpChannel->connectRetry);
      break;
    }
  }
}

/* function: linTCP_exit */
void TMWDEFS_GLOBAL linTCP_exit(void)
{
  if (_tcpSemaphore != TMWDEFS_NULL)
  {
    TMWTARG_LOCK_DELETE(&_tcpSemaphore);
    _tcpSemaphore = TMWDEFS_NULL;
  }
}

#if TMWTARG_SUPPORT_UDP
/* function: _setupUDP */
static TMWTYPES_BOOL _setupUDP(TCP_IO_CHANNEL *pTcpChannel)
{
  char *pIpAddressString;
  struct addrinfo *pAddrInfo;
  struct addrinfo hints;
  int    result;
  struct sockaddr_in my_addr;
  SOCKET udpSocket;

  if (pTcpChannel->udpSocket != INVALID_SOCKET)
  {
    return TMWDEFS_TRUE; 
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_flags = AI_PASSIVE;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_family = pTcpChannel->afInet;
  hints.ai_addrlen = 0;
  hints.ai_addr = NULL;
  hints.ai_canonname = NULL;
  hints.ai_next = NULL;

  if(pTcpChannel->chnlConfig.mode == TMWTARGTCP_MODE_UDP)
    /* If UDP only, then use the configured IP address to send all messages to */
    pIpAddressString = pTcpChannel->chnlConfig.ipAddress;
  else
    /* Otherwise use the broadcast address to send only broadcast UDP messages to */
    pIpAddressString = pTcpChannel->chnlConfig.udpBroadcastAddress;

  if(strcmp(pIpAddressString, "*.*.*.*") == 0)
  {
    pTcpChannel->destUDPaddr.sin_family = pTcpChannel->afInet;
    pTcpChannel->destUDPaddr.sin_port = htons(pTcpChannel->chnlConfig.destUDPPort);
    pTcpChannel->destUDPaddr.sin_addr.s_addr = INADDR_ANY;
  }
  else 
  {
    result = getaddrinfo(pIpAddressString, NULL, &hints, &pAddrInfo);
    if (result != 0)
    {
      LINIODIAG_ERRORMSG("UDP(%s), address resolution failed with %d",
                         pTcpChannel->chnlConfig.chnlName, result); 
      return(TMWDEFS_FALSE);
    }
  
    /* Just use the first one */
    pTcpChannel->destUDPaddr.sin_family = pTcpChannel->afInet;
    pTcpChannel->destUDPaddr.sin_port = htons(pTcpChannel->chnlConfig.destUDPPort);
    memcpy(&pTcpChannel->destUDPaddr, pAddrInfo->ai_addr, pAddrInfo->ai_addrlen);
    pTcpChannel->destUDPaddrLen = pAddrInfo->ai_addrlen;
    freeaddrinfo(pAddrInfo);
  }


  /* Now set up UDP socket to send and receive on. */
  udpSocket = socket(pTcpChannel->afInet, SOCK_DGRAM, IPPROTO_UDP);
  if (udpSocket == INVALID_SOCKET)
  {
    LINIODIAG_ERRORMSG("UDP(%s), socket failed", pTcpChannel->chnlConfig.chnlName);
    return(TMWDEFS_FALSE);
  }

  my_addr.sin_family = pTcpChannel->afInet;
  my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  if (pTcpChannel->chnlConfig.localUDPPort == TMWTARG_UDP_PORT_ANY)
    my_addr.sin_port = 0;
  else
    my_addr.sin_port = htons(pTcpChannel->chnlConfig.localUDPPort);

  if (bind(udpSocket, (struct sockaddr *) &my_addr, sizeof(my_addr)) != 0)
  {
    LINIODIAG_ERRORMSG("UDP(%s), socket bind failed: %s",
                       pTcpChannel->chnlConfig.chnlName, strerror(errno));
    close(udpSocket);
    return(TMWDEFS_FALSE);
  }
  pTcpChannel->udpReadIndex = 0;
  pTcpChannel->udpWriteIndex = 0;
  pTcpChannel->udpSocket = udpSocket;
  pTcpChannel->pollFds[SOCKET_INDEX_UDP].fd = udpSocket;

  if(pTcpChannel->chnlConfig.validateUDPAddress)
  { 
    /* If UDP only, use the configured address */
    if(pTcpChannel->chnlConfig.mode == TMWTARGTCP_MODE_UDP)
    {
      pTcpChannel->validUDPAddress = pTcpChannel->destUDPaddr.sin_addr.s_addr;
    }
    else
    {
      /* Set UDPAddress for validation when connection is made */
      pTcpChannel->validUDPAddress = INADDR_NONE; 
    }
  }
  return(TMWDEFS_TRUE);
}

/* function: inputUdpData 
 * get UDP bytes from socket and copy into circular buffer
 */
static void _inputUdpData(TCP_IO_CHANNEL *pTcpChannel)
{
  /* Perform address check */
  struct sockaddr_in fromAddr;
  socklen_t   fromAddrLen;
  int         remain;
  int         result;
  char        tempBuff[ LINTCP_MAX_UDP_FRAME ];

  fromAddrLen = sizeof(fromAddr);
  result = recvfrom(pTcpChannel->udpSocket, tempBuff, LINTCP_MAX_UDP_FRAME, 0, 
    (struct sockaddr *) &fromAddr, &fromAddrLen);

  if (result < 0)
  {
    LINIODIAG_ERRORMSG("UDP(%s), Bad return from read of UDP: %d",
                       pTcpChannel->chnlConfig.chnlName, errno);
    return;
  }
 
  /* If outstation TCP and UDP, verify the src address with TCP connection end point.
   * If outstation UDP only, verify the src address of master
   * If master UDP only, verify src address of slave.
   * These are done by setting validUDPAddress to appropriate address
   *   if validation is enabled.
   */
  if((pTcpChannel->validUDPAddress != 0)
    &&(fromAddr.sin_addr.s_addr != pTcpChannel->validUDPAddress))
  {
    return;
  }

  TMWTARG_LOCK_SECTION(&pTcpChannel->udpBufferLock);
  pTcpChannel->sourceUDPPort = ntohs(fromAddr.sin_port);
  remain = LINTCP_UDP_BUFFER_SIZE - pTcpChannel->udpWriteIndex;
  if (remain >= result)
  {
    memcpy(&pTcpChannel->udpBuffer[ pTcpChannel->udpWriteIndex ], tempBuff, result);
    pTcpChannel->udpWriteIndex += result;
  }
  else
  {
    memcpy(&pTcpChannel->udpBuffer[ pTcpChannel->udpWriteIndex ], tempBuff, remain);
    result = result - remain;
    memcpy(&pTcpChannel->udpBuffer[ 0 ], &tempBuff[ remain ], result);
    pTcpChannel->udpWriteIndex = result;
  }
  TMWTARG_UNLOCK_SECTION(&pTcpChannel->udpBufferLock);

  return;
}

/* function: _UDPReceive
 *  Copy any received UDP data from circular buffer into return pointer
 */
static TMWTYPES_USHORT _UDPReceive(
  TCP_IO_CHANNEL  *pTcpChannel,
  TMWTYPES_UCHAR  *pBuff,
  TMWTYPES_ULONG  maxBytes)
{
  TMWTYPES_ULONG udpReadIndex;
  TMWTYPES_ULONG udpWriteIndex;
  TMWTYPES_ULONG bytesRead = 0;
  TMWTYPES_UCHAR *readPtr = NULL;

  /* See if there are any bytes in the circular buffer */
  if(pTcpChannel->udpReadIndex == pTcpChannel->udpWriteIndex)
    return(0);

  TMWTARG_LOCK_SECTION(&pTcpChannel->udpBufferLock);

  udpReadIndex = pTcpChannel->udpReadIndex;
  udpWriteIndex = pTcpChannel->udpWriteIndex;
  readPtr = &pTcpChannel->udpBuffer[udpReadIndex];

  if(udpReadIndex < udpWriteIndex)
  {
    bytesRead = udpWriteIndex - udpReadIndex;
    if(bytesRead > maxBytes)
    {
      bytesRead = maxBytes;
    }
    pTcpChannel->udpReadIndex += bytesRead;
  }
  else
  {
    bytesRead = LINTCP_UDP_BUFFER_SIZE - udpReadIndex;
    if(bytesRead > maxBytes)
    {
      bytesRead = maxBytes;
      pTcpChannel->udpReadIndex += bytesRead;
    }
    else
    {
      pTcpChannel->udpReadIndex = 0;
    }
  }
  memcpy(pBuff, readPtr, bytesRead);
  TMWTARG_UNLOCK_SECTION(&pTcpChannel->udpBufferLock);
  
  return((TMWTYPES_USHORT)bytesRead);
}

/* function: linTCP_transmitUDP */
TMWTYPES_BOOL TMWDEFS_GLOBAL linTCP_transmitUDP(
  TMWTARG_IO_CHANNEL *pTargIoChannel,
  TMWTYPES_UCHAR UDPPort,
  TMWTYPES_UCHAR *pBuff,
  TMWTYPES_USHORT numBytes)
{
  TCP_IO_CHANNEL      *pTcpChannel = (TCP_IO_CHANNEL *) pTargIoChannel->pChannelInfo;
  TMWTYPES_USHORT     nUDPPort;
  int                 result;

  if (pTcpChannel->udpSocket != INVALID_SOCKET)
  {
    if (pTcpChannel->sourceUDPPort == TMWTARG_UDP_PORT_NONE)
    {
      if (UDPPort == TMWTARG_UDP_SEND)
        nUDPPort = pTcpChannel->chnlConfig.destUDPPort;
      else
        nUDPPort = pTcpChannel->chnlConfig.initUnsolUDPPort;
    }
    else
    {
      /* If configuration allows it, use src port from previous request
       * This would only be allowed on an outstation.
       */
      if (pTcpChannel->chnlConfig.destUDPPort == TMWTARG_UDP_PORT_SRC)
        nUDPPort = pTcpChannel->sourceUDPPort;
      else
        nUDPPort = pTcpChannel->chnlConfig.destUDPPort;
    }

    pTcpChannel->destUDPaddr.sin_port = htons(nUDPPort);
    result = sendto(pTcpChannel->udpSocket, (char *) pBuff, numBytes, 0,
      (const struct sockaddr *) &pTcpChannel->destUDPaddr,
      pTcpChannel->destUDPaddrLen);
    if (result <= 0)
    {
      close(pTcpChannel->udpSocket);
      pTcpChannel->udpSocket = INVALID_SOCKET;

      if (pTargIoChannel->pChannelCallback != TMWDEFS_NULL)
        pTargIoChannel->pChannelCallback(pTargIoChannel->pChannelCallbackParam,
        TMWDEFS_FALSE, 
        TMWDEFS_TARG_OC_FAILURE);

      return(TMWDEFS_FALSE);
    }
  }
  return(TMWDEFS_TRUE);
}
#endif /* #if TMWTARG_SUPPORT_UDP */

#endif /* #if TMWTARG_SUPPORT_TCP */
