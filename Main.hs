{-# LANGUAGE OverloadedStrings #-}
module Main where

import Network.Socks5
import Network.Socks5.Types
import Network.Socks5.Lowlevel
import Network.Socket hiding (recv, recvFrom, sendTo)
import Network.Socket.ByteString
import Control.Concurrent
import Data.List (find)
import Data.Foldable (for_)
import Data.Serialize (encode,decode)
import Control.Monad
import Control.Exception
import System.IO
import System.IO.Error
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString as B
import Data.ByteString (ByteString)
import BinaryHandle

------------------------------------------------------------------------
-- Configuration
------------------------------------------------------------------------


data Configuration = Configuration
  { listenHost    :: HostName
  , listenService :: ServiceName
  , debugLevel    :: Verbosity
  , logLock       :: MVar ()
  , configUser    :: ByteString
  , configPass    :: ByteString
  , authPreference :: [SocksMethod]
  , bindAddress   :: SockAddr
  , forceLearningMode :: Bool
  }

data Verbosity = VInfo | VDebug
  deriving (Read, Show, Eq, Ord)

getConfiguration = do
  logMutex <- newMVar ()
  return (Configuration "" "2080" VDebug logMutex "emertens" "paswerd" [SocksMethodUsernamePassword,SocksMethodNone]
                        (SockAddrInet aNY_PORT iNADDR_ANY) True)

------------------------------------------------------------------------
-- Logging
------------------------------------------------------------------------

logMsg :: Verbosity -> Configuration -> String -> IO ()
logMsg level config msg
  = when (level <= debugLevel config)
  $ do threadId <- myThreadId
       let msg' = drop 9 (show threadId) ++ ": " ++ msg
       withMVar (logLock config) (const (hPutStrLn stderr msg'))

info :: Configuration -> String -> IO ()
info = logMsg VInfo

debug :: Configuration -> String -> IO ()
debug = logMsg VDebug

------------------------------------------------------------------------
-- Main
------------------------------------------------------------------------

main :: IO ()
main = withSocketsDo $ do

  config <- getConfiguration

  let hints = tcpHints { addrFlags = [AI_PASSIVE, AI_ADDRCONFIG] }
  ais <- getAddrInfo (Just hints) (Just (listenHost config)) (Just (listenService config))

  when (null ais) (fail "Failed to resolve listening address")

  done <- newEmptyMVar
  for_ ais $ \ai ->
    forkIO (listenerLoop config ai `finally` putMVar done ())
  takeMVar done

------------------------------------------------------------------------
-- Top-level listener
------------------------------------------------------------------------

listenerLoop :: Configuration -> AddrInfo -> IO ()
listenerLoop config ai =
  withTcpSocket (addrFamily ai) $ \s -> do
  setSocketOption s ReuseAddr 1

  -- We support binding on multiple addresses. Keeping them separate
  -- will help later when we're making additional connections for UDP.
  when (addrFamily ai == AF_INET6) (setSocketOption s IPv6Only 1)

  bind s (addrAddress ai)
  info config ("Listening on " ++ show (addrAddress ai))
  listen s maxListenQueue

  forever $ do
    (c,who) <- accept s
    cxt     <- newGetContext
    info config ("Connection accepted from " ++ show who)
    forkIO (handleClientHello config c cxt who `finally` sClose c)


------------------------------------------------------------------------
-- Client startup
------------------------------------------------------------------------

handleClientHello :: Configuration -> Socket -> GetContext -> SockAddr -> IO ()
handleClientHello config s cxt who = do
  debug config ("Client thread started for " ++ show who)
  SocksHello authTypes <- recvGet s cxt

  debug config ("Client proposed " ++ show authTypes)
  debug config ("Server supports " ++ show (authPreference config))

  case find (`elem` authTypes) (authPreference config) of

    Just SocksMethodNone ->
         do debug config "No authentication selected"
            sendSerialized s (SocksHelloResponse SocksMethodNone)
            readyForClientRequest config s cxt who

    Just SocksMethodUsernamePassword ->
         do debug config "Username/password authentication selected"
            sendSerialized s (SocksHelloResponse SocksMethodUsernamePassword)
            login <- recvGet s cxt

            if configUser config == plainUsername login &&
               configPass config == plainPassword login

              then do debug config "Authentication succeeded"
                      sendSerialized s SocksPlainLoginSuccess
                      readyForClientRequest config s cxt who

              else do debug config "Authentication failed"
                      sendSerialized s SocksPlainLoginFailure

    _ -> do debug config "Authentication failed"
            sendSerialized s (SocksHelloResponse SocksMethodNotAcceptable)

------------------------------------------------------------------------
-- Post authentication
------------------------------------------------------------------------


readyForClientRequest :: Configuration -> Socket -> GetContext -> SockAddr -> IO ()
readyForClientRequest config s cxt who = do
  req <- recvGet s cxt
  mbDst <- resolveSocksAddress config (requestDst req)
  case mbDst of

    Nothing  -> do info config "Connection failed"
                   sendSerialized s (errorResponse SocksErrorHostUnreachable)

    Just dst -> do handleClientRequest (requestCommand req) config s who dst

------------------------------------------------------------------------
-- Request modes
------------------------------------------------------------------------

handleClientRequest :: SocksCommand -> Configuration -> Socket -> SockAddr -> SockAddr -> IO ()


handleClientRequest SocksCommandConnect config s who dst =
  flip finally (debug config "Thread complete") $
  withTcpSocket (sockAddrFamily dst) $ \c ->
  do
  debug config ("Connecting to " ++ show dst)
  connectResult <- tryIOError (connect c dst)

  case connectResult of

    Left err -> do
      info config ("Connect failed with " ++ show err)
      sendSerialized s (errorResponse SocksErrorConnectionRefused)

    Right () -> do
      info config ("Connected to " ++ show dst)
      localAddr <- sockAddrToSocksAddress `fmap` getSocketName c
      sendSerialized s (SocksResponse SocksReplySuccess localAddr)
      tcpRelay config s c



handleClientRequest SocksCommandBind config s who dst =
  flip finally (info config "Thread Complete") $
  withTcpSocket (sockAddrFamily dst) $ \c ->
  do
  debug config "Binding TCP socket"

  bind c (bindAddress config)
  listen c 0
  boundAddr <- getSocketName c
  info config ("Socket bound to " ++ show boundAddr)
  sendSerialized s (SocksResponse SocksReplySuccess (sockAddrToSocksAddress boundAddr))

  bracket (accept c) (sClose.fst) $ \(c1,who) ->
    do debug config ("Connection received from " ++ show who)
       sendSerialized s (SocksResponse SocksReplySuccess (sockAddrToSocksAddress who))
       tcpRelay config s c1



handleClientRequest SocksCommandUdpAssociate config s who dst =
  flip finally (info config "Thread Complete") $
  getSocketName s >>= \localAddr ->
  withUdpSocket (sockAddrFamily localAddr) $ \c1 ->
  withUdpSocket (sockAddrFamily localAddr) $ \c2 ->
  do
  debug config "Associating UDP socket"
  debug config ("Client UDP address: " ++ show dst)

  bind c1 (setPort 0 localAddr)
  localDataAddr <- getSocketName c1
  debug config ("Server UDP address: " ++ show localDataAddr)

  bind c2 (wildAddress (sockAddrFamily localAddr))
  remoteDataAddr <- getSocketName c2
  info config ("UDP outgoing socket bound to " ++ show remoteDataAddr)

  sendSerialized s (SocksResponse SocksReplySuccess (sockAddrToSocksAddress localDataAddr))

  let relay = if forceLearningMode config || isWild dst then learningUdpRelay else udpRelay
  relay config c1 c2 dst

  -- UDP connections are preserved until the control connection goes down
  setSocketOption s KeepAlive 1
  recv s 1
  return ()


handleClientRequest cmd config s who _ = do
  info config ("Unsupported command " ++ show cmd)
  sendSerialized s (errorResponse SocksErrorCommandNotSupported)

isWild (SockAddrInet  p   h  ) = p == aNY_PORT || h == iNADDR_ANY
isWild (SockAddrInet6 p _ h _) = p == aNY_PORT || h == iN6ADDR_ANY
isWild (SockAddrUnix  _      ) = error "isWild: SockAddrUnix not supported"

discardIOErrors m = catchIOError m (const (return ()))

learningUdpRelay :: Configuration -> Socket -> Socket -> SockAddr -> IO ()
learningUdpRelay config c1 c2 dst =
  do debug config "UDP address learning mode"
     forkIO (discardIOErrors handleFirst)
     return ()
  where
  handleFirst = do

    (bs,src) <- recvFrom c1 4096
    debug config ("-> client " ++ show src ++ " (" ++ show (B.length bs) ++ ")")

    case decode bs of

      Right udp | udpFragment udp == 0 -> do
        mbAddr <- resolveSocksAddress config (udpRemoteAddr udp)
        case mbAddr of
          Nothing   -> do debug config ("Dropping unresolvable packet: " ++ show (udpRemoteAddr udp))
          Just addr -> do let cnts = udpContents udp
                          debug config ("<- remote " ++ show addr ++ " (" ++ show (B.length cnts) ++ ")")
                          sendTo c2 cnts addr
                          return ()
        udpRelay config c1 c2 src

      Left err -> do debug config ("Ignoring malformed UDP packet: " ++ err)
                     handleFirst


udpRelay :: Configuration -> Socket -> Socket -> SockAddr -> IO ()
udpRelay config c1 c2 dst = do

  _forwardThread  <- forkIO $ discardIOErrors $ forever $ do

    (bs,src) <- recvFrom c1 4096
    debug config ("-> client " ++ show src ++ " (" ++ show (B.length bs) ++ ")")

    case (src == dst, decode bs) of
      (False,_)    -> debug config "Dropping UDP packet due to source mismatch"
      (_,Left err) -> debug config ("Dropping malformed UDP packet: " ++ err)
      (_,Right udp) | udpFragment udp /= 0 -> debug config ("Dropping fragmented UDP packet: " ++ show (udpFragment udp))

      (True, Right udp) -> do
        mbAddr <- resolveSocksAddress config (udpRemoteAddr udp)
        case mbAddr of
          Nothing   -> do debug config "Dropping unresolvable packet"
          Just addr -> do let cnts = udpContents udp
                          debug config ("<- remote " ++ show addr ++ " (" ++ show (B.length cnts) ++ ")")
                          sendTo c2 cnts addr
                          return ()


  _backwardThread <- forkIO $ discardIOErrors $ forever $ do
    (msg, remote) <- recvFrom c2 4096
    debug config ("-> remote " ++ show remote ++ " (" ++ show (B.length msg) ++ ")")
    let cnts = encode (SocksUdpEnvelope 0 (sockAddrToSocksAddress remote) msg)
    debug config ("<- client " ++ show dst ++ " (" ++ show (B.length cnts) ++ ")")
    sendTo c1 cnts dst

  return ()


------------------------------------------------------------------------
-- TCP Proxy
------------------------------------------------------------------------

tcpRelay :: Configuration -> Socket -> Socket -> IO ()
tcpRelay config s c = do
  done <- newEmptyMVar
  t1 <- forkIO (shuttle config s c `finally` putMVar done ())
  t2 <- forkIO (shuttle config c s `finally` putMVar done ())
  takeMVar done
  takeMVar done

shuttle :: Configuration -> Socket -> Socket -> IO ()
shuttle config source sink = loop `finally` cleanup
  where
  cleanup = do _ <- tryIOError (shutdown source ShutdownReceive)
               _ <- tryIOError (shutdown sink   ShutdownSend)
               return ()
  loop = do
    sourcePeer <- getPeerName source
    sourceName <- getSocketName source
    sinkName   <- getSocketName sink
    sinkPeer   <- getPeerName sink
    bs <- recv source (8*4096)
    unless (B.null bs) $ do
      sendAll sink bs
      debug config (show sourcePeer ++ " -> " ++ show sourceName
                 ++ " : "
                 ++ show sinkName   ++ " -> " ++ show sinkPeer
                 ++ " (" ++ show (B.length bs) ++ ")")
      loop


------------------------------------------------------------------------
-- Address utilities
------------------------------------------------------------------------

sockAddrToSocksAddress :: SockAddr -> SocksAddress
sockAddrToSocksAddress (SockAddrInet  p   h  ) = SocksAddress (SocksAddrIPV4 h) p
sockAddrToSocksAddress (SockAddrInet6 p _ h _) = SocksAddress (SocksAddrIPV6 h) p
sockAddrToSocksAddress (SockAddrUnix _       ) = error "sockAddrToSocksAddress: Unix sockets not supported"

sockAddrFamily :: SockAddr -> Family
sockAddrFamily SockAddrInet  {} = AF_INET
sockAddrFamily SockAddrInet6 {} = AF_INET6
sockAddrFamily SockAddrUnix  {} = AF_UNIX

errorResponse :: SocksError -> SocksResponse
errorResponse err = (SocksResponse (SocksReplyError err) (SocksAddress (SocksAddrIPV4 iNADDR_ANY) aNY_PORT))

resolveSocksAddress :: Configuration -> SocksAddress -> IO (Maybe SockAddr)
resolveSocksAddress config (SocksAddress host port) =
  case host of
    SocksAddrIPV4 a -> return (Just (SockAddrInet  port   a  ))
    SocksAddrIPV6 a -> return (Just (SockAddrInet6 port 0 a 0))
    SocksAddrDomainName str -> do
      let hostname = B8.unpack str
      ais <- getAddrInfo (Just tcpHints) (Just hostname) (Just (show port))
      case ais of

        ai : _ -> do let addr = addrAddress ai
                     debug config ("Resolved " ++ hostname ++ " to " ++ show addr)
                     return (Just addr)

        []     -> do debug config ("Unable to resolve " ++ B8.unpack str)
                     return Nothing

tcpHints :: AddrInfo
tcpHints = defaultHints
         { addrSocketType = Stream
         , addrFlags      = [AI_ADDRCONFIG]
         }

setPort :: PortNumber -> SockAddr -> SockAddr
setPort port (SockAddrInet  _      host      ) = SockAddrInet  port      host
setPort port (SockAddrInet6 _ flow host scope) = SockAddrInet6 port flow host scope
setPort _    SockAddrUnix {}                   = error "unix sockets don't have ports"

getPort :: SockAddr -> PortNumber
getPort (SockAddrInet  port   _  ) = port
getPort (SockAddrInet6 port _ _ _) = port
getPort SockAddrUnix {}            = error "seriously, stop using unix sockets"

wildAddress :: Family -> SockAddr
wildAddress AF_INET  = SockAddrInet aNY_PORT iNADDR_ANY
wildAddress AF_INET6 = SockAddrInet6 aNY_PORT 0 iN6ADDR_ANY 0

withTcpSocket :: Family -> (Socket -> IO a) -> IO a
withTcpSocket family = bracket (socket family Stream defaultProtocol) sClose

withUdpSocket :: Family -> (Socket -> IO a) -> IO a
withUdpSocket family = bracket (socket family Datagram defaultProtocol) sClose
