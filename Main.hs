module Main where

import Network.Socks5
import Network.Socks5.Types
import Network.Socks5.Lowlevel
import Network.Socket hiding (recv)
import Network.Socket.ByteString
import Control.Concurrent
import Data.Foldable (for_)
import Control.Monad
import Control.Exception
import System.IO
import System.IO.Error
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString as B

data Configuration = Configuration
  { listenHost    :: HostName
  , listenService :: ServiceName
  , debugLevel    :: Verbosity
  , logLock       :: MVar ()
  }

data Verbosity = VInfo | VDebug
  deriving (Read, Show, Eq, Ord)

getConfiguration = do
  logMutex <- newMVar ()
  return (Configuration "::" "2080" VDebug logMutex)

logMsg level config msg
  = when (level <= debugLevel config)
  $ do threadId <- myThreadId
       let msg' = drop 9 (show threadId) ++ ": " ++ msg
       withMVar (logLock config) (const (hPutStrLn stderr msg'))

info = logMsg VInfo
debug = logMsg VDebug

main = do

  config <- getConfiguration

  let hints = tcpHints { addrFlags = [AI_PASSIVE, AI_ADDRCONFIG] }
  ais <- getAddrInfo (Just hints) (Just (listenHost config)) (Just (listenService config))

  when (null ais) (fail "Failed to resolve listening address")
  for_ ais $ \ai ->
    info config ("Listening on " ++ show (addrAddress ai))

  done <- newEmptyMVar
  for_ ais $ \ai ->
    forkIO (listenerLoop config ai `finally` putMVar done ())
  takeMVar done


listenerLoop config ai =
  bracket (socket (addrFamily ai) (addrSocketType ai) (addrProtocol ai)) sClose $ \s ->
  do setSocketOption s ReuseAddr 1
     bind s (addrAddress ai)
     listen s 5
     forever $ do
       (c,who) <- accept s
       info config ("Connection accepted from " ++ show who)
       forkIO (handleClientHello config c who `finally` sClose c)



handleClientHello config s who = do
  debug config ("Client thread started for " ++ show who)
  SocksHello authTypes <- waitSerialized s
  debug config ("Client proposed " ++ show authTypes)

  if SocksMethodNone `elem` authTypes

    then do debug config "No authentication selected"
            sendSerialized s (SocksHelloResponse SocksMethodNone)
            readyForClientRequest config s who

    else do debug config "No acceptable authentication methods proposed"
            sendSerialized s (SocksHelloResponse SocksMethodNotAcceptable)



readyForClientRequest config s who = do
  SocksRequest cmd dst <- waitSerialized s
  debug config ("Requesting " ++ show cmd ++ " @ " ++ show dst)
  mbDst <- resolveSocksAddress config dst
  case mbDst of
    Nothing -> do info config "Connection failed"
                  sendSerialized s (errorResponse SocksErrorHostUnreachable)
    Just dstAddr -> handleClientRequest cmd config s who dstAddr


------------------------------------------------------------------------
-- Request modes
------------------------------------------------------------------------

handleClientRequest SocksCommandConnect config s who dstAddr =
  bracket (socket (sockAddrFamily dstAddr) Stream defaultProtocol)
          (\s -> do sClose s
                    info config "Thread complete")
          $ \c -> do

  info config ("Connecting to " ++ show dstAddr)
  connectResult <- tryIOError (connect c dstAddr)

  case connectResult of

    Left err -> do
      info config ("Connect failed with " ++ show err)
      sendSerialized s (errorResponse SocksErrorConnectionRefused)

    Right () -> do
      info config ("Connected to " ++ show dstAddr)
      localAddr <- sockAddrToSocksAddress `fmap` getSocketName c
      sendSerialized s (SocksResponse SocksReplySuccess localAddr)
      tcpRelay config s c


handleClientRequest cmd config s who _ = do
  info config ("Unsupported command " ++ show cmd)
  sendSerialized s (errorResponse SocksErrorCommandNotSupported)


------------------------------------------------------------------------
-- TCP Proxy
------------------------------------------------------------------------

tcpRelay config s c = do
  done <- newEmptyMVar
  t1 <- forkIO $ shuttle s c `finally` putMVar done ()
  t2 <- forkIO $ shuttle c s `finally` putMVar done ()
  takeMVar done
  killThread t1
  killThread t2

shuttle source sink = do
  bs <- recv source 4096
  unless (B.null bs) (sendAll sink bs >> shuttle source sink)



------------------------------------------------------------------------
-- 
------------------------------------------------------------------------

sockAddrToSocksAddress :: SockAddr -> SocksAddress
sockAddrToSocksAddress (SockAddrInet  p   h  ) = SocksAddress (SocksAddrIPV4 h) p
sockAddrToSocksAddress (SockAddrInet6 p _ h _) = SocksAddress (SocksAddrIPV6 h) p

sockAddrFamily :: SockAddr -> Family
sockAddrFamily SockAddrInet  {} = AF_INET
sockAddrFamily SockAddrInet6 {} = AF_INET6
sockAddrFamily SockAddrUnix  {} = AF_UNIX

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
                     info config ("Resolved " ++ hostname ++ " to " ++ show addr)
                     return (Just addr)

        []     -> do info config ("Unable to resolve " ++ B8.unpack str)
                     return Nothing

tcpHints = defaultHints
         { addrSocketType = Stream
         , addrFlags      = [AI_ADDRCONFIG]
         }
