module BinaryHandle where

import Data.Serialize
import Data.ByteString
import Control.Concurrent.MVar
import Network.Socket.ByteString
import Network.Socket (Socket)

newtype GetContext = GetContext (MVar ByteString)

newGetContext :: IO GetContext
newGetContext = fmap GetContext (newMVar empty)

recvGet :: Serialize a => Socket -> GetContext -> IO a
recvGet sock (GetContext mvar) = do
  mb <- modifyMVar mvar $ \buffer ->
    let loop (Done r   rest) = return (rest, Right r)
        loop (Fail err rest) = return (rest, Left err)
        loop (Partial k)     = loop . k =<< recv sock 4096
    in loop (runGetPartial get buffer)
  case mb of
    Left err -> fail err
    Right x  -> return x
