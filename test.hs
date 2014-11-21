
import Control.Exception( assert )
import Data.Maybe ( fromJust )
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString as BS
import CryptoBackend
import BasicUI

main = do
  let passphrase = "testpassphrase"
  -- encrypt
  putStrLn "Encrypting empty container ..."
  storage <- initStdStorage passphrase
  innersalt <- genRandomness (innersalt_length $ fromJust $ props storage)
  let encrypted = encrypt storage innersalt
  putStrLn $ "Size (bytes): "++(show $ BS.length encrypted)
  -- decrypt
  putStrLn "Decrypting empty container ..."
  let (Just props, fcontent') = readProps encrypted
  let Just (lockhash, newhash, serialized)
              = assert (checkStorageProps props)
                       (decrypt props (BS8.pack passphrase) fcontent')
  putStrLn $ "Hash: "++(printHex newhash)

