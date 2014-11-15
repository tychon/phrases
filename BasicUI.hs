
module BasicUI where

import Data.Maybe ( fromJust )
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS ( writeFile )
import qualified Data.ByteString.Char8 as BS8 ( pack, unpack )
import Crypto.Random.DRBG

import CryptoBackend

-- | Gets entropy over HMAC-DRBG seed with systems secure random number source.
genRandomness :: Int -> IO ByteString
genRandomness length = do
  gen <- newGenIO :: IO HmacDRBG
  let (bytes, _) = throwLeft $ genBytes length gen
  return bytes

-- | Initialize Storage with standard properties, generate permanent salt.
-- innersalt will still be empty ByteString.
initStdStorage :: String -> IO Storage
initStdStorage passphrase = do
  let props = getStdStorageProps
  salt <- genRandomness (salt_length props)
  let props' = props { salt=salt }
      lockhash = getPBK props (BS8.pack passphrase)
  return Storage { props=Just props', lockhash=Just lockhash, entries=[] }

-- | Generate a new inner salt and save the encrypted storage to the given path.
save :: String -> Storage -> IO ()
save path storage = do
  innersalt <- genRandomness (innersalt_length $ fromJust $ props storage)
  let fcontent = encrypt storage innersalt
  BS.writeFile path fcontent

