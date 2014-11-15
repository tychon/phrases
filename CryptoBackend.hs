
module CryptoBackend where

import Control.Exception( assert )
import Data.Maybe ( fromJust )
import Numeric ( showHex )
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8 ( singleton, unpack, pack, elemIndex )
-- crypto
import Crypto.Hash.SHA256 ( hash )
import Crypto.PBKDF( sha512PBKDF2 )
import Crypto.Random.DRBG
import Data.Bits( xor )

-- legacy storage type
data StorageLegacy1 = StorageLegacy1 {
  entrieslegacy :: [SEntry],
  lockhashlegacy :: String,
  saltlegacy :: String }
    deriving (Show, Read)
data SEntryLegacy1 = SEntryLegacy1 {
  namelegacy,
  commentlegacy,
  phraselegacy :: String }
    deriving (Show, Read)

-- storage type
data StorageProps = StorageProps {
  version,
  salt_length,
  innersalt_length,
  pbkdf2_rounds,
  pbkdf2_length :: Int,
  salt,
  innersalt :: ByteString }
    deriving (Show, Read)
data Storage = Storage {
  props :: Maybe StorageProps,
  lockhash :: Maybe ByteString,
  entries :: [SEntry] }
    deriving (Show, Read)
data SEntry =
    Phrase {
      name,
      comment,
      phrase :: String }
  | Asym {
      name,
      comment,
      fingerprint,
      public,
      private :: String }
  deriving (Show, Read)

-- | Simply creates a ByteString containing one NUL character.
nullbytestring :: ByteString
nullbytestring = BS8.singleton '\0'

-- | Runs the PBKDF2 on the given passphrase and props.
-- Returns a String with the length as specified in (pbkdf2_length props).
getPBK :: StorageProps -> ByteString -> ByteString
getPBK StorageProps{..} passphrase =
  BS8.pack $ sha512PBKDF2 (BS8.unpack passphrase) (BS8.unpack salt) pbkdf2_rounds pbkdf2_length

-- | Initializes a DRBG from the given seed.
getDRBG :: ByteString -> HmacDRBG
getDRBG seed = throwLeft (newGen seed) :: HmacDRBG

-- | Retrieve standard storage properties.
-- You still have to initialize the salt and innersalts.
getStdStorageProps = StorageProps {
  version = 2,
  salt_length = 16,
  innersalt_length = 16,
  pbkdf2_rounds = 150000,
  pbkdf2_length = 64,
  salt = BS.empty,
  innersalt = BS.empty }

-- | Check StorageProps for sanity.
checkStorageProps StorageProps{..}
  | version >= 1
  , salt_length >= 16
  , innersalt_length >= 16
  , pbkdf2_rounds >= 150000
  , pbkdf2_length >= 64
  , BS.length salt == salt_length
  , BS.length innersalt == innersalt_length
    = True
  | otherwise
    = False

-- | Read the StorageProps from file content.
-- Returns the parsed Storage Props and the remaining content.
-- Don't forget to call checkStorageProps.
readProps :: ByteString -> (StorageProps, ByteString)
readProps fcontent =
  let propsend = fromJust $ BS8.elemIndex '\0' fcontent -- search for first nullbyte in file
      (propsstr, fcontent') = (BS.take propsend fcontent, BS.drop (propsend+1) fcontent)
      props = read (BS8.unpack propsstr) :: StorageProps
  in (props, fcontent')

-- | Decrypt an container when you have its props.
-- Takes the StorageProps the passphrase and the file content left after
-- consuming the StorageProps.
-- Returns Nothing if hashes don't match, Just (lockhash, hash, plaintext) in
-- case the passphrase worked. You still have to check the hash against the
-- plaintext and set props and lockhash in the parsed storage.
decrypt :: StorageProps -> ByteString -> ByteString -> Maybe (ByteString, ByteString, ByteString)
decrypt props@StorageProps{..} passphrase encrypted =
  let lockhash = (getPBK props passphrase)
      gen = getDRBG $ BS.append lockhash innersalt
      (cipher, _) = throwLeft $ genBytes (BS.length encrypted) gen
      decrypted = BS.pack $ BS.zipWith (xor) encrypted cipher
      -- check hashes
      (hash1, decrypted') = BS.splitAt 32 decrypted
      (hash2, plaintext) = BS.splitAt 32 decrypted'
  in if hash1 /= hash2
      then Nothing
      else Just (lockhash, hash1, plaintext)

-- | Pretty print ByteString as hex chars. Use to display hash.
printHex :: ByteString -> String
printHex = concat . map (flip showHex "") . BS.unpack

-- | Check if readhash and hash of plaintext match, then parse Storage.
-- Returns Nothing when hashes didn't match, Just Storage otherwise.
checkHash :: ByteString -> ByteString -> Maybe Storage
checkHash readhash plaintext =
  let texthash = hash plaintext
  in if readhash /= texthash
      then Nothing
      else Just $ read $ BS8.unpack plaintext

-- | Encrypts the storage with its containing properties and an extra innersalt.
-- You have to generate a newinnersalt yourself because it is an IO operation.
-- Returns a ByteString to be written to a file.
encrypt :: Storage -> ByteString -> ByteString
encrypt storage newinnersalt =
  let sprops = (fromJust $ props storage) { innersalt=newinnersalt }
      slockhash = fromJust $ lockhash storage
      plaintext = BS8.pack $ show $ storage { props=Nothing, lockhash=Nothing }
      texthash = hash plaintext
      gen = assert (BS.length newinnersalt == (innersalt_length sprops))
                   (getDRBG (BS.append slockhash newinnersalt))
      cipherlen = (BS.length plaintext) + 2 * (BS.length texthash)
      (cipher, _) = throwLeft $ genBytes cipherlen gen
      -- put together full plaintext
      fullplaintext = BS.append texthash $ BS.append texthash plaintext
      encrypted = BS.pack $ BS.zipWith xor fullplaintext cipher
  in BS.append (BS8.pack $ show sprops) $ BS.append nullbytestring encrypted

