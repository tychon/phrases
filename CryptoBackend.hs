
module CryptoBackend () where

import Control.Exception( assert )
import Data.Maybe ( fromJust )
import qualified Data.ByteString.Char8 as BS8 ( unpack, pack, elemIndex, take )
import qualified Data.ByteString.Internal as BSInternal (c2w, w2c)
import qualified Data.ByteString as BS
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
data Storage = Storage {
  salt :: String,
  lockhash :: String,
  entries :: [SEntry] }
    deriving (Show, Read)
data StorageProps = StorageProps {
  version,
  salt_length,
  innersalt_length,
  pbkdf2_rounds,
  pbkdf2_length :: Int }
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

--bsToString :: BS.ByteString -> String
--bsToString bytestring = (map BSInternal.w2c $ BS.unpack bytestring)

-- | Runs the PBKDF2 on the given passphrase and salt with given props.
-- Returns a String with the length as specified in (pbkdf2_length props).
getPBK :: StorageProps -> String -> String -> String
getPBK (StorageProps { pbkdf2_rounds=rounds, pbkdf2_length=length }) passphrase salt =
  sha512PBKDF2 passphrase salt rounds length

-- | Initializes a DRBG from the given seed.
getDRBG :: String -> HashDRBG
getDRBG seed = throwLeft (newGen (BS8.pack seed)) :: HashDRBG

getStdStorageProps = StorageProps {
  version = 2,
  salt_length = 16,
  innersalt_length = 16,
  pbkdf2_rounds = 150000,
  pbkdf2_length = 64 }

-- | Check StorageProps for sanity.
checkStorageProps p | version p >= 1
                    , salt_length p >= 16
                    , innersalt_length p >= 16
                    , pbkdf2_rounds p >= 150000
                    , pbkdf2_length p >= 64
                      = True
                    | otherwise
                      = False

-- | Read the StorageProps from file content.
-- Returns the parsed Storage Props and the remaining content.
-- Don't forget to call checkStorageProps.
readProps :: BS.ByteString -> (StorageProps, BS.ByteString)
readProps fcontent =
  let propsend = fromJust $ BS8.elemIndex '\0' fcontent
      (propsstr, fcontent') = (BS.take propsend fcontent, BS.drop (propsend+1) fcontent)
      props = read (BS8.unpack propsstr) :: StorageProps
  in (props, fcontent')

-- | Decrypt an container when you have its props.
-- Takes the StorageProps the passphrase and the file content left after
-- consuming the StorageProps.
-- Returns Nothing if hashes don't match, Just (hash, plaintext) in case the
-- passphrase worked. You still have to check the hash against the plaintext.
decrypt :: StorageProps -> String -> BS.ByteString -> Maybe (String, String)
decrypt props passphrase fcontent =
  let (salt, fcontent') = assert ((version props) == 2) (BS.splitAt (salt_length props) fcontent)
      (innersalt, encrypted) = BS.splitAt (innersalt_length props) fcontent'
      -- decrypt
      gen = getDRBG $ (getPBK props passphrase (BS8.unpack salt)) ++ (BS8.unpack innersalt)
      (cipher, _) = throwLeft $ genBytes (BS.length encrypted) gen
      decrypted = BS.pack $ BS.zipWith (xor) encrypted cipher
      -- check hashes
      (hash1, decrypted') = BS.splitAt 32 decrypted
      (hash2, plaintext) = BS.splitAt 32 decrypted'
  in if hash1 /= hash2
      then Nothing
      else Just (BS8.unpack hash1, BS8.unpack plaintext)

encrypt :: Storage -> BS.ByteString
encrypt storage@(Storage { entries=_, lockhash=lockhash, salt=salt }) =
  let plaintext = show storage
      gen = getDRBG lockhash
      cipherlen = (length plaintext) + 2 * verifier_length
      (cipher, gen') = throwLeft $ genBytes cipherlen gen
      (verifier, _) = throwLeft $ genBytes verifier_length gen'
      -- put together full plaintext
      fullplaintext = BS.append verifier $ BS.append verifier $ pack plaintext
      encrypted = BS.pack $ BS.zipWith xor fullplaintext cipher
  in BS.append (pack salt) encrypted

