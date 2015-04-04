module CryptoBackend where

import Control.Exception ( assert )
import Data.Maybe ( fromJust )
import Numeric ( showHex )
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Text.Read ( readMaybe )
-- crypto
import Crypto.Hash.SHA256 ( hash )
import Crypto.PBKDF ( sha512PBKDF2 )
import Crypto.Random.DRBG ( HmacDRBG, newGen, genBytes, throwLeft )
import Data.Bits ( xor )

currentversion = 2 :: Int

-- | Holds properties of the storage important for en- and decryption.
-- It is saved unencrypted in front of ciphertext.  Only version 1
-- storage has no storage properties field.
data StorageProps = StorageProps
    { version :: Int          -- ^ The numerical version of the storage
    , salt_length :: Int      -- ^ The length of the permanent salt in bytes
    , innersalt_length :: Int -- ^ The length of the innersalt in bytes
    , pbkdf2_rounds :: Int    -- ^ The number of iterations in PBKDF2
    , pbkdf2_length :: Int    -- ^ The length of the generated key in bytes
    , salt :: ByteString      -- ^ The permanent salt
    , innersalt :: ByteString -- ^ The inner salt
    } deriving (Show, Read)

data Storage = Storage
    -- | The storage properties associated to this storage.
    -- Set to Nothing when Storage is serialized.
    { props :: Maybe StorageProps
    -- | The hashed passphrase to the container without the innersalt.
    -- Derieved by running PBKDF2 on passphrase and salt.
    -- Set to Nothing when Storage is serialized.
    , lockhash :: Maybe ByteString
    -- | The list of entries in the container.
    , entries :: [SEntry]
    } deriving (Show, Read)

data SEntry =
    Phrase { -- for simple passwords
      name
    , comment
    , phrase :: String }
  | Asym { -- for asymmetric keys
      name
    , comment
    , fingerprint
    , public
    , private :: String }
  | Field { -- for general data
      name
    , comment :: String
    , field :: ByteString }
  deriving (Show, Read)

instance Eq SEntry where
  Phrase n1 _ _ == Phrase n2 _ _ = n1 == n2
  Phrase{}      == _             = False
  Asym n1 _ _ _ _ == Asym n2 _ _ _ _ = n1 == n2
  Asym{}          == _               = False
  Field n1 _ _ == Field n2 _ _ = n1 == n2
  Field{}      == _          = False
instance Ord SEntry where
  Phrase n1 _ _ <= Phrase n2 _ _ = n1 <= n2
  Phrase{}      <= _             = True
  Asym n1 _ _ _ _ <= Asym n2 _ _ _ _ = n1 <= n2
  Asym{}          <= Phrase{}        = False
  Asym{}          <= Field{}         = True
  Field n1 _ _ <= Field n2 _ _ = n1 <= n2
  Field{}    <= _          = False


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
  pbkdf2_rounds = 200000,
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

-- | Read the StorageProps from file content.  Returns the Maybe
-- StorageProps and the remaining content.  Returns Nothing when read
-- failed.  Don't forget to call checkStorageProps.

readProps :: ByteString -> (Maybe StorageProps, ByteString)
readProps fcontent =
  let -- search for first nullbyte in file
      propsend = fromJust $ BS8.elemIndex '\0' fcontent
      (propsstr, fcontent') = ( BS.take propsend fcontent
                              , BS.drop (propsend+1) fcontent)
      props = readMaybe (BS8.unpack propsstr) :: Maybe StorageProps
  in (props, fcontent')

-- | Decrypt an container when you have its props and the passphrase.
-- Returns lockhash and result of decryptWithLockhash.
decrypt :: StorageProps
        -> ByteString
	-> ByteString
	-> (ByteString, Maybe (ByteString, ByteString))
decrypt props passphrase encrypted =
  let lockhash = (getPBK props passphrase)
  in (lockhash, decryptWithLockhash props lockhash encrypted)

-- | Decrypt storage with known properties and lockhash.
-- Returns Nothing if hashes don't match (lockhash is wrong)
-- or (Just (hash, plaintext)) in case the lockhash is right.
-- You still have to check the hash against the plaintext and set
-- props and lockhash in the parsed storage.
decryptWithLockhash :: StorageProps
                    -> ByteString
                    -> ByteString
                    -> Maybe (ByteString, ByteString)
decryptWithLockhash props lockhash encrypted =
  let gen = getDRBG $ BS.append lockhash (innersalt props)
      (cipher, _) = throwLeft $ genBytes (BS.length encrypted) gen
      decrypted = BS.pack $ BS.zipWith (xor) encrypted cipher
      -- check hashes
      (hash1, decrypted') = BS.splitAt 32 decrypted
      (hash2, plaintext) = BS.splitAt 32 decrypted'
  in if hash1 /= hash2
      then Nothing
      else Just (hash1, plaintext)

-- | Pretty print ByteString as hex chars. Use to display hash.
printHex :: ByteString -> String
printHex = concat . map (flip showHex "") . BS.unpack

-- | Check if readhash and hash of plaintext match, then parse Storage.
-- Returns Nothing when hashes didn't match, Just Storage otherwise.
checkHashAndParse :: ByteString -> ByteString -> Maybe Storage
checkHashAndParse readhash plaintext =
  let texthash = hash plaintext
  in if readhash /= texthash
      then Nothing
      else readMaybe $ BS8.unpack plaintext


-- | Encrypts the storage with its contained properties and an extra innersalt.
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
      fullplaintext = assert (BS.length texthash == 32) (BS.append texthash $ BS.append texthash plaintext)
      encrypted = BS.pack $ BS.zipWith xor fullplaintext cipher
      container = BS.append (BS8.pack $ show sprops) $ BS.append nullbytestring encrypted
  in container

