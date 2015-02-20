
module Migrate (migrate) where

import System.Exit ( exitSuccess, exitFailure )
import qualified Data.ByteString.Internal as BSInternal
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString as BS
import Text.Read ( readMaybe )
-- crypto
import Crypto.PBKDF ( sha512PBKDF2 )
import Crypto.Random.DRBG
import Data.Bits( xor )

import qualified CryptoBackend as CB
import BasicUI ( getPassphraseOrFail, getFullPath, genRandomness
               , newStorage, save, printStorageStats )

migrate :: String -> String -> IO ()
migrate sourcepath destpath = do
  passphrase <- getPassphraseOrFail
  expandedsrcp <- getFullPath sourcepath
  fcontent <- BS.readFile $ expandedsrcp
  storage <- v1tov2 passphrase fcontent
  expandeddestp <- getFullPath destpath
  save expandeddestp storage
  putStrLn "\nNew storage with standard properties created: "
  printStorageStats storage
  putStrLn "Done."
  exitSuccess

-- Version 1 to Version 2

-- Storage entries lockhash salt
data V1Storage = Storage {
  entries :: [V1SEntry]
, lockhash :: String
, salt :: String
} deriving (Read)
-- SEntry name comment phrase
data V1SEntry = SEntry { name, comment, phrase :: String } deriving (Read)

-- | Decrypts and parses version 1 storage.
v1open :: String -> BS.ByteString -> IO V1Storage
v1open passphrase fcontent =
  let (salt, encrypted) = BS.splitAt 16 fcontent
      -- decrypt
      gen = getDRBG $ getHash passphrase (map BSInternal.w2c $ BS.unpack salt)
      (cipher, _) = throwLeft $ genBytes (BS.length encrypted) gen
      -- from [Word8], [Word8] to [Char]
      decrypted = BS.pack $ BS.zipWith xor encrypted cipher
      -- verify
      (verifier1, decrypted') = BS.splitAt 17 decrypted
      (verifier2, plaintext) = BS.splitAt 17 decrypted'
  in if verifier1 /= verifier2
      then do
        putStrLn $ (show verifier1) ++ " " ++ (show verifier2)
        putStrLn "Authentication failed."
        exitFailure
      else do
        let plainstring = map BSInternal.w2c $ BS.unpack plaintext
        putStrLn "Authentication complete."
        case (readMaybe plainstring :: Maybe V1Storage) of
          Nothing -> do
            putStrLn "Data corrupted."
            exitFailure
          Just storage -> do
            putStrLn "Decryption successful."
            return storage
  where
    getHash passphrase salt = sha512PBKDF2 passphrase salt 150000 64 :: String
    getDRBG seed = throwLeft (newGen (BS8.pack seed)) :: HashDRBG

-- | Try to open as version 1 storage and convert to version 2 storage.
-- You can call BasicUI.save on the returned type.
v1tov2 :: String -> BS.ByteString -> IO CB.Storage
v1tov2 passphrase fcontent = do
  putStrLn "Trying to open as version 1 storage ..."
  (Storage v1entries _ _) <- v1open passphrase fcontent
  let es = map (\(SEntry name comment phrase) -> CB.Phrase name comment phrase)
               v1entries
  -- Create version 1 storage with new passphrase
  putStrLn "Give me a new passphrase."
  (CB.Storage props lockh _) <- newStorage
  return $ CB.Storage props lockh es

