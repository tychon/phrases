
module Migrate (migrate) where

import System.Exit ( exitSuccess, exitFailure )
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Text.Read ( readMaybe )
-- crypto
import Crypto.PBKDF.ByteString ( sha512PBKDF2 )
import Crypto.Random.DRBG
import Data.Bits( xor )

import CryptoBackend
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
  putStrLn "New storage with standard properties created: "
  printStorageStats storage
  putStrLn "Done."
  exitSuccess

-- Version 1 to Version 2

-- Storage entries lockhash salt
data V1Storage = Storage [V1SEntry] String String deriving (Read)
-- SEntry name comment phrase
data V1SEntry = SEntry String String String deriving (Read)

-- | Decrypts and parses version 1 storage.
v1open :: String -> BS.ByteString -> IO V1Storage
v1open passphrase fcontent =
  let (salt, encrypted) = BS.splitAt 16 fcontent
      -- decrypt
      gen = getDRBG $ getHash (BS8.pack passphrase) salt
      (cipher, _) = throwLeft $ genBytes (BS.length encrypted) gen
      -- from [Word8], [Word8] to [Char]
      decrypted = BS8.unpack $ BS.pack $ BS.zipWith xor encrypted cipher
      -- verify
      verifier1 = take 17 decrypted
      verifier2 = take 17 $ drop 17 decrypted
  in if verifier1 /= verifier2
      then do
        putStrLn "Authentication failed."
        exitFailure
      else do
        putStrLn "Authentication complete."
        case (readMaybe $ drop 34 decrypted :: Maybe V1Storage) of
          Nothing -> do
            putStrLn "Data corrupted."
            exitFailure
          Just storage -> do
            putStrLn "Decryption successful."
            return storage
  where
    getHash passphrase salt = sha512PBKDF2 passphrase salt 150000 64 :: BS.ByteString
    getDRBG seed = throwLeft (newGen seed) :: HashDRBG

-- | Try to open as version 1 storage and convert to version 2 storage.
-- You can call BasicUI.save on the returned type.
v1tov2 :: String -> BS.ByteString -> IO Storage
v1tov2 passphrase fcontent = do
  putStrLn "Trying to open as version 1 storage ..."
  (Migrate.Storage v1entries _ _) <- v1open passphrase fcontent
  let entries = map (\(SEntry name comment phrase) -> Phrase name comment phrase)
                    v1entries
  -- Create version 1 storage with new passphrase
  putStrLn "Give me a new passphrase."
  storage <- newStorage
  return storage { entries=entries }

