
module BasicUI where

import System.Exit
import System.IO
import Control.Exception ( Exception, SomeException, catch )
import Data.Maybe ( fromJust )
import Data.Char ( isPrint )
import Data.ByteString.Char8 ( pack )
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS ( readFile, writeFile )
import qualified Data.ByteString.Char8 as BS8 ( pack, unpack )
import Crypto.Random.DRBG

import CryptoBackend

-- | Gets entropy over HMAC-DRBG seed with systems secure random number source.
genRandomness :: Int -> IO ByteString
genRandomness length = do
  gen <- newGenIO :: IO HmacDRBG
  let (bytes, _) = throwLeft $ genBytes length gen
  return bytes

-- | Let the user inter input.
-- Returns (Right String) when the user successfully entered something.
-- Returns (Left SomeException) when the user didn't want to enter something.
-- Contains a catch all clause. Use with care!
getPromptAns :: IO (Either SomeException String)
getPromptAns = do
    hFlush stdout
    catch f h
  where
    -- computation function
    f = do
      line <- getLine
      if all isPrint line
        then return (Right line)
        else error "Non-printable characters entered."
    -- exception handler
    h e = return (Left e)

-- | Turn off echoing on stdin and ask for input, reactivate echoing afterwards.
-- Returns the same result as getPromptAns.
getPassphrase :: IO (Either SomeException String)
getPassphrase = do
  putStr "Enter passphrase: "
  hSetEcho stdin False
  phrase <- getPromptAns
  hSetEcho stdin True
  putStrLn "<done>"
  hFlush stdout
  return phrase

-- | Like getPassphrase but calls exitFailure on Exception.
getPassphraseOrFail :: IO String
getPassphraseOrFail = do
  passphrase <- getPassphrase
  case passphrase of
    Left e -> do
      putStrLn $ "Exception: " ++ (show e)
      exitFailure
    Right passphrase -> do
      return passphrase

-- | Initialize Storage with passphrase and standard properties.
-- Generate permanent salt in (salt props).
-- innersalt will still be empty ByteString in (innersalt props).
initStdStorage :: String -> IO Storage
initStdStorage passphrase = do
  let props = getStdStorageProps
  salt <- genRandomness (salt_length props)
  let props' = props { salt=salt }
      lockhash = getPBK props' (BS8.pack passphrase)
  return Storage { props=Just props', lockhash=Just lockhash, entries=[] }

-- | Ask the user for a passphrase, then create a Storage with standard props.
-- Exits on empty passphrase or invalid input.
newStorage :: IO Storage
newStorage = do
  passphrase <- getPassphraseOrFail
  if length passphrase == 0
    then do
      putStrLn "Empty passphrase. Exit."
      exitSuccess
    else do
      initStdStorage passphrase

-- | Generate a new inner salt and save the encrypted storage to the given path.
save :: String -> Storage -> IO ()
save path storage = do
  innersalt <- genRandomness (innersalt_length $ fromJust $ props storage)
  let fcontent = encrypt storage innersalt
  BS.writeFile path fcontent

-- | Opens the container at the given path.
-- Calls exitFailure when storage version is not supported.
open :: String -> IO Storage
open path = do
  fcontent <- BS.readFile path
  let (maybeprops, fcontent') = readProps fcontent
  props <- case maybeprops of
    Nothing -> do
      putStrLn "Could not read plaintext properties of storage."
      putStrLn "Probably not a valid container file or a wrong version :-("
      exitFailure
    Just props -> return props
  if not $ checkStorageProps props
    then do
      putStrLn "WARNING: The standard property requirements are not met."
      putStrLn "WARNING: This container is most probably unsafe."
    else return ()
  if (version props) /= currentversion
    then do
      putStrLn $ "Container version: "++(show $ version props)++" Supported version: "++(show currentversion)
      putStrLn "The version of this container is not supported."
      exitFailure
    else return ()
  passphrasestr <- getPassphraseOrFail
  (lockhash, hash, serialized) <- case decrypt props (BS8.pack passphrasestr) fcontent' of
    Nothing -> do
      putStrLn "Inner verifiers don't match."
      putStrLn "Authorization failed."
      exitFailure
    Just x -> return x
  storage <- case checkHash hash serialized of
    Nothing -> do
      putStrLn "Hash doesn't match content."
      putStrLn "Data corrupted."
      exitFailure
    Just x -> return x
  putStrLn "Authorization complete."
  return storage { props=Just props, lockhash=Just lockhash }

