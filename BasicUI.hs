
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
import Text.Regex.TDFA

import CryptoBackend

-- | Gets entropy over HMAC-DRBG seed with systems secure random number source.
genRandomness :: Int -> IO ByteString
genRandomness length = do
  gen <- newGenIO :: IO HmacDRBG
  let (bytes, _) = throwLeft $ genBytes length gen
  return bytes

invalidinput :: SomeException -> String -> IO ()
invalidinput e msg = do
  putStrLn "Invalid input."
  putStrLn $ "Exception: " ++ (show e)
  putStrLn msg

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


--------------------------------------------------------------------------------
-- Functions for cmd line commands

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
  putStrLn $ "Saved to "++path

-- | Opens the container at the given path.
-- Calls exitFailure if anything goes wrong.
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
      putStrLn "Authorization failed."
      exitFailure
    Just x -> return x
  putStrLn "Authorization complete.\n"
  storage <- case checkHash hash serialized of
    Nothing -> do
      putStrLn "Hash doesn't match content."
      putStrLn "Data corrupted."
      exitFailure
    Just x -> return x
  return storage { props=Just props, lockhash=Just lockhash }

printStorageProps (Just StorageProps{..}) = do
  putStrLn $ "  Version: "++(show version)
  putStrLn $ "  PBKDF2 rounds: "++(show pbkdf2_rounds)
  putStrLn $ "  PBKDF2 length: "++(show pbkdf2_length)
  putStrLn $ "  Salt length: "++(show salt_length)
  putStrLn $ "  Salt: "++(printHex salt)
  putStrLn $ "  Inner salt length: "++(show innersalt_length)
  putStrLn $ "  Inner salt: "++(printHex innersalt)

printStorageStats Storage{..} = do
  putStrLn $ "Number of entries: "++(show $ length entries)
  putStrLn "Storage Properties:"
  printStorageProps props

-- | Change the passphrase of the storage
-- The lockhash PBKDF2 is recalculated so it takes lazy seconds.
changelock :: String -> Storage -> Storage
changelock newpassphrase storage =
  let newlockhash = getPBK (fromJust $ props storage) (BS8.pack newpassphrase)
  in storage { lockhash=Just newlockhash }

-- | Change the outer salt of the storage.
-- Also recalculates the PBKDF2 and takes lazy seconds.
resalt :: String -> Storage -> IO Storage
resalt passphrase storage = do
  let Just oldprops = props storage
  salt <- genRandomness $ salt_length oldprops
  let props' = oldprops { salt=salt }
      newlockhash = getPBK props' (BS8.pack passphrase)
  return Storage { props=Just props', lockhash=Just newlockhash, entries=entries storage }


--------------------------------------------------------------------------------
-- Prompt Functions

-- | Returns all entries whose names match the given regex.
-- TODO refactor with filter function
filterEntries :: String -> [SEntry] -> [SEntry]
filterEntries regex [] = []
filterEntries regex (entry:list) =
  let re = makeRegexOpts CompOption {
                           caseSensitive=False
                         , multiline=False
                         , rightAssoc=True
                         , newSyntax=True
                         , lastStarGreedy=True
                         } defaultExecOpt regex
  in if match re (name entry)
       then entry:(filterEntries regex list)
       else filterEntries regex list

-- | Searches for given name in the list of entries.
doesNameExist :: String -> [SEntry] -> Bool
doesNameExist searchname [] = False
doesNameExist searchname (entry:entries)
  | searchname == (name entry) = True
  | otherwise                  = doesNameExist searchname entries

-- | Ask the user for a name and check if its valid and unique.
-- Returns Just name if everything worked out, Nothing otherwise.
getUniqueName :: [SEntry] -> IO (Maybe String)
getUniqueName existing = do
  putStr "Name: "
  ans <- getPromptAns
  case ans of
    Left e -> invalidinput e "" >> return Nothing
    Right name -> do
      if name =~ "^[a-zA-Z0-9_-]+$"
        then
          if doesNameExist name existing
            then putStrLn "Name already assigned." >> return Nothing
            else return $ Just name
        else do
          putStrLn "Name must be matching ^[a-zA-Z0-9_-]+$ ."
          return Nothing

-- | Add an entry at the right place to maintain lexicographic order.
addEntry :: SEntry -> [SEntry] -> [SEntry]
addEntry newentry [] = [newentry]
addEntry newentry (entry:entries)
  | newentry < entry = newentry:entry:entries
  | otherwise        = entry:(addEntry newentry entries)

-- | Create a new Phrase object.
-- Asks user for password.
newPhraseEntry :: String -> String -> IO (Maybe SEntry)
newPhraseEntry name comment = do
  passwd <- getPassphrase
  case passwd of
    Left e -> invalidinput e "" >> return Nothing
    Right passwd -> return $ Just (Phrase name comment passwd)

-- | Create a new Asym object for asymmetric keys
-- Asks user for fingerprint, pub and private key left empty.
newAsymEntry :: String -> String -> IO (Maybe SEntry)
newAsymEntry name comment = do
  putStr "Fingerprint: "
  ans <- getPromptAns
  case ans of
    Left e -> invalidinput e "" >> return Nothing
    Right fprint -> return $ Just (Asym name comment fprint "" "")

-- | Replace an existing Entry with a new one. Throws error if not found.
replaceEntry :: SEntry -> [SEntry] -> [SEntry]
replaceEntry _ [] = error "Entry not found."
replaceEntry repl (entry:entries)
  | (name repl) == (name entry) = repl:entries
  | otherwise                   = entry:(replaceEntry repl entries)

-- | Delete entry from list. Throws error if not found.
deleteEntry :: SEntry -> [SEntry] -> [SEntry]
deleteEntry _ [] = error "Entry not found."
deleteEntry del (entry:entries)
  | (name del) == (name entry) = entries
  | otherwise                  = entry:(deleteEntry del entries)

