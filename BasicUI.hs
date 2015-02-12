
module BasicUI where

import System.Exit
import System.IO
import System.IO.Error ( isEOFError, isPermissionError )
import System.Directory ( getHomeDirectory )
import Control.Exception ( Exception, SomeException, catch, try, tryJust )
import Control.Monad ( guard )
import Data.Maybe ( fromJust )
import Data.Char ( isPrint, isAscii )
import Data.List ( isPrefixOf )
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS ( readFile, writeFile )
import qualified Data.ByteString.Char8 as BS8 ( pack, unpack, empty, foldl' )
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

-- http://stackoverflow.com/questions/18610313/haskell-join-gethomedirectory-string
-- | Helper function for getFullPath, replaces leading tilde by homePath.
fullPath :: String -> String -> String
fullPath homePath s
  | "~" `isPrefixOf` s = homePath ++ (tail s)
  | otherwise          = s

-- | Expands tilde in beginning of path to users home directory.
getFullPath :: String -> IO String
getFullPath p = do
  homePath <- getHomeDirectory
  return $ fullPath homePath p

-- | Read from stdin until user enters EOT / Ctrl-D.
-- Use with bang pattern to get rid of high memory usage.
-- TODO better implementation, since this may be a memory leak?
loadStdin :: IO String
loadStdin = do
  c <- tryJust (guard . isEOFError) $ hGetChar stdin
  case c of
    Left e -> putStrLn "" >> return ""
    Right c -> do
      following <- loadStdin
      return $ c:following

-- | Load data from file, aborts when it's not ASCII
loadASCII :: String -> IO (Maybe String)
loadASCII lpath = do
  loadpath <- getFullPath lpath
  putStrLn $ "Loading ASCII data from file: " ++ loadpath
  content <- try $ readFile loadpath :: IO (Either SomeException String)
  case content of
    Left e -> do
      putStrLn "Could not read content, nothing changed."
      putStrLn $ show e
      return Nothing
    Right content -> do
      if all isAscii content
        then do
          return $ Just content
        else do
          putStrLn "Contains non ASCII characters, aborted."
          return Nothing

-- | Write String to file and show error on permission error.
writeASCII :: String -> String -> IO ()
writeASCII wpath text = do
  writepath <- getFullPath wpath
  putStrLn $ "Writing data to file: " ++ writepath
  res <- tryJust (\e -> if isPermissionError e then Just e else Nothing)
                 (writeFile writepath text)
  case res of
    Left e -> do
      putStrLn "Permission denied."
      putStrLn $ show e
      return ()
    Right () -> putStrLn "Done." >> return ()

-- | Load data from file, aborts when it's not ASCII
loadBytes :: String -> IO (Maybe ByteString)
loadBytes lpath = do
  loadpath <- getFullPath lpath
  putStrLn $ "Loading binary data from file: " ++ loadpath
  content <- try $ BS.readFile loadpath :: IO (Either SomeException ByteString)
  case content of
    Left e -> do
      putStrLn "Could not read data, nothing changed."
      putStrLn $ show e
      return Nothing
    Right content ->
      return $ Just content

writeBytes :: String -> ByteString -> IO ()
writeBytes wpath bytes = do
  writepath <- getFullPath wpath
  putStrLn $ "Writing data to file: " ++ writepath
  res <- tryJust (\e -> if isPermissionError e then Just e else Nothing)
                 (BS.writeFile writepath bytes)
  case res of
    Left e -> do
      putStrLn "Permission denied."
      putStrLn $ show e
      return ()
    Right () -> putStrLn "Done." >> return ()

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
  -- the `!x <- ...` forces strict evaluation (I think :-/ )
  !x <- BS.writeFile path fcontent
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
filterEntries :: String -> [SEntry] -> [SEntry]
filterEntries regex entries =
  let re = makeRegexOpts CompOption {
                           caseSensitive=False
                         , multiline=False
                         , rightAssoc=True
                         , newSyntax=True
                         , lastStarGreedy=True
                         } defaultExecOpt regex
  in filter (\e -> match re (name e)) entries

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

-- | Create a new field entry with empty content.
newFieldEntry :: String -> String -> IO (Maybe SEntry)
newFieldEntry name comment = do return $ Just (Field name comment empty)

-- | Replace an existing entry with a new one. Throws error if not found.
-- | Compares by name: onyl use for entries with unchaned names!
replaceEntry :: SEntry -> Storage -> Storage
replaceEntry repl s@(Storage _ _ entries) =
  s{ entries=(replaceEntry' repl entries) }
-- | Helper function for replaceEntry working on the list of entries.
replaceEntry' :: SEntry -> [SEntry] -> [SEntry]
replaceEntry' _ [] = error "Entry not found."
replaceEntry' repl (entry:entries)
  | (name repl) == (name entry) = repl:entries
  | otherwise                   = entry:(replaceEntry' repl entries)

-- | Delete entry from list. Throws error if not found.
deleteEntry :: SEntry -> [SEntry] -> [SEntry]
deleteEntry _ [] = error "Entry not found."
deleteEntry del (entry:entries)
  | (name del) == (name entry) = entries
  | otherwise                  = entry:(deleteEntry del entries)


--------------------------------------------------------------------------------
-- type specific functions

setAsymPub :: Maybe String -> SEntry -> Storage -> IO (SEntry, Storage)
setAsymPub content asym storage =
  case content of
    Nothing -> return (asym, storage)
    Just content -> do
      let newentry = asym{ public=content }
          newstorage = replaceEntry newentry storage
      putStrLn "New public key set."
      return (newentry, newstorage)

setAsymPriv :: Maybe String -> SEntry -> Storage -> IO (SEntry, Storage)
setAsymPriv content asym storage =
  case content of
    Nothing -> return (asym, storage)
    Just content -> do
      let newentry = asym{ private=content }
          newstorage = replaceEntry newentry storage
      putStrLn "New private key set."
      return (newentry, newstorage)

isFieldPrintable :: ByteString -> Bool
isFieldPrintable field =
  BS8.foldl' (\prev ch -> prev && isAscii ch && ch /= '\ESC') True field

setField :: Maybe ByteString -> SEntry -> Storage -> IO (SEntry, Storage)
setField content field storage =
  case content of
    Nothing -> return (field, storage)
    Just content -> do
      let newentry = field{ field=content }
          newstorage = replaceEntry newentry storage
      putStrLn "New field data set."
      return (newentry, newstorage)

