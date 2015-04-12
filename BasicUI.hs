module BasicUI where

import System.Exit
import System.IO
import System.IO.Error ( isEOFError, isPermissionError )
import System.Directory ( getHomeDirectory, doesFileExist )
import Control.Exception ( Exception, SomeException, catch, try, tryJust )
import Control.Monad ( guard )
import Data.Maybe ( fromJust )
import Data.Char ( isPrint, isAscii )
import Data.List ( isPrefixOf )
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Crypto.Random.DRBG
import Text.Regex.TDFA

import CryptoBackend

-- | Gets entropy over HMAC-DRBG seed with systems secure random number source.
genRandomness :: Int -> IO ByteString
genRandomness length = do
  gen <- newGenIO :: IO HmacDRBG
  let (bytes, _) = throwLeft $ genBytes length gen
  return bytes

-- | Helperfunction to display exceptions and a short error message.
invalidinput :: SomeException -> String -> IO ()
invalidinput e msg = do
  putStrLn "Invalid input."
  putStrLn $ "Exception: " ++ (show e)
  putStrLn msg


-- | Let the user enter input.
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


-- | Add indent of length cols to every line and unline all.
indent :: Int -> [String] -> String
indent cols lines =
    unlines $ zipWith (++) (take (length lines) $ repeat ind) lines
  where ind = take cols $ repeat ' '


-- | Helper function for getFullPath, replaces leading tilde by homePath.
-- <http://stackoverflow.com/questions/18610313/haskell-join-gethomedirectory-string>
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

-- | Load binary data from file
-- Returns IO Nothing if it fails.
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

-- | Write bytes to file and show error on permission error.
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


data DecryptionError = IOError | WrongKey

-- | Ask user for passphrase and open storage.
openAskPassphrase :: String
                  -> IO (Either DecryptionError Storage)
openAskPassphrase path = do
  res <- openPrepare path
  case res of
    Nothing -> return $ Left IOError
    Just (props, fcontent) -> do
      passphrase <- getPassphrase
      case passphrase of
        Left e -> do
          invalidinput e ""
          return $ Left IOError
        Right passphrase -> do
          let lockhash = getPBK props (BS8.pack passphrase)
          openFinalize props lockhash fcontent

openAskPassphraseRepeat :: String -> IO (Maybe Storage)
openAskPassphraseRepeat path = do
  res <- openAskPassphrase path
  case res of
    Left IOError -> return Nothing
    Left WrongKey -> openAskPassphraseRepeat path
    Right storage -> return $ Just storage

-- | Open storage using given lockhash.
openWithLockhash :: String
                 -> ByteString
                 -> IO (Either DecryptionError Storage)
openWithLockhash path lockhash = do
  res <- openPrepare path
  case res of
    Nothing -> return $ Left IOError
    Just (props, fcontent) ->
      openFinalize props lockhash fcontent

openWithLockhashRepeat :: String -> ByteString -> IO (Maybe Storage)
openWithLockhashRepeat path lockhash = do
  putStrLn "Trying known salt and key combination ..."
  res <- openWithLockhash path lockhash
  case res of
    Left IOError -> return Nothing
    Left WrongKey -> openAskPassphraseRepeat path
    Right storage -> do
      putStrLn "Remote storage was a copy of this storage."
      return $ Just storage

-- | Reads file and parses storage properties
openPrepare :: String -> IO (Maybe (StorageProps, ByteString))
openPrepare path = do
  existing <- doesFileExist path
  if not existing
    then do
      putStrLn "File doesn't exist."
      return Nothing
    else do
      fcontent <- BS.readFile path
      let (props, fcontent') = readProps fcontent
      case props of
        Nothing -> do
          putStrLn "Could not read plaintext properties of remote storage."
          putStrLn "Probably not a valid storage file or a wrong version :-("
          return Nothing
        Just props -> do
          if not $ checkStorageProps props
            then do
              putStrLn "WARNING: The standard property requirements\
                        \are not met."
              putStrLn "WARNING: The storage is most probably unsafe."
            else return ()
          if (version props) /= currentversion
            then do
              putStrLn $ "Container version: "++(show $ version props)
              putStrLn $ "Supported version: "++(show currentversion)
              putStrLn "The version of remote storage is not supported."
              return Nothing
            else
              return $ Just (props, fcontent')

-- | Try to open storagen with given lockhash.
openFinalize :: StorageProps
             -> ByteString
             -> ByteString
             -> IO (Either DecryptionError Storage)
openFinalize props lockhash encrypted = do
  case decryptWithLockhash props lockhash encrypted of
    Nothing -> do
      putStrLn "Authorization failed."
      return $ Left WrongKey
    Just (hash, serialized) -> do
      putStrLn "Authorization complete.\n"
      case checkHashAndParse hash serialized of
        Nothing -> do
          putStrLn "Hash doesn't match content."
          putStrLn "Data corrupted."
          return $ Left IOError
        Just storage ->
          return $ Right storage { props=Just props
                                 , lockhash=Just lockhash }


-- | Helper function printing storage properties to stdout
printStorageProps (Just StorageProps{..}) = do
  putStrLn $ "  Version: "++(show version)
  putStrLn $ "  PBKDF2 rounds: "++(show pbkdf2_rounds)
  putStrLn $ "  PBKDF2 length: "++(show pbkdf2_length)
  putStrLn $ "  Salt length: "++(show salt_length)
  putStrLn $ "  Salt: "++(printHex salt)
  putStrLn $ "  Inner salt length: "++(show innersalt_length)
  putStrLn $ "  Inner salt: "++(printHex innersalt)

-- | Prints stats and storage properties to stdout
printStorageStats Storage{..} = do
  putStrLn $ "Number of entries: "++(show $ length entries)
  putStrLn "Storage Properties:"
  printStorageProps props


-- | Generate a new inner salt and save the encrypted storage to the given path.
save :: String -> Storage -> IO ()
save path storage = do
  innersalt <- genRandomness (innersalt_length $ fromJust $ props storage)
  let fcontent = encrypt storage innersalt
  -- the `!x <- ...` forces strict evaluation (I think :-/ )
  !x <- BS.writeFile path fcontent
  putStrLn $ "Saved to "++path


--------------------------------------------------------------------------------
-- Prompt Functions

-- | Change the passphrase of the storage
-- The lockhash PBKDF2 is recalculated so it takes lazy seconds.
changelock :: String -> Storage -> Storage
changelock newpassphrase storage =
  let newlockhash = getPBK (fromJust $ props storage) (BS8.pack newpassphrase)
  in storage { lockhash=Just newlockhash }

-- | Ask the user to remember the passphrase.
-- Returns the plaintext passphrase if it was right or Nothing if it was
-- entered wrong or cancled.
rememberPassphrase :: Storage -> IO (Maybe String)
rememberPassphrase (Storage (Just props) (Just lockhash) _) = do
  ans <- getPassphrase
  case ans of
    Left e -> invalidinput e "" >> return Nothing
    Right ans -> do
      let lhash = getPBK props (BS8.pack ans)
      if lhash == lockhash
        then do
          putStrLn "Congrats, you remembered did it!"
          return $ Just ans
        else do
          putStrLn "Sorry, you're wrong."
          return Nothing

-- | Change the outer salt of the storage.
-- Also recalculates the PBKDF2 and may take some strict seconds.
resalt :: String -> Storage -> IO Storage
resalt passphrase storage = do
  let Just oldprops = props storage
  salt <- genRandomness $ salt_length oldprops
  let props' = oldprops { salt=salt }
      !newlockhash = getPBK props' (BS8.pack passphrase)
  return Storage{ props=Just props'
                , lockhash=Just newlockhash
                , entries=entries storage
                }


data DiffResult = NameConflict | NoMatch | Unchanged | Match SEntry String

merge :: Storage -> Storage -> IO Storage
merge source dest = do
  let (conflicts, new, changed, deleted) = diff (entries source) (entries dest)
      lengths = [length conflicts, length new, length changed, length deleted]
  putStrLn . unwords $ zipWith (++)
                     ["Conflicts: ", " New: ", " Changed: ", " Deleted: "]
                     (map show lengths)
  if sum lengths == 0
  then do
      putStrLn "No difference."
      return dest
  else do
    if not $ null conflicts
    then do
      putStrLn "Conflicting names:"
      putStrLn . indent 3 $ map name conflicts
      putStrLn "Resolve conflicts first!"
      return dest
    else do
      -- TODO
      return dest

diff :: [SEntry] -- ^ list of elements in source storage
     -> [SEntry] -- ^ list of elements in destination storage
     -> ([SEntry], [SEntry], [DiffResult], [SEntry])
     -- ^ Diffs sorted by (name-conflicts, new, changed, deleted) entries.
     -- The 'DiffResult' s only contain Matches.
diff [] dest = ([], [], [], dest)
diff source [] = ([], source, [], [])
diff (s:source) dest =
    case res of
      NameConflict -> (s:conflicts, new, changed, deleted)
      NoMatch -> (conflicts, s:new, changed, deleted)
      Unchanged -> (conflicts, new, changed, deleted)
      res -> (conflicts, new, res:changed, deleted)
  where (remaining, res) = diffConsumeElem s dest
        (conflicts, new, changed, deleted) = diff source remaining

-- | Find the corresponding element for source in dest and compare
diffConsumeElem :: SEntry   -- ^ the source element to search for
                -> [SEntry] -- ^ the dest list to search in
                -- ^ the list of remaining elements and the diff result
                -> ([SEntry], DiffResult)
diffConsumeElem s [] = ([], NoMatch)
diffConsumeElem s (d:dest) =
    case diffCompareElem s d of
      NoMatch ->
          let (remaining, res) = diffConsumeElem s dest
          in (d:remaining, res)
      res -> (dest, res)

-- | Compare one storage element to another.
diffCompareElem :: SEntry     -- ^ source element
                -> SEntry     -- ^ dest element
                -> DiffResult -- ^ the result containing source on match
diffCompareElem s@Phrase{} d@Phrase{}
    | (name s /= name d) = NoMatch
    | otherwise          =
        let hint = ((if comment s /= comment d
                     then "comment changed; " else "")
                 ++ (if phrase s /= phrase d
                     then "phrase changed;" else ""))
        in if null hint
           then Unchanged
           else Match s hint
diffCompareElem s d
    | (name s == name d) = NameConflict
    | otherwise          = NoMatch


-- | Sets the new number of PBKDF2 rounds and recalcs lockhash.  Needs
-- the plaintext passphrase to rerun PBKDF2. May take some strict
-- seconds.
changePBKDF2Rounds :: Int -> String -> Storage -> Storage
changePBKDF2Rounds rounds passphrase storage@(Storage (Just prop) _ _) =
  let prop' = prop{ pbkdf2_rounds=rounds }
      !newlockhash = getPBK prop' (BS8.pack passphrase)
  in storage{ props=Just prop', lockhash=Just newlockhash }


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
            if doesNameExist name existing
            then putStrLn "Name already assigned." >> return Nothing
            else return $ Just name

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

setField :: Maybe ByteString -> SEntry -> Storage -> IO (SEntry, Storage)
setField content field storage =
  case content of
    Nothing -> return (field, storage)
    Just content -> do
      let newentry = field{ field=content }
          newstorage = replaceEntry newentry storage
      putStrLn "New field data set."
      return (newentry, newstorage)
