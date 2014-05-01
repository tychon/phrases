
module Main( main ) where

-- io / interaction
import System.Environment
import Control.Monad( when )
import Control.Exception( try )
import System.Exit
import System.IO
import System.IO.Error( isEOFError )
import System.Console.GetOpt
import System.Console.ANSI( clearLine, setCursorColumn, clearScreen )
-- general
import Data.ByteString.Char8( pack )
import qualified Data.ByteString.Internal as BSInternal (c2w, w2c)
import qualified Data.ByteString as BS
import Text.Regex.Posix
import Text.Printf( printf )
import Data.Char( toUpper )
-- crypto
import Crypto.PBKDF( sha512PBKDF2 )
import Crypto.Random.DRBG
import Data.Bits( xor )

main = do putStrLn "This is your passphrase storage manager."
          -- parse command line arguments
          args <- getArgs
          case getOpt RequireOrder options args of
            (flags, [], []) -> do
                -- show version and exit
                when (Version `elem` flags) $ do
                    putStrLn "Version [unimplemented]\n" -- Unimplemented
                    putStrLn $ usageInfo header options
                    exitSuccess
                -- ask for passphrase, decrypt and load data file
                let path = findInputPath flags
                putStrLn $ "Storage File: "++path
                if (InitStorage `elem` flags)
                    then do let storage = Storage { entries = [], lockhash="", salt="" }
                            putStrLn "Initializing Storage:"
                            clres <- changeLock path storage
                            case clres of
                              Nothing -> exitFailure
                              Just storage' ->
                                  mainprompt path storage' NoPromptInfo
                    else do storage@(Storage { entries=entries }) <- openStorage path
                            putStrLn "Loaded."
                            putStrLn "== All Entries "
                            let list = listEntries ".*" entries
                            putStr $ unlines $ showEntries 1 list
                            mainprompt path storage (PromptList list)
            (_, nonOpts, []) -> error $ "unrecognized arguments: " ++ unwords nonOpts
            (_, _, msgs) -> error $ concat msgs ++ usageInfo header options

-- command line args

data Flag = Version | InitStorage | Input String deriving (Show, Eq)

options = [
    Option ['V'] ["version"] (NoArg Version) "show version number",
    Option ['n'] ["init"]    (NoArg InitStorage) "does not load content from input file",
    Option ['i'] ["input"]   (ReqArg Input "FILE") "the data file"
  ]

header = "Usage: main [OPTION...]"

findInputPath [] = "passphrases"
findInputPath (Input path:flags) = path
findInputPath (_:flags) = findInputPath flags

getPromptAns :: IO (Maybe String)
getPromptAns = do hFlush stdout
                  input <- try getLine
                  case input of
                    Left e -> if isEOFError e
                                  then do putStrLn "[EOT]"
                                          return Nothing
                                  else error ("IOError: "++(show e))
                    Right inp -> return (Just inp)

-----------
-- storage and its functions

data Storage = Storage { entries :: [SEntry], lockhash :: String, salt :: String }
       deriving (Show, Read)
data SEntry = SEntry { name, comment, phrase :: String }
       deriving (Show, Read)

-- set passphrase and salt
setPassphrase :: Storage -> String -> IO Storage
setPassphrase (Storage entries _ _) newpassphrase = do
  gen <- newGenIO :: IO HashDRBG
  let (newsaltbs, _) = throwLeft $ genBytes salt_length gen
      newsalt = bsToString newsaltbs
      lockhash = getHash newpassphrase newsalt
  return (Storage entries lockhash newsalt)

-- new
newEntry :: SEntry -> [SEntry] -> [SEntry]
newEntry entry [] = [entry]
newEntry
  entry@(SEntry { name=newname })
  (curentry@(SEntry { name=curname }):entries)
  = if (map toUpper newname) < (map toUpper curname) then
        entry:curentry:entries
    else curentry:(newEntry entry entries)

-- list
listEntries :: String -> [SEntry] -> [SEntry]
listEntries _ [] = []
listEntries
  regex
  (e@(SEntry name comment phrase):entries)
  = if name =~ regex then
        e:(listEntries regex entries)
    else
        listEntries regex entries

-- print list of entries to list of strings
showEntries ::
     Int      -- The start index for counting the keys
  -> [SEntry] -- The list of entries
  -> [String] -- The list of lines to be printed without '\n'
showEntries _ [] = []
showEntries counter ((SEntry name comment phrase):entries) =
  let name' = justl name 24
      comment' = take 50 comment
  in (printf "%03d %s %s" counter name' comment'):(showEntries (counter+1) entries)

justl :: String -> Int -> String
justl str len =
  let txtlen = length str
  in  take len $ str ++ (concat $ take (len - txtlen) $ repeat ". ")

-- change name
changeName :: String -> String -> [SEntry] -> [SEntry]
changeName _ _ [] = []
changeName
  oldname
  newname
  (curentry@(SEntry name comment phrase):entries)
  = if name == oldname then
        (SEntry newname comment phrase):entries
    else
        curentry:(changeName oldname newname entries)

changePassphrase :: String -> String -> [SEntry] -> [SEntry]
changePassphrase _ _ [] = []
changePassphrase
  name
  newphrase
  (curentry@(SEntry curname comment phrase):entries)
  = if curname == name then
        (SEntry name comment newphrase):entries
    else
        curentry:(changePassphrase name newphrase entries)

-- | Deletes only the first occurence of SEntry with the given name
deleteEntry :: String -> [SEntry] -> [SEntry]
deleteEntry
  delname
  (curentry@(SEntry name comment phrase):entries)
  = if name == delname then
        entries
    else
        curentry:(deleteEntry delname entries)

------------
-- crypto

bsToString :: BS.ByteString -> String
bsToString bytestring = (map BSInternal.w2c $ BS.unpack bytestring)

-- constans
pbkdf2_rounds = 150000
pbkdf2_length = 64
salt_length = 16
verifier_length = 17

getHash :: String -> String -> String
getHash passphrase salt = sha512PBKDF2 passphrase salt pbkdf2_rounds pbkdf2_length

getDRBG :: String -> HashDRBG
getDRBG seed = throwLeft (newGen (pack seed)) :: HashDRBG

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

decrypt :: String -> BS.ByteString -> Maybe String
decrypt passphrase fcontent =
  let (salt, encrypted) = BS.splitAt salt_length fcontent
      -- decrypt
      gen = getDRBG $ getHash passphrase (bsToString salt)
      (cipher, _) = throwLeft $ genBytes (BS.length encrypted) gen
      decrypted = BS.pack $ BS.zipWith xor encrypted cipher
      -- verify
      (verifier1, decrypted') = BS.splitAt verifier_length decrypted
      (verifier2, plaintext) = BS.splitAt verifier_length decrypted'
  in if verifier1 /= verifier2
      then Nothing
      else Just (map BSInternal.w2c $ BS.unpack plaintext)

openStorage :: String -> IO Storage
openStorage path = do
  putStr "(loading) Passphrase: "
  hSetEcho stdin False
  mpassphrase <- getPromptAns
  hSetEcho stdin True
  if mpassphrase == Nothing
      then exitSuccess
      else do putStrLn ""
              let Just passphrase = mpassphrase
              -- read and decrypt
              putStr "decrypting ..."
              hFlush stdout
              fdata <- BS.readFile path
              let decrypted = decrypt passphrase fdata
              clearLine
              setCursorColumn 0
              case decrypted of
                Nothing -> do
                    putStrLn "Authentication failed."
                    exitFailure
                Just plaintext -> do
                    putStrLn "Authentication complete."
                    let storage = read plaintext :: Storage
                        Storage entries _ _ = storage
                    -- forcing evaluation
                    putStrLn $ "Number of keys: "++(show $ length entries)
                    return storage

save :: String -> Storage -> IO ()
save path storage@(Storage { entries=_, lockhash=lockhash }) = do
  putStr "encrypting ..."
  hFlush stdout
  let encrypted = encrypt storage
  BS.writeFile path encrypted
  clearLine
  setCursorColumn 0
  putStrLn "saved."

changeLock path storage = do
  putStrLn "Changing master passphrase"
  putStr "    New passphrase: "
  hSetEcho stdin False
  mpassphrase <- getPromptAns
  hSetEcho stdin True
  case mpassphrase of
    Nothing -> return Nothing
    Just passphrase -> do
      putStr "\n Repeat passphrase: "
      hSetEcho stdin False
      mpassphrase' <- getPromptAns
      hSetEcho stdin True
      case mpassphrase' of
        Nothing -> return Nothing
        Just passphrase' -> do
          putStrLn ""
          if passphrase /= passphrase'
              then do putStrLn "ERROR: given passphrases do not match"
                      return Nothing
              else do storage' <- setPassphrase storage passphrase
                      putStrLn "New hash saved."
                      save path storage'
                      return (Just storage')

-----------

data PromptInfo = PromptList [SEntry] | PromptName SEntry | NoPromptInfo

mainprompt path storage promptinfo = do
  putStrLn ""
  case promptinfo of
    NoPromptInfo -> putStr "> "
    PromptList l -> putStr "(list)> "
    PromptName (SEntry { name=name }) -> putStr $ name++" > "
  minputstr <- getPromptAns
  case minputstr of
    Nothing -> do putStrLn "Try \"quit\""
                  mainprompt path storage promptinfo
    Just inputstr -> do let input = words inputstr
                        (storage', promptinfo) <- prompthandle path storage promptinfo input
                        mainprompt path storage' promptinfo

prompthandle :: String -> Storage -> PromptInfo -> [String] -> IO (Storage, PromptInfo)
-- empty line
prompthandle path storage@(Storage entries oldlockhash salt) pinf [] = do
  clearScreen
  putStrLn $ "Datafile: " ++ path
  putStrLn $ "Keys: " ++ (show $ length entries)
  putStrLn "For available commands try \"help\""
  return (storage, pinf)
-- help
prompthandle _ storage pinf ("help":[]) = do
  putStrLn "== Available Commands:"
  putStrLn "quit         Exit programm"
  putStrLn "save         Save to file"
  putStrLn "change-lock  Choose new master passphrase"
  putStrLn "list [RE]    Search for name"
  putStrLn "[NUM]        Select a name from previous list"
  putStrLn "new [NAME]   New name-phrase pair"
  putStrLn "\n== With selected pair:"
  putStrLn "rename [NAME] Set another name"
  putStrLn "plain         Shows plaintext passphrase"
  putStrLn "change        Change passphrase of this pair"
  putStrLn "delete        Deletes the selected pair immediately"
  putStrLn "\n== Comment"
  putStrLn "Use ENTER to clear the screen immediately."
  putStrLn "ALL changes are save instantly to the data file when\none action is successful."
  return (storage, pinf)
-- save
prompthandle path storage pinf ("save":[]) = do
  save path storage
  return (storage, pinf)
-- change master passphrase
prompthandle path storage@(Storage entries oldlockhash salt) pinf ("change-lock":[]) = do
  res <- changeLock path storage
  case res of
    Nothing -> return (storage, pinf)
    Just storage' -> return (storage', pinf)
-- save and exit
prompthandle path storage _ ("quit":[]) = do
  --save path storage -- not neccessary since we save on every change of data already.
  exitSuccess

-- new
prompthandle path storage@(Storage entries lockhash salt) pinf ("new":name:[]) = do
  putStrLn $ "New entry: "++name
  putStr $ "  Comment: "
  mcomment <- getPromptAns
  let comment = case mcomment of
                  Nothing -> ""
                  Just str -> str
  putStr $ " Passphrase: "
  hSetEcho stdin False
  mpassphrase <- getPromptAns
  hSetEcho stdin True
  case mpassphrase of
    Nothing -> do
        putStrLn "Not saved."
        return (storage, pinf)
    Just passphrase -> do
        putStrLn ""
        let newentry = (SEntry name comment passphrase)
            entries' = newEntry newentry entries
            storage' = Storage entries' lockhash salt
        save path storage'
        return (storage', PromptName newentry)

-- list
prompthandle _ storage@(Storage {entries=entries}) _ ("list":[]) = do
  let list = listEntries ".*" entries
  putStr $ unlines $ showEntries 1 list
  return (storage, PromptList list)
prompthandle _ storage@(Storage entries lockhash salt) pinf ("list":regex:[]) = do
  let list = listEntries regex entries
  if null list then do
      putStrLn "no matches"
      return (storage, NoPromptInfo)
  else do
      putStr $ unlines $ showEntries 1 list
      return (storage, PromptList list)

-- plain
prompthandle _ storage pinf@(PromptName (SEntry name comment phrase)) ("plain":[]) = do
  putStrLn "=========="
  putStrLn $ "  "++name
  putStrLn $ "  "++comment
  putStrLn $ "  "++phrase
  putStrLn "=========="
  return (storage, pinf)

-- change
prompthandle
  path
  storage@(Storage entries lockhash salt)
  pinf@(PromptName (SEntry name comment phrase))
  ("change":[])
  = do putStr $ " New passphrase: "
       hSetEcho stdin False
       mpassphrase <- getPromptAns
       hSetEcho stdin True
       case mpassphrase of
         Nothing -> do putStrLn "Aborted."
                       return (storage, pinf)
         Just newphrase -> do
             putStrLn ""
             let entries' = changePassphrase name newphrase entries
                 storage' = (Storage entries' lockhash salt)
             save path storage'
             return (storage', PromptName (SEntry name comment newphrase))

-- rename
prompthandle _ storage pinf ("rename":[]) = do
  putStrLn "Say `rename NEWNAME'"
  return (storage, pinf)
prompthandle
  path
  storage@(Storage entries lockhash salt)
  pinf@(PromptName (SEntry name comment phrase))
  ("rename":newname:[])
  = do let entries' = changeName name newname entries
           storage' = (Storage entries' lockhash salt)
       save path storage'
       return (storage', PromptName (SEntry newname comment phrase))

-- delete
prompthandle
  path
  storage@(Storage entries lockhash salt)
  pinf@(PromptName (SEntry name comment phrase))
  ("delete":[])
  = do let entries' = deleteEntry name entries
           storage' = (Storage entries' lockhash salt)
       save path storage'
       let list = listEntries ".*" entries'
       putStr $ unlines $ showEntries 1 list
       return (storage', (PromptList list))

-- unknown input maybe select item from list
prompthandle path storage pinf (other:[]) =
  if other =~ "^[0-9]+$" then do
      let idx = (read other :: Int) -1
      case pinf of
        PromptList entries -> if idx >= (length entries) || idx < 0 then do
                                  putStrLn "Index out of range."
                                  return (storage, pinf)
                              else
                                  return (storage, PromptName (entries !! idx))
        _ -> do putStrLn "No list showed. You can not select :-("
                return (storage, pinf)
  else do
      putStrLn $ "unknown command: "++other
      return (storage, pinf)
prompthandle path storage pinf other = do
  putStrLn $ "unknown command: "++(unwords other)
  return (storage, pinf)

