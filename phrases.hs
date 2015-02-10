
module Main (main) where

import System.Environment ( getArgs )
import System.Exit ( exitSuccess, exitFailure )
import System.IO ( putStr, putStrLn )
import System.Console.ANSI( clearLine, setCursorColumn, clearScreen )
import System.Directory ( canonicalizePath, doesFileExist )
import System.Posix.Signals ( Handler(Catch), keyboardSignal, installHandler )
import Control.Exception ( AsyncException(UserInterrupt), throwTo )
import Control.Concurrent ( myThreadId )
import Data.Maybe ( fromJust )
import Data.Char ( isPrint )
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Text.Regex.TDFA
import System.Hclip

import CryptoBackend
import BasicUI
import EmbeddedContent

data PromptInfo = PromptList [SEntry] | PromptEntry SEntry | NoPromptInfo
data Prompt = Prompt { path :: String, info :: PromptInfo, storage :: Storage }

main = do
  putStrLn "This is your passphrase storage manager."
  -- set up signal handler for user interrupt Ctrl-C
  tid <- myThreadId
  installHandler keyboardSignal (Catch (throwTo tid UserInterrupt)) Nothing
  -- now parse commands
  args <- getArgs
  parseargs args

parseargs :: [String] -> IO ()
parseargs [] = parseargs ["help"]

-- | Print help text and exit
parseargs ["help"] = do
  putStr $(helptext)

-- | Print version info and exit.
parseargs ["version"] = do
  putStrLn $ "Version: " ++ (show currentversion)
  putStrLn $ "GHC version: " ++ $(ghcversion)

parseargs ["init", pathname] = do
  putStrLn $ "Creating new container at " ++ pathname
  existing <- doesFileExist pathname
  if existing
    then do
      putStrLn "File exists already. Exit."
      exitFailure
    else do
      BS.writeFile pathname BS.empty
      putStrLn $ "File successfully created."
      storage <- newStorage
      save pathname storage
      putStrLn $ "Empty storage created."
      exitSuccess

-- | Open container and enter prompt loop on 'open' command
parseargs ["open", pathname] = do
  putStrLn $ "Opening container at " ++ pathname
  existing <- doesFileExist pathname
  if not existing
    then do
      putStrLn "File doesn't exist. Exit."
      exitFailure
    else do
      storage <- open pathname
      printStorageStats storage
      putStrLn "Type 'help' for a list of available commands."
      putStrLn "Enter empty line to clear screen."
      prompt (Prompt pathname NoPromptInfo storage)

--TODO implement migrate command

parseargs ["dump", storagepath, plainpath] = do
  putStrLn $ "Opening container at " ++ storagepath
  existing <- doesFileExist storagepath
  if not existing
    then do
      putStrLn "Container file doesn't exist. Exit."
      exitFailure
    else do
      storage <- open storagepath
      let storage' = storage{ lockhash=Nothing }
      --printStorageStats storage
      putStrLn $ "Dumping into " ++ plainpath
      writeFile plainpath $ show storage'
      putStrLn "Done."
      exitSuccess

parseargs _ = do
  putStrLn "No valid command given. Try 'help'."
  exitFailure

--------------------------------------------------------------------------------
-- Prompt commands

-- | Helper function printing a list of entries
listEntries :: [SEntry] -> IO ()
listEntries entries = listEntries' 1 entries
listEntries' :: Int -> [SEntry] -> IO ()
listEntries' _ [] = putStrLn ""
listEntries' line (entry:entries) = do
  case entry of
    Phrase name comment _ -> putStrLn $   (show line) ++ "\tphrase " ++ name
    Asym name comment _ _ _ -> putStrLn $ (show line) ++ "\tasym   " ++ name
  listEntries' (line+1) entries

-- | The prompt loop. Exits through exitSuccess in lower functions.
prompt p@(Prompt path info storage) = do
  case info of
    NoPromptInfo -> putStr "\n> "
    PromptList _ -> putStr "\nSELECT > "
    PromptEntry entry -> putStr $ "\n" ++ (name entry) ++ " > "
  ans <- getPromptAns
  case ans of
    Left e -> do
      invalidinput e ""
      prompt p
    Right cmd -> do
      p' <- prompthandle p (words cmd)
      prompt p'
  exitFailure

prompthandle :: Prompt -> [String] -> IO Prompt
prompthandle p [] = do
  clearScreen
  return p

prompthandle p ["quit"] = do
  clearScreen
  putStrLn "Exit."
  exitSuccess

prompthandle p ["exit"] = do
  clearScreen
  putStrLn "Exit."
  exitSuccess -- just kidding in the README :-P

prompthandle p ["help"] = do
  putStr $(prompthelptext)
  return p

prompthandle p@(Prompt path _ storage) ["stats"] = do
  putStrLn $ "Path: " ++ path
  printStorageStats storage
  return p

prompthandle p@(Prompt path _ storage) ["save"] = do
  save path storage
  return p

prompthandle p@(Prompt path _ storage) ["change-lock"] = do
  putStrLn "Think of a new passphrase:"
  maybepassphrase <- getPassphrase
  case maybepassphrase of
    Left e -> do
      invalidinput e "Passphrase not changed."
      return p
    Right passphrase -> do
      let newstorage = changelock passphrase storage
      save path newstorage
      putStrLn "Passphrase changed."
      return p { storage=newstorage }

prompthandle p@(Prompt path _ storage) ["resalt"] = do
  putStrLn "Remember your passphrase or choose a new one:"
  maybepassphrase <- getPassphrase
  case maybepassphrase of
    Left e -> do
      invalidinput e "Passphrase and salt not changed."
      return p
    Right passphrase -> do
      newstorage <- resalt passphrase storage
      save path newstorage
      putStrLn "Salt changed, passphrase set."
      return p { storage=newstorage }

prompthandle p@(Prompt path _ storage) ["test"] = do
  putStrLn "Remember your passphrase:"
  maybepassphrase <- getPassphrase
  case maybepassphrase of
    Left e -> do
      invalidinput e ""
    Right passphrase -> do
      let testlockhash = getPBK (fromJust $ props storage) (BS8.pack passphrase)
          Just currentlockhash = lockhash storage
      if testlockhash == currentlockhash
        then do
          putStrLn "Passphrases match. Congratulations, you remembered!"
        else do
          putStrLn "Passphrases don't match. Maybe try again :-/"
  return p

prompthandle p@(Prompt _ _ storage) ["list"] = do
  let newlist = entries storage
  case length newlist of
    0 -> do
      putStrLn "Empty storage."
      return p{ info=NoPromptInfo }
    1 -> do
      putStrLn "Storage contains only one entry."
      return p{ info=PromptEntry (newlist !! 0) }
    _ -> do
      listEntries newlist
      return p { info=PromptList newlist }

prompthandle p@(Prompt _ _ storage) ("list":regex:[]) = do
  -- TODO catch errors on malformed regexes or
  -- move to other regex library because TDFA doesn't use exceptions
  let newlist = filterEntries regex (entries storage)
  case length newlist of
    0 -> do
      putStrLn "No matching entries found."
      return p{ info=NoPromptInfo }
    1 -> do
      putStrLn "One match selected."
      return p{ info=PromptEntry (newlist !! 0) }
    _ -> do
      listEntries newlist
      return p { info=PromptList newlist }

-- You find the select function in the last prompthandle pattern.

-- | The prompt command `new TYPE`
-- Asks user for name and comment for the new entry and then calls respective
-- BasicUI new... functions for different types.
prompthandle p@(Prompt path _ storage) ("new":typename:[])
  | typename `elem` ["phrase", "asym", "field", "data"] = do
      name <- getUniqueName (entries storage)
      case name of
        Nothing -> return p
        Just name -> do
          putStr "Comment: "
          com <- getPromptAns
          case com of
            Left e -> do
              invalidinput e ""
              return p
            Right com -> do
              maybenewentry <- case typename of
                "phrase" -> newPhraseEntry name com
                "asym" -> newAsymEntry name com
                _ -> error "Previously unknown type occured ???"
              case maybenewentry of
                Nothing -> return p
                Just newentry -> do
                  let newentrylist = addEntry newentry (entries storage)
                      newstorage = storage { entries=newentrylist }
                  save path newstorage
                  putStrLn "New entry saved."
                  return p { info=PromptEntry newentry, storage=newstorage }
  | otherwise = do
      putStrLn "Unknown type."
      return p

-- | Print some information about the currently selected entry.
prompthandle p@(Prompt _ (PromptEntry entry) _) ("plain":[]) = do
  putStrLn $ "Name: " ++ (name entry)
  putStrLn $ "Comment: " ++ (comment entry)
  case entry of
    Phrase _ _ phrase -> putStrLn $ "Phrase: " ++ phrase
    Asym _ _ fprint pub _ -> do
      putStrLn $ "Fingerprint: " ++ fprint
      putStrLn $ "Public key:  " ++ pub
      putStrLn ""
    Field _ _ field ->
      let asstring = BS8.unpack field
      in if all isPrint asstring
        then do
          putStrLn "Content:\n"
          putStrLn asstring
        else
          putStrLn "Can not show you content since it contains non-printable characters."
  putStrLn "Type newline/ENTER to clear screen."
  return p

prompthandle p@(Prompt path (PromptEntry entry) storage) ("rename":[]) = do
  newname <- getUniqueName (entries storage)
  case newname of
    Nothing -> return p
    Just newname -> do
      let list' = deleteEntry entry (entries storage)
          newentry = entry{ name=newname }
          newentries = addEntry newentry list'
          newstorage = storage{ entries=newentries }
      save path newstorage
      putStrLn $ "Renamed " ++ (name entry) ++ " to " ++ newname ++ "."
      return p{ info=PromptEntry newentry, storage=newstorage }

prompthandle p@(Prompt path (PromptEntry entry) storage) ("comment":[]) = do
  putStrLn $ "Old Comment: " ++ (comment entry)
  putStr "New comment: "
  ans <- getPromptAns
  case ans of
    Left e -> do
      invalidinput e "" >> return p
    Right com -> do
      let newentry = entry{ comment=com }
          newentries = replaceEntry newentry (entries storage)
          newstorage = storage{ entries=newentries }
      save path newstorage
      putStrLn "Comment changed."
      return p{ storage=newstorage }

prompthandle p ("clear":[]) = do
  setClipboard ""
  putStrLn "Clipboard cleared."
  return p

prompthandle p ("cb":[]) =
  prompthandle p ["clipboard"]
prompthandle p@(Prompt _ (PromptEntry (Phrase _ _ pw)) _) ("clipboard":[]) = do
  setClipboard pw
  putStrLn "Password put into clipboard."
  return p

prompthandle p@(Prompt _ (PromptEntry (Asym _ _ fprint _ _)) _) ("fprintcb":[]) = do
  setClipboard fprint
  putStrLn "Fingerprint put into clipboard."
  return p

prompthandle p@(Prompt _ (PromptEntry (Asym _ _ _ pub _)) _) ("pubcb":[]) = do
  setClipboard pub
  putStrLn "Public key put into clipboard."
  return p

prompthandle p@(Prompt _ (PromptEntry (Asym _ _ _ _ priv)) _) ("privcb":[]) = do
  setClipboard priv
  putStrLn "PRIVATE KEY PUT INTO CLIPBOARD!"
  return p

prompthandle p@(Prompt path (PromptEntry entry) storage) ("delete":[]) = do
  let oldname = (name entry)
      newlist = deleteEntry entry (entries storage)
      newstorage = storage{ entries=newlist }
  save path newstorage
  putStrLn $ "Deleted: " ++ oldname
  return p{ info=NoPromptInfo, storage=newstorage }

prompthandle p@(Prompt _ (PromptList entries) storage) (other:[]) = do
  if other =~ "^[0-9]+$"
    then do
      let idx = (read other :: Int) - 1
      if idx >= (length entries) || idx < 0
        then putStrLn "Index out of range." >> return p
        else do
          let entry = entries !! idx
          putStrLn $ "Name: " ++ (name entry)
          putStrLn $ "Comment: " ++ (comment entry)
          return p{ info=PromptEntry entry }
    else prompthandle p ["unknown command"]

prompthandle p _ = do
  clearScreen
  putStrLn "Unknown command."
  putStrLn "Type 'help' for help, or 'quit' to exit program."
  return p

