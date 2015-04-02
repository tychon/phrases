
module Prompt (prompt) where

import System.Exit ( exitSuccess, exitFailure )
import System.Console.ANSI( clearLine, setCursorColumn, clearScreen )
import Data.Char ( isDigit )
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Text.Regex.TDFA
import System.Hclip

import EmbeddedContent
import CryptoBackend
import BasicUI

data PromptInfo = PromptList [SEntry] | PromptEntry SEntry | NoPromptInfo
data Prompt = Prompt { path :: String, info :: PromptInfo, storage :: Storage }

-- | Helper function printing a list of entries
listEntries :: [SEntry] -> IO ()
listEntries entries = listEntries' 1 entries
listEntries' :: Int -> [SEntry] -> IO ()
listEntries' _ [] = putStrLn ""
listEntries' line (entry:entries) = do
  -- use terminal-size to get max width
  -- https://hackage.haskell.org/package/terminal-size-0.3.0/docs/System-Console-Terminal-Size.html
  -- one line: type (7), num (4), name (25), comment (80-36=44)
  let linestr = show line
      paddedline = (take (3 - length linestr) $ repeat ' ') ++ linestr
      name' = take 25 $ name entry
      paddedname = name' ++ (take (25 - length name') $ repeat ' ')
      com = take 44 $ comment entry
      whole = paddedline ++ " " ++ paddedname ++ com
  case entry of
    Phrase{} -> putStrLn $ "phrase " ++ whole
    Asym{}   -> putStrLn $ "asym   " ++ whole
    Field{}  -> putStrLn $ "field  " ++ whole
  listEntries' (line+1) entries


-- | Start prompt loop
prompt :: String -> Storage -> IO ()
prompt pathname storage = promptloop (Prompt pathname NoPromptInfo storage)

-- | The prompt loop. Exits through exitSuccess in lower functions.
promptloop :: Prompt -> IO ()
promptloop p@(Prompt path info storage) = do
  case info of
    NoPromptInfo -> putStr "\n> "
    PromptList _ -> putStr "\nSELECT > "
    PromptEntry entry -> putStr $ "\n" ++ (name entry) ++ " > "
  ans <- getPromptAns
  case ans of
    Left e -> do
      invalidinput e ""
      promptloop p
    Right cmd -> do
      p' <- prompthandle p (words cmd)
      promptloop p'
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
      putStrLn "\nAnd again: "
      maybeagain <- getPassphrase
      case maybeagain of
        Left e -> do
          invalidinput e "Passphrase not changed."
          return p
        Right again -> do
          if passphrase == again
            then do
              let newstorage = changelock passphrase storage
              save path newstorage
              putStrLn "Passphrase changed."
              return p { storage=newstorage }
            else do
              putStrLn "Phrases do not match."
              return p

prompthandle p@(Prompt _ _ storage) ["test"] = do
  rememberPassphrase storage
  return p

prompthandle p@(Prompt path _ storage) ["resalt"] = do
  passphrase <- rememberPassphrase storage
  case passphrase of
    Nothing -> return p
    Just passphrase -> do
      newstorage <- resalt passphrase storage
      save path newstorage
      putStrLn "Salt changed."
      return p { storage=newstorage }

prompthandle p@(Prompt path _ storage@(Storage (Just prop) _ _)) ["iterations"] = do
  passphrase <- rememberPassphrase storage
  case passphrase of
    Nothing -> return p
    Just passphrase -> do
      putStrLn $ "Current number of iterations: " ++ (show . pbkdf2_rounds $ prop)
      putStr "Enter the number of iterations for PBDKF2: "
      ans <- getPromptAns
      case ans of
        Left e -> invalidinput e "" >> return p
        Right ans ->
          if all isDigit ans
            then do
              let iterations = read ans :: Int
                  storage' = changePBKDF2Rounds iterations passphrase storage
              save path storage'
              putStrLn "Iterations set."
              return p{ storage=storage' }
            else do
              putStrLn "Not a number."
              return p


prompthandle p@(Prompt localpath _ storage) ["merge"] = do
  putStr "Path to file to merge: "
  remotepath <- getPromptAns
  case remotepath of
    Left e -> do
      invalidinput e ""
      return p
    Right remotepath -> do
      let Just lh = lockhash storage
      res <- openWithLockhashRepeat remotepath lh
      case res of
        Nothing -> return p
        Just storage -> do
          undefined

prompthandle p@(Prompt _ _ storage) ["export"] = do
  undefined


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
  -- TODO LATER catch errors on malformed regexes or move to other regex library
  -- because TDFA doesn't use exceptions
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
                "field" -> newFieldEntry name com
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
    Phrase _ _ phrase -> do
      putStrLn $ "Phrase: " ++ phrase
      putStrLn "Type newline/ENTER to clear screen."
    Asym _ _ fprint pub priv -> do
      putStrLn $ "Fingerprint: " ++ fprint
      putStrLn $ "Public key:\n" ++ pub
      putStrLn ""
      putStrLn $ "Private key: [" ++ (show $ length priv) ++ " characters]\
                 \ use 'putpriv' to display here."
    Field _ _ field ->
      if BS.null field
        then putStrLn "Empty."
        else
          if isFieldPrintable field
            then do
              putStrLn "Content:\n"
              putStrLn $ BS8.unpack field
            else
              putStrLn "Can not show you content since \
                        \it contains non-printable characters."
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
          newstorage = replaceEntry newentry storage
      save path newstorage
      putStrLn "Comment changed."
      return p{ info=(PromptEntry newentry), storage=newstorage }

prompthandle p ("clear":[]) = do
  setClipboard ""
  putStrLn "Clipboard cleared."
  return p

prompthandle p@(Prompt path (PromptEntry entry) storage) ("delete":[]) = do
  let oldname = (name entry)
      newlist = deleteEntry entry (entries storage)
      newstorage = storage{ entries=newlist }
  save path newstorage
  putStrLn $ "Deleted: " ++ oldname
  return p{ info=NoPromptInfo, storage=newstorage }


--------------------------------------------------------------------------------
-- type specific prompt commands

prompthandle p ("cb":[]) =
  prompthandle p ["clipboard"]
prompthandle p@(Prompt _ (PromptEntry (Phrase _ _ pw)) _) ("clipboard":[]) = do
  setClipboard pw
  putStrLn "Password put into clipboard."
  return p


prompthandle p@(Prompt path (PromptEntry asym) storage) ("fingerprint":[]) = do
  putStrLn $ "Old fingerprint is: " ++ (fingerprint asym)
  putStr "Enter new fingerprint: "
  ans <- getPromptAns
  case ans of
    Left e -> invalidinput e "" >> return p
    Right ans -> do
      let newentry = asym{ fingerprint=ans }
          newstorage = replaceEntry newentry storage
      save path newstorage
      putStrLn "Fingerprint changed."
      return p{ info=(PromptEntry newentry), storage=newstorage }

prompthandle p@(Prompt path (PromptEntry asym@Asym{}) storage) ("set":[]) = do
  !content <- loadStdin
  (newentry, newstorage) <- setAsymPub (Just content) asym storage
  save path newstorage
  return p{ info=(PromptEntry newentry), storage=newstorage }

prompthandle p@(Prompt path (PromptEntry asym@Asym{}) storage) ("set":lpath:[]) = do
  content <- loadASCII lpath
  (newentry, newstorage) <- setAsymPub content asym storage
  save path newstorage
  return p{ info=(PromptEntry newentry), storage=newstorage }


prompthandle p@(Prompt path (PromptEntry asym@(Asym _ _ _ pub _)) _) ("put":[]) = do
  putStrLn pub
  return p

prompthandle p@(Prompt path (PromptEntry asym@(Asym _ _ _ pub _)) _) ("put":ppath:[]) = do
  writeASCII ppath pub
  return p

prompthandle p@(Prompt path (PromptEntry asym@Asym{}) storage) ("setpriv":[]) = do
  !content <- loadStdin
  (newentry, newstorage) <- setAsymPriv (Just content) asym storage
  save path newstorage
  return p{ info=(PromptEntry newentry), storage=newstorage }

prompthandle p@(Prompt path (PromptEntry asym@Asym{}) storage) ("setpriv":lpath:[]) = do
  content <- loadASCII lpath
  (newentry, newstorage) <- setAsymPriv content asym storage
  save path newstorage
  return p{ info=(PromptEntry newentry), storage=newstorage }

prompthandle p@(Prompt path (PromptEntry asym@(Asym _ _ _ _ priv)) _) ("putpriv":[]) = do
  putStrLn priv
  return p

prompthandle p@(Prompt path (PromptEntry asym@(Asym _ _ _ _ priv)) _) ("putpriv":ppath:[]) = do
  writeASCII ppath priv
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


prompthandle p@(Prompt path (PromptEntry field@Field{}) storage) ("set":[]) = do
  !content <- loadStdin
  (newentry, newstorage) <- setField (Just $ BS8.pack content) field storage
  save path newstorage
  return p{ info=(PromptEntry newentry), storage=newstorage }

prompthandle p@(Prompt path (PromptEntry field@Field{}) storage) ("set":lpath:[]) = do
  content <- loadBytes lpath
  (newentry, newstorage) <- setField content field storage
  save path newstorage
  return p{ info=(PromptEntry newentry), storage=newstorage }

prompthandle p@(Prompt _ (PromptEntry (Field _ _ field)) _) ("put":[]) = do
  if isFieldPrintable field
    then (putStrLn $ BS8.unpack field) >> return p
    else putStrLn "Contains non-ASCII characters. Put to file!" >> return p

prompthandle p@(Prompt _ (PromptEntry (Field _ _ field)) _) ("put":wpath:[]) = do
  writeBytes wpath field
  return p


--------------------------------------------------------------------------------
-- The fallthrough prompt handlers

-- Select an entry from the list.
prompthandle p@(Prompt _ (PromptList entries) storage) (other:[]) =
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
    else do
      putStrLn "Not a number. Give a number from the list above."
      return p

prompthandle p _ = do
  clearScreen
  putStrLn "Unknown command."
  putStrLn "Type 'help' for help, or 'quit' to exit program."
  return p
