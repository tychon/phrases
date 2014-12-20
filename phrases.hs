
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
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString as BS

import CryptoBackend
import BasicUI
import EmbeddedContent

data PromptInfo = PromptList [SEntry] | PromptName SEntry | NoPromptInfo
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

--TODO other commands

parseargs _ = do
  putStrLn "No valid command given. Try 'help'."
  exitFailure

listEntries :: [SEntry] -> IO ()
listEntries [] = putStrLn ""
listEntries (entry:entries) = do
  case entry of
    Phrase name comment _ -> putStrLn $ "phrase " ++ name
    Asym name comment _ _ _ -> putStrLn $ "asym   " ++ name
  listEntries entries

prompt p@(Prompt path info storage) = do
  case info of
    NoPromptInfo -> putStr "\n> "
    PromptList _ -> putStr "\nSELECT > "
    PromptName entry -> putStr $ "\n" ++ (name entry) ++ " > "
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
  exitSuccess

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
  listEntries newlist
  return p { info=PromptList newlist }

--prompthandle p@(Prompt _ _ storage) ("list":regex:[]) = do
--

prompthandle p@(Prompt path _ storage) ("new":typename:[])
  | typename `elem` ["phrase", "asym", "field", "data"] = do
      putStr "Name: "
      name <- getPromptAns
      case name of
        Left e -> do
          invalidinput e ""
          return p
        Right name -> do
          if doesNameExist name (entries storage)
            then do
              putStrLn "Name already assigned."
              return p
            else do
              putStr "Comment: "
              com <- getPromptAns
              case com of
                Left e -> do
                  invalidinput e ""
                  return p
                Right com -> do
                  maybenewentry <- case typename of
                    "phrase" -> return $ newPhraseEntry name com
                    "asym" -> return $ newAsymEntry name com
                    _ -> error "Previously unknown type occured ???"
                  case maybenewentry of
                    Nothing -> return p
                    Just newentry -> do
                      let newentrylist = addEntry newentry (entries storage)
                          newstorage = storage { entries=newentrylist }
                      save path newstorage
                      putStrLn "New entry saved."
                      return p { info=PromptName newentry, storage=newstorage }
  | otherwise = do
      putStrLn "Unknown type."
      return p

--TODO other commands

prompthandle p _ = do
  clearScreen
  putStrLn "Unknown command."
  putStrLn "Type 'help' for help, or 'quit' to exit program."
  return p

