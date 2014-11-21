
module Main (main) where

import System.Environment ( getArgs )
import System.Exit ( exitSuccess, exitFailure )
import System.IO ( putStr, putStrLn )
import System.Directory ( canonicalizePath, doesFileExist )
import System.Posix.Signals ( Handler(Catch), keyboardSignal, installHandler )
import Control.Exception ( AsyncException(UserInterrupt), throwTo )
import Control.Concurrent ( myThreadId )
import qualified Data.ByteString as BS

import CryptoBackend
import BasicUI
import EmbeddedContent

data Prompt = Prompt { path :: String, storage :: Storage }

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
      prompt (Prompt pathname storage)

parseargs _ = do
  putStrLn "No valid command given. Try 'help'."
  exitFailure

prompt p@(Prompt path storage) = do
  putStr "> "
  ans <- getPromptAns
  case ans of
    Left e -> do
      putStrLn $ "Invalid input: " ++ (show e)
      prompt p
    Right cmd -> do
      storage' <- prompthandle p (words cmd)
      prompt p{storage=storage'}
  exitFailure

prompthandle :: Prompt -> [String] -> IO Storage
prompthandle p [] = return (storage p)

