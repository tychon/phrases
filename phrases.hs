
module Main (main) where

import System.Environment ( getArgs )
import System.Exit ( exitSuccess, exitFailure )
import System.IO ( putStr, putStrLn )
import System.Directory ( canonicalizePath, doesFileExist )
import System.Posix.Signals ( Handler(Catch), keyboardSignal, installHandler )
import Control.Exception ( AsyncException(UserInterrupt), throwTo )
import Control.Concurrent ( myThreadId )
import Data.Maybe ( fromJust )
import qualified Data.ByteString as BS

import EmbeddedContent ( ghcversion, helptext )
import CryptoBackend ( currentversion )
import BasicUI ( newStorage, open, save, printStorageStats )
import Migrate ( migrate )
import Prompt ( prompt )

main = do
  putStrLn "This is your passphrase storage manager."
  -- set up signal handler for user interrupt Ctrl-C
  tid <- myThreadId
  installHandler keyboardSignal (Catch (throwTo tid UserInterrupt)) Nothing
  -- now parse commands
  args <- getArgs
  parseargs args

-- | Show help when no command is given.
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
      prompt pathname storage

parseargs ["migrate", srcpath, destpath] = do
  putStrLn $ "Migration: " ++ srcpath ++ " => " ++ destpath
  migrate srcpath destpath

parseargs ["dump", storagepath, plainpath] = do
  putStrLn $ "Opening container at " ++ storagepath
  existing <- doesFileExist storagepath
  if not existing
    then do
      putStrLn "Container file doesn't exist. Exit."
      exitFailure
    else do
      storage <- open storagepath
      putStrLn $ "Dumping into " ++ plainpath
      writeFile plainpath $ show storage
      putStrLn "Done."
      exitSuccess

parseargs _ = do
  putStrLn "No valid command given. Try 'help'."
  exitFailure
