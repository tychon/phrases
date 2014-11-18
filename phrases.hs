
module Main (main) where

import System.Environment ( getArgs )
import System.Exit ( exitSuccess, exitFailure )
import System.IO
import System.Posix.Signals ( Handler(Catch), keyboardSignal, installHandler )
import Control.Exception ( AsyncException(UserInterrupt), throwTo )
import Control.Concurrent ( myThreadId )

import CryptoBackend
import BasicUI
import EmbeddedContent

currentversion = 2

data Prompt = Prompt { path :: String, storage :: Storage }

main = do
  putStrLn "This is your passphrase storage manager."
  tid <- myThreadId
  installHandler keyboardSignal (Catch (throwTo tid UserInterrupt)) Nothing
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

parseargs _ = do
  putStrLn "No valid command given. Try 'help'."
  exitFailure

prompt (Prompt path storage) = do
  exitFailure
  

