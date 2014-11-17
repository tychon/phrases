
module Main (main) where

import Control.Exception ( AsyncException(UserInterrupt), throwTo )
import Control.Concurrent ( myThreadId )
import System.Posix.Signals ( Handler(Catch), keyboardSignal, installHandler )
import System.IO

import BasicUI

main = do
  putStrLn "This is your passphrase storage manager."
  tid <- myThreadId
  installHandler keyboardSignal (Catch (throwTo tid UserInterrupt)) Nothing
  newStorage

