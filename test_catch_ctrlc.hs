
-- http://stackoverflow.com/questions/2349233/catching-control-c-exception-in-ghc-haskell

import Control.Exception as E
import Control.Concurrent
import System.Posix.Signals
import System.IO

main :: IO ()
main = do
  tid <- myThreadId
  installHandler keyboardSignal (Catch (throwTo tid UserInterrupt)) Nothing
  --hSetBuffering stdout NoBuffering
  --hSetBuffering stdin NoBuffering
  repLoop

repLoop :: IO ()
repLoop
  = do putStr "> "
       line <- interruptible "<interrupted>" getLine
       if line == "exit"
          then putStrLn "goodbye"
          else do putStrLn $ "input was: " ++ line
                  repLoop

interruptible :: a -> IO a -> IO a
interruptible a m
  = E.handleJust f return m
  where
    f UserInterrupt
      = Just a
    f _
      = Nothing

