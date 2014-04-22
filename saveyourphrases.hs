
module Main( main ) where

import System.Environment
import Control.Monad( when )
import Control.Exception( try )
import System.IO
import System.Exit
import System.IO.Error( isEOFError )
import System.Console.GetOpt

main = do putStrLn "This is your passphrase storage manager."
          -- parse command line arguments
          args <- getArgs
          case getOpt RequireOrder options args of
            (flags, [], []) -> do
                -- show version and exit
                when (elem Version flags) $ do
                    putStrLn "Version [unimplemented]\n" -- Unimplemented
                    putStrLn $ usageInfo header options
                    exitSuccess
                -- TODO ask, decrypt and load data file
                -- prompt
                mainprompt
            (_, nonOpts, []) -> error $ "unrecognized arguments: " ++ unwords nonOpts
            (_, _, msgs) -> error $ concat msgs ++ usageInfo header options

-- command line args

data Flag = Version | Input String deriving (Show, Eq)

options = [
    Option ['V'] ["version"] (NoArg Version) "show version number",
    Option ['i'] ["input"] (ReqArg Input "FILE") "the data file"
  ]

header = "Usage: main [OPTION...]"

-----------

getPromptAns :: IO (String)
getPromptAns = do hFlush stdout
                  input <- try getLine
                  case input of
                    Left e -> if isEOFError e
                                  then do putStrLn "[EOT]"
                                          exitSuccess
                                  else error ("IOError: "++(show e))
                    Right inp -> return inp

--openStorage file = do
 -- putStr "Passphrase: "
--  hFlush stdout
--  input <- try (getLine)

mainprompt = do
  putStr "> "
  hFlush stdout
  input <- getPromptAns
  putStrLn $ show input
  mainprompt

