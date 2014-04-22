
module Main( main ) where

import System.Environment
import Control.Monad( when )
import Control.Exception( try )
import System.IO
import System.Exit
import System.IO.Error( isEOFError )
import System.Console.GetOpt
import Data.ByteString.Char8( pack )
import qualified Data.ByteString as BS
import Data.Bits

import Crypto.PBKDF( sha512PBKDF2 )
import Crypto.Random.DRBG

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
                -- TODO ask, decrypt and load data file
                
                openStorage ".passphrases"
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

openStorage file = do
  -- ask
  putStr "Passphrase: "
  hSetEcho stdin False
  passphrase <- getPromptAns
  hSetEcho stdin True
  putStrLn ""
  -- decrypt
  let seed = pack $ sha512PBKDF2 passphrase "salt" 1000 64
  case newGen seed :: Either GenError HashDRBG of
    Left e -> error $ show e
    Right gen -> do encrypteddata <- BS.readFile file
                    let datalen = BS.length encrypteddata
                        (cipher, gen') = throwLeft $ genBytes datalen gen
                        decrypted = BS.pack $ BS.zipWith xor encrypteddata cipher
                    putStrLn $ show decrypted -- TODO parse decrypted file

mainprompt = do
  putStr "> "
  input <- getPromptAns
  putStrLn $ show input
  mainprompt

