
module Main( main ) where

-- io / interaction
import System.Environment
import Control.Monad( when )
import Control.Exception( try )
import System.Exit
import System.IO
import System.IO.Error( isEOFError )
import System.Console.GetOpt
import System.Console.ANSI( clearLine, setCursorColumn )
-- general
import Data.ByteString.Char8( pack )
import qualified Data.ByteString.Internal as BSInternal (c2w, w2c)
import qualified Data.ByteString as BS

-- crypto
import Crypto.PBKDF( sha512PBKDF2 )
import Crypto.Random.DRBG
import Data.Bits( xor )

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
                -- ask for passphrase, decrypt and load data file
                let path = findInputPath flags
                putStrLn $ "Storage File: "++path
                if (InitStorage `elem` flags)
                    then do let storage = Storage { entries = [], lockhash = "", salt="" } -- TODO sane?
                            putStrLn "Initializing Storage."
                            mainprompt path storage
                    else do storage <- openStorage path
                            putStrLn "Loaded."
                            mainprompt path storage
            (_, nonOpts, []) -> error $ "unrecognized arguments: " ++ unwords nonOpts
            (_, _, msgs) -> error $ concat msgs ++ usageInfo header options

-- command line args

data Flag = Version | InitStorage | Input String deriving (Show, Eq)

options = [
    Option ['V'] ["version"] (NoArg Version) "show version number",
    Option ['n'] ["init"]    (NoArg InitStorage) "does not load content from input file",
    Option ['i'] ["input"]   (ReqArg Input "FILE") "the data file"
  ]

header = "Usage: main [OPTION...]"

findInputPath [] = "passphrases"
findInputPath (Input path:flags) = path
findInputPath (_:flags) = findInputPath flags

getPromptAns :: IO (Maybe String)
getPromptAns = do hFlush stdout
                  input <- try getLine
                  case input of
                    Left e -> if isEOFError e
                                  then do putStrLn "[EOT]"
                                          return Nothing
                                  else error ("IOError: "++(show e))
                    Right inp -> return (Just inp)

-----------
-- storage and its functions

data Storage = Storage { entries :: [SEntry], lockhash :: String, salt :: String }
       deriving (Show, Read)
data SEntry = SEntry { name, comment, phrase :: String }
       deriving (Show, Read)

-- set passphrase and salt

setPassphrase :: Storage -> String -> IO Storage
setPassphrase (Storage entries oldlockhash oldsalt) newpassphrase = do
  gen <- newGenIO :: IO HashDRBG
  let (newsaltbs, _) = throwLeft $ genBytes salt_length gen
      newsalt = bsToString newsaltbs
      lockhash = getHash newpassphrase newsalt
  return (Storage entries lockhash newsalt)

------------
-- crypto

bsToString :: BS.ByteString -> String
bsToString bytestring = (map BSInternal.w2c $ BS.unpack bytestring)

-- constans
pbkdf2_rounds = 150000
pbkdf2_length = 64
salt_length = 16
verifier_length = 17

getHash :: String -> String -> String
getHash passphrase salt = sha512PBKDF2 passphrase salt pbkdf2_rounds pbkdf2_length

getDRBG :: String -> HashDRBG
getDRBG seed = throwLeft (newGen (pack seed)) :: HashDRBG

encrypt :: Storage -> BS.ByteString
encrypt storage@(Storage { entries=_, lockhash=lockhash, salt=salt }) =
  let plaintext = show storage
      gen = getDRBG lockhash
      cipherlen = (length plaintext) + 2 * verifier_length
      (cipher, gen') = throwLeft $ genBytes cipherlen gen
      (verifier, _) = throwLeft $ genBytes verifier_length gen'
      -- put together full plaintext
      fullplaintext = BS.append verifier $ BS.append verifier $ pack plaintext
      encrypted = BS.pack $ BS.zipWith xor fullplaintext cipher
  in BS.append (pack salt) encrypted

decrypt :: String -> BS.ByteString -> Maybe String
decrypt passphrase fcontent =
  let (salt, encrypted) = BS.splitAt salt_length fcontent
      -- decrypt
      gen = getDRBG $ getHash passphrase (bsToString salt)
      (cipher, _) = throwLeft $ genBytes (BS.length encrypted) gen
      decrypted = BS.pack $ BS.zipWith xor encrypted cipher
      -- verify
      (verifier1, decrypted') = BS.splitAt verifier_length decrypted
      (verifier2, plaintext) = BS.splitAt verifier_length decrypted'
  in if verifier1 /= verifier2
      then Nothing
      else Just (map BSInternal.w2c $ BS.unpack plaintext)

openStorage :: String -> IO Storage
openStorage path = do
  putStr "(loading) Passphrase: "
  hSetEcho stdin False
  mpassphrase <- getPromptAns
  hSetEcho stdin True
  if mpassphrase == Nothing
      then exitSuccess
      else do putStrLn ""
              let Just passphrase = mpassphrase
              -- read and decrypt
              putStr "decrypting ..."
              hFlush stdout
              fdata <- BS.readFile path
              let decrypted = decrypt passphrase fdata
              clearLine
              setCursorColumn 0
              case decrypted of
                Nothing -> do
                    putStrLn "Authentication failed."
                    exitFailure
                Just plaintext -> do
                    putStrLn "Authentication complete."
                    let storage = read plaintext :: Storage
                        Storage entries _ _ = storage
                    -- forcing evaluation
                    putStrLn $ "Number of keys: "++(show $ length entries)
                    return storage

save :: String -> Storage -> IO ()
save path storage@(Storage { entries=_, lockhash=lockhash }) = do
  putStr "encrypting ..."
  hFlush stdout
  let encrypted = encrypt storage
  BS.writeFile path encrypted
  clearLine
  setCursorColumn 0
  putStrLn "saved."

-----------

mainprompt path storage = do
  putStr "> "
  minputstr <- getPromptAns
  case minputstr of
    Nothing -> do putStrLn "Try \"quit\""
                  mainprompt path storage
    Just inputstr -> do let input = words inputstr
                        storage' <- prompthandle path storage input
                        mainprompt path storage'

prompthandle :: String -> Storage -> [String] -> IO Storage
prompthandle path storage [] = return storage

prompthandle path storage@(Storage entries oldlockhash salt) ("change-lock":[]) = do
  putStr "   New passphrase: "
  hSetEcho stdin False
  mpassphrase <- getPromptAns
  hSetEcho stdin True
  case mpassphrase of
    Nothing -> return storage
    Just passphrase -> do
      putStr "\nRepeat passphrase: "
      hSetEcho stdin False
      mpassphrase' <- getPromptAns
      hSetEcho stdin True
      case mpassphrase' of
        Nothing -> return storage
        Just passphrase' -> do
          putStrLn ""
          if passphrase /= passphrase'
              then do putStrLn "ERROR: given passphrases do not match"
                      return storage
              else do storage' <- setPassphrase storage passphrase
                      putStrLn "New hash saved."
                      return storage'

prompthandle path storage ("quit":[]) = do
  quit path storage
prompthandle path storage other = do
  putStrLn $ "unknown command: "++(unwords other)
  return storage

-----------

quit path storage = do
  save path storage
  exitSuccess

