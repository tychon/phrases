
module Main( main ) where

-- io / interaction
import System.Environment
import Control.Monad( when )
import Control.Exception( try )
import System.Exit
import System.IO
import System.IO.Error( isEOFError )
import System.Console.GetOpt
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
                    then do let storage = Storage { entries = [], lockhash = "" }
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

-----------

data Storage = Storage { entries :: [SEntry], lockhash :: String }
       deriving (Show, Read)
data SEntry = SEntry { domain, username, comment, phrase :: String }
       deriving (Show, Read)

getPromptAns :: IO (Maybe String)
getPromptAns = do hFlush stdout
                  input <- try getLine
                  case input of
                    Left e -> if isEOFError e
                                  then do putStrLn "[EOT]"
                                          return Nothing
                                  else error ("IOError: "++(show e))
                    Right inp -> return (Just inp)

-- | Hashes your passphrase with PBKDF2 and generates
--   deterministric randomness from it.
getCipherAndHash ::
     String -- the passphrase as string
  -> ByteLength -- the length of the cipher to create
  -> (String, BS.ByteString, HashDRBG)
getCipherAndHash passphrase len = do
  let lockhash = sha512PBKDF2 passphrase "salt" 150000 64
      (cipher, gen) = getCipher lockhash len
  (lockhash, cipher, gen)

getCipher ::
     String -- the PBKDF2 hash of your passphrase
  -> ByteLength -- the length of the cipher to create
  -> (BS.ByteString, HashDRBG) -- the randomness and the generator
getCipher lockhash len = do
  let seed = pack $ lockhash
  case newGen seed :: Either GenError HashDRBG of
    Left e -> error $ show e
    Right gen -> do let (cipher, gen') = throwLeft $ genBytes len gen
                    (cipher, gen')

openStorage :: String -> IO Storage
openStorage file = do
  -- ask
  putStr "(loading) Passphrase: "
  hSetEcho stdin False
  mpassphrase <- getPromptAns
  hSetEcho stdin True
  if mpassphrase == Nothing
      then exitSuccess
      else return ()
  putStrLn ""
  let Just passphrase = mpassphrase
  -- open file
  encrypteddata <- BS.readFile file
  -- decrypt
  let (lockhash, cipherbytes, _) = getCipherAndHash passphrase $ BS.length encrypteddata
      decrypted = BS.pack $ BS.zipWith xor encrypteddata cipherbytes
      -- verify
      (verifier1, decrypted') = BS.splitAt 64 decrypted
      (verifier2, plaintext) = BS.splitAt 64 decrypted'
  if verifier1 /= verifier2
      then do putStrLn "Authentication failed."
              exitFailure
      else do putStrLn "Authentication complete."
              let storage = read (map BSInternal.w2c $ BS.unpack plaintext) :: Storage -- read
                  Storage entries _ = storage
              putStrLn $ "Number of keys: "++(show $ length entries) -- forcing evaluation
              return (Storage entries lockhash)

save :: String -> Storage -> IO ()
save path storage@(Storage { entries=_, lockhash=lockhash }) = do
  -- encrypt
  let plaintext = show storage
      (cipherbytes, gen) = getCipher lockhash $ (length plaintext) + 128
      (verifier, _) = throwLeft $ genBytes 64 gen -- get verifier
      fulltext = BS.append verifier $ BS.append verifier $ pack plaintext
      encrypted = BS.pack $ BS.zipWith xor fulltext cipherbytes
  BS.writeFile path encrypted

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

prompthandle path storage@(Storage entries _) ("change-lock":[]) = do
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
              else do let (newlockhash, _, _) = getCipherAndHash passphrase 0
                      putStrLn "New hash saved."
                      return (Storage entries newlockhash)

prompthandle path storage ("quit":[]) = do
  quit path storage
prompthandle path storage other = do
  putStrLn $ "unknown command: "++(unwords other)
  return storage

-----------

quit path storage = do
  save path storage
  exitSuccess

