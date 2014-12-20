
module EmbedStr (embedStr) where

import Language.Haskell.TH
import Language.Haskell.TH.Syntax (lift)

embedStr :: IO String -> ExpQ
embedStr readStr = lift =<< runIO readStr

embedFile :: String -> ExpQ
embedFile path = embedStr readStr
  where readStr = readFile path

embedFile' :: String -> ExpQ
embedFile' path = lift =<< runIO readStr
  where readStr = readFile path

