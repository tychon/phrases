
module EmbeddedContent ( helptext, ghcversion ) where

import Language.Haskell.TH
import Language.Haskell.TH.Syntax (lift)

-- | Template Haskell function running the readFile operation while compiling.
-- Takes a path and returns an Expression to be evaluated.
embedFile :: String -> ExpQ
embedFile path = lift =<< runIO readStr
  where readStr = readFile path

-- | Returns an expression evaluating to the helptext string.
helptext :: ExpQ
helptext = embedFile "embedded-helptext"

-- | Returns an expression evaluating to the ghc --numeric-version.
-- The file "embedded-ghcversion" is created by the makefile target all.
ghcversion :: ExpQ
ghcversion = embedFile "embedded-ghcversion"

