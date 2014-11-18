all:
	ghc --numeric-version > embedded-ghcversion
	ghc -XTemplateHaskell -XRecordWildCards --make phrases -o phrases

clear:
	rm -f *.hi *.o embedded-ghcversion phrases

