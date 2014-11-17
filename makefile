all:
	ghc -XRecordWildCards --make phrases -o phrases

clear:
	rm -f *.hi *.o phrases

