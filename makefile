.PHONY: main test clear

main: embedded-helptext embedded-ghcversion embedded-prompthelp
	ghc -XTemplateHaskell -XRecordWildCards phrases -o phrases

embedded-helptext: README.md
	cat README.md | awk '/END_HELPTEXT/{p=0;exit}p;/BEGIN_HELPTEXT/{p=1}' > embedded-helptext

embedded-prompthelp: README.md
	cat README.md | awk '/END_PROMPTHELP/{p=0;exit}p;/BEGIN_PROMPTHELP/{p=1}' > embedded-prompthelp

embedded-ghcversion:
	ghc --numeric-version > embedded-ghcversion

test:
	ghc -XRecordWildCards test -o test
	./test

clear:
	rm -f *.hi *.o embedded-* phrases test

