all: embedded-helptext embedded-ghcversion
	ghc -XTemplateHaskell -XRecordWildCards phrases -o phrases

embedded-helptext: README
	cat README | awk '/END_HELPTEXT/{p=0;exit}p;/BEGIN_HELPTEXT/{p=1}' > embedded-helptext

embedded-ghcversion: embedded-ghcversion
	ghc --numeric-version > embedded-ghcversion

clear:
	rm -f *.hi *.o embedded-ghcversion embedded-helptext phrases

