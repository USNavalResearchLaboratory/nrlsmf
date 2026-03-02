default: elastic

elastic:
	make -C makefiles -f Makefile.linux elastic
	cp -u makefiles/nrlsmf .

install: elastic
	sudo cp -u ./nrlsmf /usr/bin/nrlsmf

clean:
	make -C makefiles -f Makefile.linux clean
	rm -f nrlsmf