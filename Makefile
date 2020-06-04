.PHONY: hhvm

hhvm:
	${hphpizepatch}hphpize && cmake . && make && cp ext_session.so /etc/hhvm/ext_session.so && service hhvm restart && hhvm tests/001.php