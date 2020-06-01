project(ext_session)

HHVM_EXTENSION(ext_session ext_session.cpp ext_session.h)
HHVM_SYSTEMLIB(ext_session ext_session.php)