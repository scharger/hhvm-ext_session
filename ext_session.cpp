/*
   +----------------------------------------------------------------------+
   | HipHop for PHP                                                       |
   +----------------------------------------------------------------------+
   | Copyright (c) 2010-present Facebook, Inc. (http://www.facebook.com)  |
   | Copyright (c) 1997-2010 The PHP Group                                |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   
   Update by Artūras Kaukėnas
*/


#include "ext_session.h"

#include <string>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <vector>

#include <folly/String.h>
#include <folly/portability/Dirent.h>
#include <folly/portability/SysFile.h>
#include <folly/portability/SysTime.h>

#include "hphp/util/lock.h"
#include "hphp/util/logger.h"
#include "hphp/util/compatibility.h"

#include "hphp/runtime/base/array-iterator.h"
#include "hphp/runtime/base/builtin-functions.h"
#include "hphp/runtime/base/comparisons.h"
#include "hphp/runtime/base/datetime.h"
#include "hphp/runtime/base/file.h"
#include "hphp/runtime/base/ini-setting.h"
#include "hphp/runtime/base/object-data.h"
#include "hphp/runtime/base/php-globals.h"
#include "hphp/runtime/base/rds-local.h"
#include "hphp/runtime/base/string-buffer.h"
#include "hphp/runtime/base/tv-refcount.h"
#include "hphp/runtime/base/variable-serializer.h"
#include "hphp/runtime/base/variable-unserializer.h"
#include "hphp/runtime/base/zend-math.h"

#include "hphp/runtime/ext/extension-registry.h"
#include "hphp/runtime/ext/hash/ext_hash.h"
#include "hphp/runtime/ext/std/ext_std_function.h"
#include "hphp/runtime/ext/std/ext_std_misc.h"
#include "hphp/runtime/ext/std/ext_std_options.h"

#include "hphp/runtime/vm/jit/translator-inline.h"
#include "hphp/runtime/vm/interp-helpers.h"
#include "hphp/runtime/vm/method-lookup.h"

namespace HPHP {
	///////////////////////////////////////////////////////////////////////////////
	using std::string;

	static bool ini_set_save_handler();

	static bool ini_on_update_save_dir(const std::string& value);
	static bool mod_is_open();

	///////////////////////////////////////////////////////////////////////////////
	// global data

	struct SessionSerializer;
	struct Session {
		enum Status {
			Disabled,
			None,
			Active
		};

		std::string 		save_path;
		bool				reset_save_path{false};
		std::string 		save_handler_str;
		
		std::string 		crypto_cookie_time_user_key;
		std::string 		use_crypto_storage_user_key;
		std::string 		use_crypto_storage;
		std::string 		crypto_secret;
		std::string 		digest_algo;
		std::string 		cipher_algo;
		std::string 		cipher_keylen;
		std::string 		crypto_expire;
		std::string 		memcache_persistent;
		std::string 		memcache_host;
		std::string 		memcache_port;
		std::string 		session_name;
		std::string 		extern_referer_chk;
		std::string 		entropy_file;
		int64_t		 		entropy_length{0};
		std::string 		cache_limiter;
		int64_t		 		cookie_lifetime{0};
		std::string 		cookie_path;
		std::string 		cookie_domain;
		Status				session_status{None};
		bool				cookie_secure{false};
		bool				cookie_httponly{false};
		bool				mod_data{false};
		bool				mod_user_implemented{false};

		SessionModule* 		mod{nullptr};

		int64_t				gc_probability{0};
		int64_t				gc_divisor{0};
		int64_t				gc_maxlifetime{0};
		int64_t				cache_expire{0};

		Object 				ps_session_handler;
		SessionSerializer* 	serializer;

		bool 				invalid_session_id{false};
		bool 				auto_start{false};
		bool 				use_cookies{false};
		bool 				use_only_cookies{false};
		bool 				use_trans_sid{false}; // contains INI value of whether to use trans-sid
		bool 				apply_trans_sid{false}; // whether to enable trans-sid for current req
		bool 				send_cookie{false};
		bool 				define_sid{false};

		int64_t 			hash_bits_per_character{0};
	};

	const StaticString s_session_ext_name("ext_session");

	struct SessionRequestData final : Session {
		void init() {
			id.detach();
			session_status = Session::None;
			ps_session_handler.reset();
			save_path.clear();
			if (reset_save_path) IniSetting::ResetSystemDefault("session.save_path");
		}

		void destroy() {
			id.reset();
			session_status = Session::None;
			// Note: we should not destroy user save handler here
			// (if the session is restarted during request, the handler
			// should be alive), it's destroyed only in the request shutdown.
		}

		void requestShutdownImpl();

	public:
		String id;
	};

	RDS_LOCAL_NO_CHECK(SessionRequestData, s_session);

	void SessionRequestData::requestShutdownImpl() {
		if (mod_is_open()) {
			try {
				mod->close();
			} catch (...) {}
		}
		ps_session_handler.reset();
		id.reset();
	}

	std::vector<SessionModule*> SessionModule::RegisteredModules;

	/*
	 * Note that we cannot use the BASE64 alphabet here, because
	 * it contains "/" and "+": both are unacceptable for simple inclusion
	 * into URLs.
	 */
	static char hexconvtab[] =
		"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ,-";

	static void bin_to_readable(const String& in, StringBuffer &out, char nbits) {
		unsigned char *p = (unsigned char *)in.data();
		unsigned char *q = (unsigned char *)in.data() + in.size();
		unsigned short w = 0;
		int have = 0;
		int mask = (1 << nbits) - 1;

		while (true) {
			if (have < nbits) {
				if (p < q) {
					w |= *p++ << have;
					have += 8;
				} else {
					/* consumed everything? */
					if (have == 0) break;
					/* No? We need a final round */
					have = nbits;
				}
			}

			/* consume nbits */
			out.append(hexconvtab[w & mask]);
			w >>= nbits;
			have -= nbits;
		}
	}

	const StaticString
		s_REMOTE_ADDR("REMOTE_ADDR"),
		s__SERVER("_SERVER"),
		s__SESSION("_SESSION"),
		s__COOKIE("_COOKIE"),
		s__GET("_GET"),
		s__POST("_POST");

	String SessionModule::create_sid() {
		String remote_addr = php_global(s__SERVER)
			.toArray()[s_REMOTE_ADDR].toString();

		struct timeval tv;
		gettimeofday(&tv, nullptr);

		StringBuffer buf;
		buf.printf("%.15s%ld%ld%0.8F", remote_addr.data(),
							 tv.tv_sec, (long int)tv.tv_usec, math_combined_lcg() * 10);

		Variant context = HHVM_FN(hash_init)("md5");
		if (same(context, false)) {
			Logger::Error("Invalid session hash function: md5");
			return String();
		}
		if (!HHVM_FN(hash_update)(context.toResource(), buf.detach())) {
			Logger::Error("hash_update() failed");
			return String();
		}

		if (s_session->entropy_length > 0) {
			int fd = ::open(s_session->entropy_file.c_str(), O_RDONLY);
			if (fd >= 0) {
				unsigned char rbuf[2048];
				int n;
				int to_read = s_session->entropy_length;
				while (to_read > 0) {
					n = ::read(fd, rbuf, (to_read < (int)sizeof(rbuf) ?
																to_read : (int)sizeof(buf)));
					if (n <= 0) break;
					if (!HHVM_FN(hash_update)(context.toResource(),
														 String((const char *)rbuf, n, CopyString))) {
						Logger::Error("hash_update() failed");
						::close(fd);
						return String();
					}
					to_read -= n;
				}
				::close(fd);
			}
		}

		auto const hashed = HHVM_FN(hash_final)(
			context.toResource(), /* raw */ true
		).toString();

		if (s_session->hash_bits_per_character < 4 ||
				s_session->hash_bits_per_character > 6) {
			s_session->hash_bits_per_character = 4;
			raise_warning("The ini setting hash_bits_per_character is out of range "
										"(should be 4, 5, or 6) - using 4 for now");
		}

		StringBuffer readable;
		bin_to_readable(hashed, readable, s_session->hash_bits_per_character);
		return readable.detach();
	}

	///////////////////////////////////////////////////////////////////////////////
	// SystemlibSessionModule

	static StaticString s_SessionHandlerInterface("SessionHandlerInterface");

	static StaticString s_open("open");
	static StaticString s_close("close");
	static StaticString s_read("read");
	static StaticString s_write("write");
	static StaticString s_gc("gc");
	static StaticString s_destroy("destroy");

	LowPtr<Class> SystemlibSessionModule::s_SHIClass = nullptr;

	/**
	 * Relies on the fact that only one SessionModule will be active
	 * in a given thread at any one moment.
	 */
	IMPLEMENT_REQUEST_LOCAL(SystemlibSessionInstance, SystemlibSessionModule::s_obj);

	Func* SystemlibSessionModule::lookupFunc(Class *cls, StringData *fname) {
		Func *f = cls->lookupMethod(fname);
		if (!f) {
			raise_error("class %s must declare method %s()",
									m_classname, fname->data());
		}

		if (f->attrs() & AttrStatic) {
			raise_error("%s::%s() must not be declared static",
									m_classname, fname->data());
		}

		if (f->attrs() & (AttrPrivate|AttrProtected|AttrAbstract)) {
			raise_error("%s::%s() must be declared public",
									m_classname, fname->data());
		}

		return f;
	}

	void SystemlibSessionModule::lookupClass() {
		Class *cls;
		if (!(cls = Unit::loadClass(String(m_classname, CopyString).get()))) {
			raise_error("Unable to locate systemlib class '%s'", m_classname);
		}

		if (cls->attrs() & (AttrTrait|AttrInterface)) {
			raise_error("'%s' must be a real class, not an interface or trait",
				m_classname);
		}

		if (!s_SHIClass) {
			s_SHIClass = Unit::lookupClass(s_SessionHandlerInterface.get());
			if (!s_SHIClass) {
				raise_error("Unable to locate '%s' interface",
										s_SessionHandlerInterface.data());
			}
		}

		if (!cls->classof(s_SHIClass)) {
			raise_error("SystemLib session module '%s' must implement '%s'",
									m_classname,
									s_SessionHandlerInterface.data());
		}

		if (LookupResult::MethodFoundWithThis !=
				lookupCtorMethod(m_ctor, cls, arGetContextClass(vmfp()))) {
			raise_error("Unable to call %s's constructor", m_classname);
		}

		m_open 		= lookupFunc(cls, s_open.get());
		m_close 	= lookupFunc(cls, s_close.get());
		m_read		= lookupFunc(cls, s_read.get());
		m_write		= lookupFunc(cls, s_write.get());
		m_gc		= lookupFunc(cls, s_gc.get());
		m_destroy 	= lookupFunc(cls, s_destroy.get());
		m_cls 		= cls;
	}

	const Object& SystemlibSessionModule::getObject() {
		if (const auto& o = s_obj->getObject()) {
			return o;
		}

		VMRegAnchor _;
		if (!m_cls) {
			lookupClass();
		}
		callerDynamicConstructChecks(m_cls);
		s_obj->setObject(Object{m_cls});
		const auto& obj = s_obj->getObject();
		tvDecRefGen(
			g_context->invokeFuncFew(m_ctor, obj.get())
		);
		return obj;
	}

	bool SystemlibSessionModule::open(const char *save_path, const char *session_name) {
		const auto& obj = getObject();

		Variant savePath = String(save_path, CopyString);
		Variant sessionName = String(session_name, CopyString);
	
		TypedValue args[2] = { *savePath.toCell(), *sessionName.toCell() };
		auto ret = Variant::attach(g_context->invokeFuncFew(m_open, obj.get(), nullptr, 2, args));

		if (ret.isBoolean() && ret.toBoolean()) {
			s_session->mod_data = true;
			return true;
		}

		raise_warning("Failed calling %s::open()", m_classname);
		return false;
	}

	bool SystemlibSessionModule::close() {
		const auto& obj = s_obj->getObject();
		if (!obj) {
			// close() can be called twice in some circumstances
			s_session->mod_data = false;
			return true;
		}

		auto ret = Variant::attach(
			g_context->invokeFuncFew(m_close, obj.get())
		);
		s_obj->destroy();

		if (ret.isBoolean() && ret.toBoolean()) {
			return true;
		}

		raise_warning("Failed calling %s::close()", m_classname);
		return false;
	}

	bool SystemlibSessionModule::read(const char *key, String &value) {
		const auto& obj = getObject();

		Variant sessionKey = String(key, CopyString);
		auto ret = Variant::attach(g_context->invokeFuncFew(m_read, obj.get(),nullptr, 1, sessionKey.toCell()));

		if (ret.isString()) {
			value = ret.toString();
			return true;
		}

		raise_warning("Failed calling %s::read()", m_classname);
		return false;
	}

	bool SystemlibSessionModule::write(const char *key, const String& value) {
		const auto& obj = getObject();

		Variant sessionKey = String(key, CopyString);
		Variant sessionVal = value;
		TypedValue args[2] = { *sessionKey.toCell(), *sessionVal.toCell() };
		auto ret = Variant::attach(g_context->invokeFuncFew(m_write, obj.get(), nullptr, 2, args));

		if (ret.isBoolean() && ret.toBoolean()) {
			return true;
		}

		raise_warning("Failed calling %s::write()", m_classname);
		return false;
	}

	bool SystemlibSessionModule::destroy(const char *key) {
		const auto& obj = getObject();

		Variant sessionKey = String(key, CopyString);
		auto ret = Variant::attach(	g_context->invokeFuncFew(m_destroy, obj.get(), nullptr, 1, sessionKey.toCell()));

		if (ret.isBoolean() && ret.toBoolean()) {
			return true;
		}

		raise_warning("Failed calling %s::destroy()", m_classname);
		return false;
	}

	bool SystemlibSessionModule::gc(int maxlifetime, int *nrdels) {
		const auto& obj = getObject();

		Variant maxLifeTime = maxlifetime;
		auto ret = Variant::attach(g_context->invokeFuncFew(m_gc, obj.get(),nullptr, 1, maxLifeTime.toCell()));

		if (ret.isInteger()) {
			if (nrdels) {
				*nrdels = ret.toInt64();
			}
			return true;
		}

		raise_warning("Failed calling %s::gc()", m_classname);
		return false;
	}
	
	//////////////////////////////////////////////////////////////////////////////
	// FileSessionModule

	struct FileSessionData {
	  FileSessionData() : m_fd(-1), m_dirdepth(0), m_st_size(0), m_filemode(0600) {
	  }

	  bool open(const char* save_path, const char* session_name) {
		String tmpdir;
		if (*save_path == '\0') {
		  tmpdir = HHVM_FN(sys_get_temp_dir)();
		  save_path = tmpdir.data();
		}

		/* split up input parameter */
		const char *argv[3];
		int argc = 0;
		const char *last = save_path;
		const char *p = strchr(save_path, ';');
		while (p) {
		  argv[argc++] = last; last = ++p; p = strchr(p, ';');
		  if (argc > 1) break;
		}
		argv[argc++] = last;

		if (argc > 1) {
		  errno = 0;
		  m_dirdepth = (size_t) strtol(argv[0], nullptr, 10);
		  if (errno == ERANGE) {
			raise_warning("The first parameter in session.save_path is invalid");
			return false;
		  }
		}

		if (argc > 2) {
		  errno = 0;
		  m_filemode = strtol(argv[1], nullptr, 8);
		  if (errno == ERANGE || m_filemode < 0 || m_filemode > 07777) {
			raise_warning("The second parameter in session.save_path is invalid");
			return false;
		  }
		}

		save_path = argv[argc - 1];
		if (File::TranslatePath(save_path).empty()) {
		  raise_warning("Unable to open save_path %s", save_path);
		  return false;
		}

		m_fd = -1;
		m_basedir = save_path;
		s_session->mod_data = true;
		return true;
	  }

	  bool close() {
		closeImpl();
		m_lastkey.clear();
		m_basedir.clear();
		s_session->mod_data = false;
		return true;
	  }

	  bool read(const char *key, String &value) {
		openImpl(key);
		if (m_fd < 0) {
		  return false;
		}

		struct stat sbuf;
		if (fstat(m_fd, &sbuf)) {
		  return false;
		}
		m_st_size = sbuf.st_size;
		if (m_st_size == 0) {
		  value = "";
		  return true;
		}

		String s = String(m_st_size, ReserveString);
		char *val = s.mutableData();

		lseek(m_fd, 0, SEEK_SET);
		long n = ::read(m_fd, val, m_st_size);

		if (n != (int)m_st_size) {
		  if (n == -1) {
			raise_warning("read failed: %s (%d)", folly::errnoStr(errno).c_str(),
						  errno);
		  } else {
				raise_warning("read returned less bytes than requested");
		  }
		  return false;
		}

		value = s.setSize(m_st_size);
		return true;
	  }

	  bool write(const char *key, const String& value) {
		openImpl(key);
		if (m_fd < 0) {
		  return false;
		}

		struct stat sbuf;
		if (fstat(m_fd, &sbuf)) {
		  return false;
		}
		m_st_size = sbuf.st_size;

		/*
		 * truncate file, if the amount of new data is smaller than
		 * the existing data set.
		 */
		if (value.size() < (int)m_st_size) {
		  if (ftruncate(m_fd, 0) < 0) {
			raise_warning("truncate failed: %s (%d)",
						  folly::errnoStr(errno).c_str(), errno);
			return false;
		  }
		}

		lseek(m_fd, 0, SEEK_SET);
		long n = ::write(m_fd, value.data(), value.size());

		if (n != value.size()) {
		  if (n == -1) {
			raise_warning("write failed: %s (%d)",
						  folly::errnoStr(errno).c_str(), errno);
		  } else {
			raise_warning("write wrote less bytes than requested");
		  }
		  return false;
		}

		return true;
	  }

	  bool destroy(const char *key) {
		char buf[PATH_MAX];
		if (!createPath(buf, sizeof(buf), key)) {
		  return false;
		}

		if (m_fd != -1) {
		  closeImpl();
		  if (unlink(buf) == -1) {
			/* This is a little safety check for instances when we are dealing
			   with a regenerated session that was not yet written to disk */
			if (!access(buf, F_OK)) {
			  return false;
			}
		  }
		}

		return true;
	  }

	  bool gc(int maxlifetime, int *nrdels) {
		/* we don't perform any cleanup, if dirdepth is larger than 0.
		   we return true, since all cleanup should be handled by
		   an external entity (i.e. find -ctime x | xargs rm) */
		if (m_dirdepth == 0) {
		  *nrdels = CleanupDir(m_basedir.c_str(), maxlifetime);
		}
		return true;
	  }

	private:
	  int m_fd;
	  std::string m_lastkey;
	  std::string m_basedir;
	  size_t m_dirdepth;
	  size_t m_st_size;
	  int m_filemode;

	  /* If you change the logic here, please also update the error message in
	   * ps_files_open() appropriately */
	  static bool IsValid(const char *key) {
		const char *p; char c;
		bool ret = true;
		for (p = key; (c = *p); p++) {
		  /* valid characters are a..z,A..Z,0..9 */
		  if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
				|| (c >= '0' && c <= '9') || c == ',' || c == '-')) {
			ret = false;
			break;
		  }
		}
		size_t len = p - key;
		if (len == 0) {
		  ret = false;
		}
		return ret;
	  }

	#define FILE_PREFIX "sess_"

	  bool createPath(char *buf, size_t buflen, const char *key) {
		size_t key_len = strlen(key);
		if (key_len <= m_dirdepth ||
			buflen < (m_basedir.size() + 2 * m_dirdepth + key_len +
					  5 + sizeof(FILE_PREFIX))) {
		  return false;
		}

		const char *p = key;
		int n = m_basedir.size();
		memcpy(buf, m_basedir.c_str(), n);
		buf[n++] = PHP_DIR_SEPARATOR;
		for (int i = 0; i < (int)m_dirdepth; i++) {
		  buf[n++] = *p++;
		  buf[n++] = PHP_DIR_SEPARATOR;
		}
		memcpy(buf + n, FILE_PREFIX, sizeof(FILE_PREFIX) - 1);
		n += sizeof(FILE_PREFIX) - 1;
		memcpy(buf + n, key, key_len);
		n += key_len;
		buf[n] = '\0';

		return true;
	  }

	  void closeImpl() {
		if (m_fd != -1) {
		  ::close(m_fd);
		  m_fd = -1;
		}
	  }

	  void openImpl(const char *key) {
		if (m_fd < 0 || !m_lastkey.empty() || m_lastkey != key) {
		  m_lastkey.clear();
		  closeImpl();

		  if (!IsValid(key)) {
			raise_warning("The session id contains illegal characters, "
						  "valid characters are a-z, A-Z, 0-9 and '-,'");
			s_session->invalid_session_id = true;
			return;
		  }

		  char buf[PATH_MAX];
		  if (!createPath(buf, sizeof(buf), key)) {
			return;
		  }

		  m_lastkey = key;
		  m_fd = ::open(buf, O_CREAT | O_RDWR | 0, m_filemode);

		  if (m_fd != -1) {
			flock(m_fd, LOCK_EX);

	#ifdef F_SETFD
	# ifndef FD_CLOEXEC
	#  define FD_CLOEXEC 1
	# endif
			if (fcntl(m_fd, F_SETFD, FD_CLOEXEC)) {
			  raise_warning("fcntl(%d, F_SETFD, FD_CLOEXEC) failed: %s (%d)",
							m_fd, folly::errnoStr(errno).c_str(), errno);
			}
	#endif
		  } else {
			raise_warning("open(%s, O_RDWR) failed: %s (%d)", buf,
						  folly::errnoStr(errno).c_str(), errno);
		  }
		}
	  }

	  static int CleanupDir(const char *dirname, int maxlifetime) {
		DIR *dir = opendir(dirname);
		if (!dir) {
		  raise_notice("ps_files_cleanup_dir: opendir(%s) failed: %s (%d)",
					   dirname, folly::errnoStr(errno).c_str(), errno);
		  return 0;
		}

		time_t now;
		time(&now);

		size_t dirname_len = strlen(dirname);
		char dentry[sizeof(struct dirent) + PATH_MAX];
		struct dirent *entry = (struct dirent *) &dentry;
		struct stat sbuf;
		int nrdels = 0;

		/* Prepare buffer (dirname never changes) */
		char buf[PATH_MAX];
		memcpy(buf, dirname, dirname_len);
		buf[dirname_len] = PHP_DIR_SEPARATOR;

		while (readdir_r(dir, (struct dirent *)dentry, &entry) == 0 && entry) {
		  /* does the file start with our prefix? */
		  if (!strncmp(entry->d_name, FILE_PREFIX, sizeof(FILE_PREFIX) - 1)) {
			size_t entry_len = strlen(entry->d_name);

			/* does it fit into our buffer? */
			if (entry_len + dirname_len + 2 < PATH_MAX) {
			  /* create the full path.. */
			  memcpy(buf + dirname_len + 1, entry->d_name, entry_len);

			  /* NUL terminate it and */
			  buf[dirname_len + entry_len + 1] = '\0';

			  /* check whether its last access was more than maxlifet ago */
			  if (stat(buf, &sbuf) == 0 && (now - sbuf.st_mtime) > maxlifetime) {
				unlink(buf);
				nrdels++;
			  }
			}
		  }
		}

		closedir(dir);
		return nrdels;
	  }
	};
	RDS_LOCAL(FileSessionData, s_file_session_data);

	struct FileSessionModule : SessionModule {
	  FileSessionModule() : SessionModule("files") {
	  }
	  bool open(const char *save_path, const char *session_name) override {
		return s_file_session_data->open(save_path, session_name);
	  }
	  bool close() override {
		return s_file_session_data->close();
	  }
	  bool read(const char *key, String &value) override {
		return s_file_session_data->read(key, value);
	  }
	  bool write(const char *key, const String& value) override {
		return s_file_session_data->write(key, value);
	  }
	  bool destroy(const char *key) override {
		return s_file_session_data->destroy(key);
	  }
	  bool gc(int maxlifetime, int *nrdels) override {
		return s_file_session_data->gc(maxlifetime, nrdels);
	  }
	};
	static FileSessionModule s_file_session_module;

	//////////////////////////////////////////////////////////////////////////////
	// SystemlibSessionModule implementations

	static struct MemcacheSessionModule : SystemlibSessionModule {
		MemcacheSessionModule() : SystemlibSessionModule("memcache", "MemcacheSessionModule") { }
	} s_memcache_session_module;


	///////////////////////////////////////////////////////////////////////////////
	// session serializers


	#define PS_DELIMITER '|'
	#define PS_UNDEF_MARKER '!'

	struct SessionSerializer {
		String encode() {
			StringBuffer buf;
			VariableSerializer vs(VariableSerializer::Type::Serialize);
			for (ArrayIter iter(php_global(s__SESSION).toArray()); iter; ++iter) {
				Variant key = iter.first();
				if (key.isString()) {
					String skey = key.toString();
					buf.append(skey);
					if (skey.find(PS_DELIMITER) >= 0 || skey.find(PS_UNDEF_MARKER) >= 0) {
						return String();
					}
					buf.append(PS_DELIMITER);
					buf.append(
						vs.serialize(
							iter.second(), 
							true, /* ret */ 
							true /* keepCount */ 
						)
					);
				} else {
					raise_notice("Skipping numeric key %" PRId64, key.toInt64());
				}
			}
			return buf.detach();
		}
		
		bool decode(const String& value) {
			const char *p = value.data();
			const char *endptr = value.data() + value.size();
			VariableUnserializer vu(nullptr, 0, VariableUnserializer::Type::Serialize);
			while (p < endptr) {
				const char *q = p;
				while (*q != PS_DELIMITER) {
					if (++q >= endptr) return true;
				}
				int has_value;
				if (p[0] == PS_UNDEF_MARKER) {
					p++;
					has_value = 0;
				} else {
						has_value = 1;
				}
				String key(p, q - p, CopyString);
				q++;
				if (has_value) {
					vu.set(q, endptr);
					try {
						auto sess = php_global_exchange(s__SESSION, init_null());
						forceToArray(sess).set(key, vu.unserialize());
						php_global_set(s__SESSION, std::move(sess));
						q = vu.head();
					} catch (const ResourceExceededException&) {
						throw;
					} catch (const Exception&) {
					}
				}
				p = q;
			}
			return true;
		}
	};

	///////////////////////////////////////////////////////////////////////////////

	static bool session_check_active_state() {
		if (s_session->session_status == Session::Active) {
			raise_warning("A session is active. You cannot change the session module's ini settings at this time");
			return false;
		}
		return true;
	}

	static bool mod_is_open() {
		return s_session->mod_data || s_session->mod_user_implemented;
	}

	static bool ini_set_save_handler() {
		if (!session_check_active_state()) {
			return false;
		}
		s_session->mod = SessionModule::Find(s_session->save_handler_str.c_str());
		return true;
	}

	static bool ini_on_update_trans_sid(const bool& /*value*/) {
		return session_check_active_state();
	}

	static bool ini_on_update_save_dir(const std::string& value) {
		if (value.find('\0') != std::string::npos) {
			return false;
		}
		if (g_context.isNull()) return false;
		const char *path = value.data() + (value.rfind(';') + 1);
		if (File::TranslatePath(path).empty()) {
			return false;
		}
		s_session->save_path = path;
		return true;
	}

	///////////////////////////////////////////////////////////////////////////////

	static bool php_session_destroy() {
		bool retval = true;

		if (s_session->session_status != Session::Active) {
			raise_warning("Trying to destroy uninitialized session");
			return false;
		}

		if (s_session->mod->destroy(s_session->id.data()) == false) {
			retval = false;
			raise_warning("Session object destruction failed");
		}

		if (mod_is_open()) {
			s_session->mod->close();
		}

		s_session->destroy();

		return retval;
	}

	static String php_session_encode() {
		return s_session->serializer->encode();
	}

	static void php_session_decode(const String& value) {
		if (!s_session->serializer->decode(value)) {
			php_session_destroy();
			raise_warning("Failed to decode session object. Session has been destroyed");
		}
	}

	static void php_session_initialize() {
		/* check session name for invalid characters */
		if (strpbrk(s_session->id.data(), "\r\n\t <>'\"\\")) {
			s_session->id.reset();
		}

		if (!s_session->mod) {
			raise_error("No storage module chosen - failed to initialize session");
			return;
		}

		/* Open session handler first */
		if (!s_session->mod->open(
				s_session->save_path.c_str(), 
				s_session->session_name.c_str()
			)
		) {
			raise_error("Failed to initialize storage module: %s (path: %s)", s_session->mod->getName(), s_session->save_path.c_str());
			return;
		}

		/* If there is no ID, use session module to create one */
		if (s_session->id.empty()) {
				s_session->id = s_session->mod->create_sid();
			if (s_session->id.empty()) {
				raise_error("Failed to create session id: %s", s_session->mod->getName());
				return;
			}
			if (s_session->use_cookies) {
				s_session->send_cookie = true;
			}
		}

		php_global_set(s__SESSION, Variant{staticEmptyArray()});

		String value;
		if (s_session->mod->read(s_session->id.data(), value)) {
			php_session_decode(value);
		}
	}

	static void php_session_save_current_state() {
		bool ret = false;
		if (mod_is_open()) {
			String value = php_session_encode();
			if (!value.isNull()) {
				ret = s_session->mod->write(s_session->id.data(), value);
			}
		}
		if (!ret) {
			raise_warning(
				"Failed to write session data (%s). Please verify that the current setting of session.save_path is correct (%s)", 
				s_session->mod->getName(), 
				s_session->save_path.c_str()
			);
		}
		if (mod_is_open()) {
			s_session->mod->close();
		}
	}

	///////////////////////////////////////////////////////////////////////////////
	// Cookie Management

	static void php_session_send_cookie() {
		Transport *transport = g_context->getTransport();
		if (!transport) return;

		if (transport->headersSent()) {
			raise_warning("Cannot send session cookie - headers already sent");
			return;
		}

		int64_t expire = 0;
		if (s_session->cookie_lifetime > 0) {
			struct timeval tv;
			gettimeofday(&tv, nullptr);
			expire = tv.tv_sec + s_session->cookie_lifetime;
		}
		transport->setCookie(
			s_session->session_name,
			s_session->id,
			expire,
			s_session->cookie_path,
			s_session->cookie_domain,
			s_session->cookie_secure,
			s_session->cookie_httponly, 
			true
		);
	}

	static void php_session_reset_id() {
		if (s_session->use_cookies && s_session->send_cookie) {
			php_session_send_cookie();
			s_session->send_cookie = false;
		}

		if (s_session->define_sid) {
			StringBuffer var;
			var.append(String(s_session->session_name));
			var.append('=');
			var.append(s_session->id);
			Variant v = var.detach();

			static const auto s_SID = makeStaticString("SID");
			auto const handle = lookupCnsHandle(s_SID);
			if (!handle) {
				auto name = String{s_SID};
				auto value = v.toCell();
				Unit::defCns(name.get(), value);
			} else {
				auto cns = rds::handleToPtr<TypedValue, rds::Mode::NonLocal>(handle);
				v.setEvalScalar();
				cns->m_data = v.asTypedValue()->m_data;
				cns->m_type = v.asTypedValue()->m_type;
				if (rds::isNormalHandle(handle)) rds::initHandle(handle);
			}
		}
	}

	///////////////////////////////////////////////////////////////////////////////
	// Cache Limiters

	typedef struct {
		char *name;
		void (*func)();
	} php_session_cache_limiter_t;

	#define CACHE_LIMITER(name) _php_cache_limiter_##name
	#define CACHE_LIMITER_FUNC(name) static void CACHE_LIMITER(name)()
	#define CACHE_LIMITER_ENTRY(name) { #name, CACHE_LIMITER(name) },
	#define ADD_HEADER(hdr) g_context->getTransport()->addHeader(hdr)

	#define LAST_MODIFIED "Last-Modified: "
	#define EXPIRES "Expires: "
	#define MAX_STR 512

	static char *month_names[] = {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
	};

	static char *week_days[] = {
		"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"
	};

	static inline void strcpy_gmt(char *ubuf, time_t *when) {
		char buf[MAX_STR];
		struct tm tm, *res;
		int n;

		res = gmtime_r(when, &tm);

		if (!res) {
			buf[0] = '\0';
			return;
		}

		n = snprintf(buf, sizeof(buf), "%s, %02d %s %d %02d:%02d:%02d GMT", // SAFE
								 week_days[tm.tm_wday], tm.tm_mday,
								 month_names[tm.tm_mon], tm.tm_year + 1900,
								 tm.tm_hour, tm.tm_min,
								 tm.tm_sec);
		memcpy(ubuf, buf, n);
		ubuf[n] = '\0';
	}

	const StaticString s_PATH_TRANSLATED("PATH_TRANSLATED");

	static inline void last_modified() {
		String path = php_global(s__SERVER).toArray()[s_PATH_TRANSLATED].toString();
		if (!path.empty()) {
			struct stat sb;
			if (stat(path.data(), &sb) == -1) {
				return;
			}

			char buf[MAX_STR + 1];
			memcpy(buf, LAST_MODIFIED, sizeof(LAST_MODIFIED) - 1);
			strcpy_gmt(buf + sizeof(LAST_MODIFIED) - 1, &sb.st_mtime);
			ADD_HEADER(buf);
		}
	}

	CACHE_LIMITER_FUNC(public) {
		char buf[MAX_STR + 1];
		struct timeval tv;
		time_t now;

		gettimeofday(&tv, nullptr);
		now = tv.tv_sec + s_session->cache_expire * 60;
		memcpy(buf, EXPIRES, sizeof(EXPIRES) - 1);
		strcpy_gmt(buf + sizeof(EXPIRES) - 1, &now);
		ADD_HEADER(buf);

		snprintf(buf, sizeof(buf) , "Cache-Control: public, max-age=%" PRId64,
						 s_session->cache_expire * 60); /* SAFE */
		ADD_HEADER(buf);

		last_modified();
	}

	CACHE_LIMITER_FUNC(private_no_expire) {
		char buf[MAX_STR + 1];

		snprintf(buf, sizeof(buf), "Cache-Control: private, max-age=%" PRId64 ", "
						 "pre-check=%" PRId64, s_session->cache_expire * 60,
						 s_session->cache_expire * 60); /* SAFE */
		ADD_HEADER(buf);

		last_modified();
	}

	CACHE_LIMITER_FUNC(private) {
		ADD_HEADER("Expires: Thu, 19 Nov 1981 08:52:00 GMT");
		CACHE_LIMITER(private_no_expire)();
	}

	CACHE_LIMITER_FUNC(nocache) {
		ADD_HEADER("Expires: Thu, 19 Nov 1981 08:52:00 GMT");

		/* For HTTP/1.1 conforming clients and the rest (MSIE 5) */
		ADD_HEADER("Cache-Control: no-store, no-cache, must-revalidate, "
							 "post-check=0, pre-check=0");

		/* For HTTP/1.0 conforming clients */
		ADD_HEADER("Pragma: no-cache");
	}

	static php_session_cache_limiter_t php_session_cache_limiters[] = {
		CACHE_LIMITER_ENTRY(public)
		CACHE_LIMITER_ENTRY(private)
		CACHE_LIMITER_ENTRY(private_no_expire)
		CACHE_LIMITER_ENTRY(nocache)
		{0}
	};

	static int php_session_cache_limiter() {
		if (s_session->cache_limiter[0] == '\0') return 0;

		Transport *transport = g_context->getTransport();
		if (transport) {
			if (transport->headersSent()) {
				raise_warning("Cannot send session cache limiter - "
											"headers already sent");
				return -2;
			}

			php_session_cache_limiter_t *lim;
			for (lim = php_session_cache_limiters; lim->name; lim++) {
				if (!strcasecmp(lim->name, s_session->cache_limiter.c_str())) {
					lim->func();
					return 0;
				}
			}
		}

		return -1;
	}

	///////////////////////////////////////////////////////////////////////////////

	int64_t HHVM_FUNCTION(session_status) {
		return s_session->session_status;
	}

	String HHVM_FUNCTION(session_id, const Variant& newid /* = null_string */) {
		String ret = s_session->id;
		/*if (ret.isNull()) {
			ret = empty_string();
		}
		if (!newid.isNull()) {
			s_session->id = newid.toString();
		}*/
		return ret;
	}

	Variant HHVM_FUNCTION(session_encode) {
		String ret = php_session_encode();
		if (ret.isNull()) {
			return false;
		}
		return ret;
	}

	bool HHVM_FUNCTION(session_decode, const String& data) {
		if (s_session->session_status != Session::None) {
			php_session_decode(data);
			return true;
		}
		return false;
	}

	const StaticString
		s_REQUEST_URI("REQUEST_URI"),
		s_HTTP_REFERER("HTTP_REFERER");

	bool HHVM_FUNCTION(session_start) {
		s_session->apply_trans_sid = s_session->use_trans_sid;
		String value;
		
		switch (s_session->session_status) {
			case Session::Active:
				raise_notice("A session had already been started - ignoring session_start()");
				return false;
			case Session::Disabled: {
				s_session->mod = SessionModule::Find(value.data());
				if (!s_session->mod) {
					raise_warning("Cannot find save handler '%s' - session startup failed", value.data());
					return false;
				}
				s_session->session_status = Session::None;
			}
			default:
				assertx(s_session->session_status == Session::None);
				s_session->define_sid = true;
				s_session->send_cookie = true;
		}

		/*
		 * Cookies are preferred, because initially
		 * cookie and get variables will be available.
		 */
		if (s_session->id.empty()) {
			if (s_session->use_cookies) {
				auto cookies = php_global(s__COOKIE).toArray();
				if (cookies.exists(String(s_session->session_name))) {
					s_session->id = cookies[String(s_session->session_name)].toString();
					s_session->apply_trans_sid = false;
					s_session->send_cookie = false;
					s_session->define_sid = false;
				}
			}

			if (!s_session->use_only_cookies && !s_session->id) {
				auto get = php_global(s__GET).toArray();
				if (get.exists(String(s_session->session_name))) {
					s_session->id = get[String(s_session->session_name)].toString();
					s_session->send_cookie = false;
				}
			}

			if (!s_session->use_only_cookies && !s_session->id) {
				auto post = php_global(s__POST).toArray();
				if (post.exists(String(s_session->session_name))) {
					s_session->id = post[String(s_session->session_name)].toString();
					s_session->send_cookie = false;
				}
			}
		}

		int lensess = s_session->session_name.size();

		/* check the REQUEST_URI symbol for a string of the form
			 '<session-name>=<session-id>' to allow URLs of the form
			 http://yoursite/<session-name>=<session-id>/script.php */
		if (!s_session->use_only_cookies && s_session->id.empty()) {
			value = php_global(s__SERVER).toArray()[s_REQUEST_URI].toString();
			const char *p = strstr(value.data(), s_session->session_name.c_str());
			if (p && p[lensess] == '=') {
				p += lensess + 1;
				const char *q;
				if ((q = strpbrk(p, "/?\\"))) {
					s_session->id = String(p, q - p, CopyString);
					s_session->send_cookie = false;
				}
			}
		}

		/* check whether the current request was referred to by
			 an external site which invalidates the previously found id */
		if (!s_session->id.empty() && s_session->extern_referer_chk[0] != '\0') {
			value = php_global(s__SERVER).toArray()[s_HTTP_REFERER].toString();
			if (!strstr(value.data(), s_session->extern_referer_chk.c_str())) {
				s_session->id.reset();
				s_session->send_cookie = true;
				if (s_session->use_trans_sid) {
					s_session->apply_trans_sid = true;
				}
			}
		}

		php_session_initialize();

		if (!s_session->use_cookies && s_session->send_cookie) {
			if (s_session->use_trans_sid) {
				s_session->apply_trans_sid = true;
			}
			s_session->send_cookie = false;
		}

		php_session_reset_id();

		s_session->session_status = Session::Active;

		php_session_cache_limiter();

		if (mod_is_open() && s_session->gc_probability > 0) {
			int nrdels = -1;

			int nrand = (int) ((float) s_session->gc_divisor * math_combined_lcg());
			if (nrand < s_session->gc_probability) {
				s_session->mod->gc(s_session->gc_maxlifetime, &nrdels);
			}
		}

		if (s_session->session_status != Session::Active) {
			return false;
		}
		return true;
	}

	bool HHVM_FUNCTION(session_destroy) {
		return php_session_destroy();
	}

	void HHVM_FUNCTION(session_unset) {
		if (s_session->session_status == Session::None) {
			return;
		}
		php_global_set(s__SESSION, empty_array());
		return;
	}

	void HHVM_FUNCTION(session_write_close) {
		if (s_session->session_status == Session::Active) {
			s_session->session_status = Session::None;
			php_session_save_current_state();
		}
	}

	///////////////////////////////////////////////////////////////////////////////

	class ext_sessionExtension : public Extension {
		public:
				ext_sessionExtension(): Extension("ext_session", "0.1.0") {}
				
		void moduleInit() override {
			HHVM_RC_INT(PHP_SESSION_DISABLE, Session::Disabled);
			HHVM_RC_INT(PHP_SESSION_NONE, Session::None);
			HHVM_RC_INT(PHP_SESSION_ACTIVE, Session::Active);

			HHVM_FE(session_status);
			HHVM_FE(session_id);
			HHVM_FE(session_encode);
			HHVM_FE(session_decode);
			HHVM_FE(session_start);
			HHVM_FE(session_destroy);
			HHVM_FE(session_unset);
			HHVM_FE(session_write_close);

			loadSystemlib();
		}

		void threadInit() override {
			assertx(s_session.isNull());
			s_session.getCheck();
			Extension* ext = ExtensionRegistry::get(s_session_ext_name);
			assertx(ext);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL,
				"session.save_path",               "",
				IniSetting::SetAndGet<std::string>(
					ini_on_update_save_dir, nullptr
				),
				&s_session->save_path);
			Variant v;
			if (IniSetting::GetSystem("session.save_path", v) && !v.toString().empty()) {
				s_session->reset_save_path = true;
			}

			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL, "session.crypto_cookie_time_user_key", "2592000", &s_session->crypto_cookie_time_user_key);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL, "session.use_crypto_storage_user_key", "0", &s_session->use_crypto_storage_user_key);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL, "session.use_crypto_storage", "0", &s_session->use_crypto_storage);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL, "session.crypto_secret", "X", &s_session->crypto_secret);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL, "session.digest_algo", "sha256", &s_session->digest_algo);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL, "session.cipher_algo", "aes-256-ctr", &s_session->cipher_algo);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL, "session.cipher_keylen", "32", &s_session->cipher_keylen);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL, "session.crypto_expire", "2592000", &s_session->crypto_expire);
			
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL, 
											"session.memcache_persistent", 		"0", 
											&s_session->memcache_persistent);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL, 
											"session.memcache_host", 			"localhost", 
											&s_session->memcache_host);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL, 
											"session.memcache_port", 			"11211", 
											&s_session->memcache_port);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL, 
											"session.save_handler", 			"files", 
											&s_session->save_handler_str);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL, 
											"session.name", 					"SESSION_ID", 
											&s_session->session_name);
			
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL,
											"session.auto_start",				"0",
											&s_session->auto_start);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL,
											"session.gc_probability",			"1",
											&s_session->gc_probability);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL,
											"session.gc_divisor",				"100",
											&s_session->gc_divisor);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL,
											"session.gc_maxlifetime",			"1440",
											&s_session->gc_maxlifetime);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL,
											"session.cookie_lifetime",			"0",
											&s_session->cookie_lifetime);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL,
											"session.cookie_path",				"/",
											&s_session->cookie_path);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL,
											"session.cookie_domain",			"",
											&s_session->cookie_domain);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL,
											"session.cookie_secure",			"",
											&s_session->cookie_secure);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL,
											"session.cookie_httponly",			"",
											&s_session->cookie_httponly);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL,
											"session.use_cookies",				"1",
											&s_session->use_cookies);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL,
											"session.use_only_cookies",			"1",
											&s_session->use_only_cookies);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL,
											"session.referer_check",			"",
											&s_session->extern_referer_chk);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL,
											"session.entropy_file",				"",
											&s_session->entropy_file);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL,
											"session.entropy_length",			"0",
											&s_session->entropy_length);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL,
											"session.cache_limiter",			"nocache",
											&s_session->cache_limiter);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL,
											"session.cache_expire",				"180",
											&s_session->cache_expire);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL,
											"session.use_trans_sid",			"0",
											IniSetting::SetAndGet<bool>(
												ini_on_update_trans_sid, nullptr
											),
											&s_session->use_trans_sid);
			IniSetting::Bind(ext, IniSetting::PHP_INI_ALL,
											"session.hash_bits_per_character", "4",
											&s_session->hash_bits_per_character);			
			ini_set_save_handler();
		}

		void threadShutdown() override {
			s_session.destroy();
		}

		void requestInit() override {
			s_session->init();
		}
		
		void requestShutdown() override {
			HHVM_FN(session_write_close)();
			s_session->requestShutdownImpl();
		}
	} s_ext_session_extension;

	HHVM_GET_MODULE(ext_session);
}