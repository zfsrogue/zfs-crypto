dnl #
dnl # Check for libcurl
dnl #
AC_DEFUN([ZFS_AC_CONFIG_LIBCURL], [
	LIBCURL=

	AC_CHECK_HEADER([curl/curl.h], [], [AC_MSG_FAILURE([
	*** curl/curl.h missing, libcurl-devel package required])])

	AC_CHECK_LIB([curl], [curl_easy_init], [], [AC_MSG_FAILURE([
	*** curl_easy_init() missing, libcurl-devel package required])])

	AC_CHECK_LIB([curl], [curl_easy_setopt], [], [AC_MSG_FAILURE([
	*** curl_easy_setopt() missing, libcurl-devel package required])])

	AC_SUBST([LIBCURL], ["-lcurl"])
	AC_DEFINE([HAVE_LIBCURL], 1, [Define if you have libcurl])
])
