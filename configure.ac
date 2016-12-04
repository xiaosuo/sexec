#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([sexec], [1.0.0], [xiaosuo@gmail.com])
AC_CONFIG_SRCDIR([src/main.cc])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_CONFIG_HEADERS([config.h])

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

# Checks for programs.
AC_PROG_CXX
AX_CXX_COMPILE_STDCXX_14

# Checks for libraries.
PKG_CHECK_MODULES(LIBSSH, [libssh])
AC_SUBST(LIBSSH_CFLAGS)
AC_SUBST(LIBSSH_LIBS)

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([memset])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
AC_MSG_RESULT([
	$PACKAGE_NAME $VERSION
	PACKAGE_TARNAME:		${PACKAGE_TARNAME}
	prefix:				${prefix}
	exec_prefix:			${exec_prefix}
	bindir:				${bindir}
	sysconfdir:			${sysconfdir}
	libdir:				${libdir}
	datarootdir:			${datarootdir}
	docdir:				${docdir}

	CXX:				${CXX}
	CXXFLAGS:			${CXXFLAGS}
	CPPFLAGS:			${CPPFLAGS}
	LDFLAGS:			${LDFLAGS}
])
