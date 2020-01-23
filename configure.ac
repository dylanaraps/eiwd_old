AC_PREREQ(2.60)
AC_INIT(iwd, 1.4)

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_AUX_DIR(build-aux)
AC_CONFIG_MACRO_DIR(build-aux)

AM_INIT_AUTOMAKE([foreign subdir-objects color-tests silent-rules
					tar-pax no-dist-gzip dist-xz])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_MAINTAINER_MODE

AC_PREFIX_DEFAULT(/usr/local)

PKG_PROG_PKG_CONFIG

COMPILER_FLAGS

AC_LANG_C

AC_PROG_CC
AC_PROG_CC_PIE
AC_PROG_CC_ASAN
AC_PROG_CC_LSAN
AC_PROG_CC_UBSAN
AC_PROG_INSTALL
AC_PROG_MKDIR_P
AC_PROG_LN_S

AC_SYS_LARGEFILE

LT_PREREQ(2.2)
LT_INIT([disable-static])

AC_ARG_ENABLE(optimization, AC_HELP_STRING([--disable-optimization],
			[disable code optimization through compiler]), [
	if (test "${enableval}" = "no"); then
		CFLAGS="$CFLAGS -U_FORTIFY_SOURCE -O0"
	fi
])

AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug],
			[enable compiling with debugging information]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_prog_cc_g}" = "yes"); then
		CFLAGS="$CFLAGS -g"
	fi
])

AC_ARG_ENABLE(pie, AC_HELP_STRING([--enable-pie],
			[enable position independent executables flag]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_prog_cc_pie}" = "yes"); then
		CFLAGS="$CFLAGS -fPIE"
		LDFLAGS="$LDFLAGS -pie"
	fi
])

save_LIBS=$LIBS
AC_CHECK_LIB(asan, _init)
LIBS=$save_LIBS

AC_ARG_ENABLE(asan, AC_HELP_STRING([--enable-asan],
			[enable linking with address sanitizer]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_lib_asan__init}" = "yes" &&
				test "${ac_cv_prog_cc_asan}" = "yes"); then
		CFLAGS="$CFLAGS -fsanitize=address";
		LDFLAGS="$LDFLAGS -fsanitize=address"
	fi
])

save_LIBS=$LIBS
AC_CHECK_LIB(lsan, _init)
LIBS=$save_LIBS

AC_ARG_ENABLE(lsan, AC_HELP_STRING([--enable-lsan],
			[enable linking with leak sanitizer]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_lib_lsan__init}" = "yes" &&
				test "${ac_cv_prog_cc_lsan}" = "yes"); then
		CFLAGS="$CFLAGS -fsanitize=leak";
		LDFLAGS="$LDFLAGS -fsanitize=leak"
	fi
])

save_LIBS=$LIBS
AC_CHECK_LIB(ubsan, _init)
LIBS=$save_LIBS

AC_ARG_ENABLE(ubsan, AC_HELP_STRING([--enable-ubsan],
			[enable linking with undefined behavior sanitizer]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_lib_ubsan__init}" = "yes" &&
				test "${ac_cv_prog_cc_ubsan}" = "yes"); then
		CFLAGS="$CFLAGS -fsanitize=undefined";
		LDFLAGS="$LDFLAGS -fsanitize=undefined"
	fi
])
if (test "${prefix}" = "NONE"); then
	dnl no prefix and no localstatedir, so default to /var
	if (test "$localstatedir" = '${prefix}/var'); then
		AC_SUBST([localstatedir], ['/var'])
	fi

	prefix="${ac_default_prefix}"
fi

if (test "$localstatedir" = '${prefix}/var'); then
	daemon_storagedir="${prefix}/var/lib/iwd"
else
	daemon_storagedir="${localstatedir}/lib/iwd"
fi

AC_SUBST([daemon_storagedir], [${daemon_storagedir}])

AC_DEFINE_UNQUOTED(DAEMON_STORAGEDIR, "${daemon_storagedir}",
			[Directory for Wireless daemon storage files])
AC_DEFINE_UNQUOTED(DAEMON_CONFIGDIR, "/etc/iwd",
			[Directory for Wireless daemon configuration])

AC_CHECK_FUNCS(explicit_bzero)

AC_CHECK_HEADERS(linux/types.h linux/if_alg.h)

# In maintainer mode: try to build with application backtrace and disable PIE.
if (test "${USE_MAINTAINER_MODE}" = yes); then
	AC_SEARCH_LIBS([backtrace], [execinfo],
		[
			AC_DEFINE([HAVE_BACKTRACE], [1],
				[Define to 1 if you have backtrace(3).])
			CFLAGS="$CFLAGS -fno-PIE"
			LDFLAGS="$LDFLAGS -no-pie"
		])
fi

AC_ARG_ENABLE([external_ell], AC_HELP_STRING([--enable-external-ell],
				[enable external Embedded Linux library]),
					[enable_external_ell=${enableval}])
if (test "${enable_external_ell}" = "yes"); then
	if (test "${enable_hwsim}" = "yes"); then
		ell_min_version="0.26"
	else
		ell_min_version="0.5"
	fi
	PKG_CHECK_MODULES(ELL, ell >= ${ell_min_version}, dummy=yes,
		AC_MSG_ERROR(Embedded Linux library >= ${ell_min_version} is required))
	AC_SUBST(ELL_CFLAGS)
	AC_SUBST(ELL_LIBS)
fi
AM_CONDITIONAL(EXTERNAL_ELL, test "${enable_external_ell}" = "yes")


AC_ARG_ENABLE([tools], AC_HELP_STRING([--enable-tools],
				[enable internal testing utilities]),
					[enable_tools=${enableval}])
AM_CONDITIONAL(TOOLS, test "${enable_tools}" = "yes")

AC_ARG_ENABLE([sim_hardcoded], AC_HELP_STRING([--enable-sim-hardcoded],
				[enable hard coded SIM keys]),
					[enable_sim_hardcoded=${enableval}])
AM_CONDITIONAL(SIM_HARDCODED, test "${enable_sim_hardcoded}" = "yes")

AC_CONFIG_FILES(Makefile)

AC_OUTPUT

AC_MSG_RESULT([
	$PACKAGE_NAME $VERSION
])
