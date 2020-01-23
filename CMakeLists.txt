cmake_minimum_required(VERSION 3.14)
project(iwd VERSION 1.4 LANGUAGES C)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

include(GNUInstallDirs)

set(DAEMON_STORAGEDIR "${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/lib/iwd" CACHE PATH
    "Directory for Wireless daemon storage files")

set(DAEMON_CONFIGDIR "${CMAKE_INSTALL_FULL_SYSCONFDIR}/iwd" CACHE PATH
    "Directory for Wireless daemon configuration")

include(CheckFunctionExists)
check_function_exists(explicit_bzero HAVE_EXPLICIT_BZERO)

option(ENABLE_PIE "enable position independent executables flag" OFF)
if(ENABLE_PIE)
    include(CheckPIESupported)
    check_pie_supported(OUTPUT_VARIABLE HAVE_PIE LANGUAGES C)
    if(HAVE_PIE)
        set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    endif()
endif()

option(ENABLE_DAEMON "install iwd system daemon" ON)
option(ENABLE_EXTERNAL_ELL "enable external Embedded Linux Library" OFF)
option(ENABLE_TOOLS "enable internal testing utilities" OFF)
option(ENABLE_SIM_HARDCODED "enable hard coded SIM keys" OFF)

option(BUILD_TESTING "Build the testing tree." OFF)

# sanitizers
option(ENABLE_ASAN "enable linking with address sanitizer" OFF)
option(ENABLE_LSAN "enable linking with leak sanitizer" OFF)
option(ENABLE_UBSAN "enable linking with undefined behaviour sanitizer" OFF)

include(CheckLibraryExists)
check_library_exists(asan  _init "" HAVE_ASAN)
check_library_exists(lsan  _init "" HAVE_LSAN)
check_library_exists(ubsan _init "" HAVE_UBSAN)

include(CheckCCompilerFlag)
check_c_compiler_flag(-fsanitize=address   HAVE_ASAN_FLAG)
check_c_compiler_flag(-fsanitize=leak      HAVE_LSAN_FLAG)
check_c_compiler_flag(-fsanitize=undefined HAVE_ASAN_FLAG)

if(ENABLE_ASAN AND HAVE_ASAN AND HAVE_ASAN_FLAG)
    add_compile_options(-fsanitize=address)
    add_link_options(-fsanitize=address)
elseif(ENABLE_LSAN AND HAVE_LSAN AND HAVE_LSAN_FLAG)
    add_compile_options(-fsanitize=leak)
    add_link_options(-fsanitize=leak)
elseif(ENABLE_UBSAN AND HAVE_UBSAN AND HAVE_UBSAN_FLAG)
    add_compile_options(-fsanitize=undefined)
    add_link_options(-fsanitize=undefined)
endif()

# ell
if(ENABLE_EXTERNAL_ELL)
    find_package(PkgConfig REQUIRED QUIET)
    pkg_check_modules(Ell REQUIRED IMPORTED_TARGET ell>=0.26)
    add_library(ell INTERFACE)
    target_link_libraries(ell INTERFACE PkgConfig::Ell)
else()
    include(CheckIncludeFile)
    check_include_file(linux/types.h HAVE_LINUX_TYPES_H)
    check_include_file(linux/if_alg.h HAVE_LINUX_IF_ALG_H)

    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/ell")
        file(CREATE_LINK "${CMAKE_CURRENT_SOURCE_DIR}/../ell" "${CMAKE_CURRENT_SOURCE_DIR}/ell" SYMBOLIC)
    endif()
    add_library(ell STATIC
        ell/ell/private.h
        ell/ell/missing.h
        ell/ell/util.c
        ell/ell/test.c
        ell/ell/strv.c
        ell/ell/utf8.c
        ell/ell/queue.c
        ell/ell/hashmap.c
        ell/ell/string.c
        ell/ell/settings.c
        ell/ell/main.c
        ell/ell/idle.c
        ell/ell/signal.c
        ell/ell/timeout.c
        ell/ell/io.c
        ell/ell/ringbuf.c
        ell/ell/log.c
        ell/ell/plugin.c
        ell/ell/checksum.c
        ell/ell/netlink-private.h
        ell/ell/netlink.c
        ell/ell/genl-private.h
        ell/ell/genl.c
        ell/ell/dbus-private.h
        ell/ell/dbus.c
        ell/ell/dbus-message.c
        ell/ell/dbus-util.c
        ell/ell/dbus-service.c
        ell/ell/dbus-client.c
        ell/ell/dbus-name-cache.c
        ell/ell/dbus-filter.c
        ell/ell/gvariant-private.h
        ell/ell/gvariant-util.c
        ell/ell/siphash-private.h
        ell/ell/siphash.c
        ell/ell/hwdb.c
        ell/ell/cipher.c
        ell/ell/random.c
        ell/ell/uintset.c
        ell/ell/base64.c
        ell/ell/asn1-private.h
        ell/ell/pem.c
        ell/ell/pem-private.h
        ell/ell/tls-private.h
        ell/ell/tls.c
        ell/ell/tls-record.c
        ell/ell/tls-suites.c
        ell/ell/tls-extensions.c
        ell/ell/uuid.c
        ell/ell/key.c
        ell/ell/pkcs5-private.h
        ell/ell/pkcs5.c
        ell/ell/file.c
        ell/ell/dir.c
        ell/ell/net.c
        ell/ell/dhcp-private.h
        ell/ell/dhcp.c
        ell/ell/dhcp-transport.c
        ell/ell/dhcp-lease.c
        ell/ell/cert-private.h
        ell/ell/cert.c
        ell/ell/ecc-external.c
        ell/ell/ecc-private.h
        ell/ell/ecc.c
        ell/ell/ecdh.c
        ell/ell/time.c
        ell/ell/path.c)
    target_compile_definitions(ell PRIVATE
        $<$<BOOL:${HAVE_EXPLICIT_BZERO}>:HAVE_EXPLICIT_BZERO>
        $<$<BOOL:${HAVE_LINUX_IF_ALG_H}>:HAVE_LINUX_IF_ALG_H>
        $<$<BOOL:${HAVE_LINUX_TYPES_H}>:HAVE_LINUX_TYPES_H>)
    target_include_directories(ell PRIVATE ell)
endif()

set(BUILTIN_MODULES)
if(ENABLE_SIM_HARDCODED)
    list(APPEND BUILTIN_MODULES "sim_hardcoded")
endif()

file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/src")
add_custom_target(builtin.h
    "${CMAKE_CURRENT_SOURCE_DIR}/src/genbuiltin" ${BUILTIN_MODULES}
    > "${CMAKE_CURRENT_BINARY_DIR}/src/builtin.h")

add_library(eap OBJECT
    src/eap.c src/eap.h src/eap-private.h
    src/eap-wsc.c src/eap-wsc.h
    src/eap-md5.c
    src/eap-tls.c
    src/eap-ttls.c
    src/eap-mschapv2.c src/eap-mschapv2.h
    src/eap-sim.c
    src/eap-aka.c
    src/eap-peap.c
    src/eap-gtc.c
    src/eap-pwd.c
    src/util.h src/util.c
    src/crypto.h src/crypto.c
    src/wscutil.h src/wscutil.c
    src/simutil.h src/simutil.c
    src/simauth.h src/simauth.c
    src/watchlist.h src/watchlist.c
    src/eap-tls-common.h src/eap-tls-common.c
    src/mschaputil.h src/mschaputil.c)
target_compile_definitions(eap PRIVATE $<$<BOOL:${HAVE_EXPLICIT_BZERO}>:HAVE_EXPLICIT_BZERO>)
target_include_directories(eap PRIVATE ell)

if(ENABLE_DAEMON)
    add_executable(iwd
        src/main.c linux/nl80211.h src/iwd.h src/missing.h
        src/plugin.h src/plugin.c
        src/netdev.h src/netdev.c
        src/wiphy.h src/wiphy.c
        src/device.c
        src/station.h src/station.c
        src/ie.h src/ie.c
        src/mpdu.h src/mpdu.c
        src/eapol.h src/eapol.c
        src/eapolutil.h src/eapolutil.c
        src/handshake.h src/handshake.c
        src/scan.h src/scan.c
        src/common.h src/common.c
        src/agent.h src/agent.c
        src/storage.h src/storage.c
        src/network.h src/network.c
        src/wsc.h src/wsc.c
        src/backtrace.h src/backtrace.c
        src/knownnetworks.h
        src/knownnetworks.c
        src/rfkill.h src/rfkill.c
        src/ft.h src/ft.c
        src/ap.c src/adhoc.c
        src/sae.h src/sae.c
        src/nl80211util.h src/nl80211util.c
        src/nl80211cmd.h src/nl80211cmd.c
        src/owe.h src/owe.c
        src/blacklist.h src/blacklist.c
        src/manager.c
        src/erp.h src/erp.c
        src/fils.h src/fils.c
        src/rtnlutil.h src/rtnlutil.c
        src/auth-proto.h
        src/anqp.h src/anqp.c
        src/anqputil.h src/anqputil.c
        src/netconfig.h src/netconfig.c
        src/resolve.h src/resolve.c
        src/hotspot.c
        src/p2putil.h src/p2putil.c
        src/module.h src/module.c
        src/rrm.c)
    target_include_directories(iwd PRIVATE ell)
    target_compile_definitions(iwd PRIVATE
        VERSION="${PROJECT_VERSION}"
        $<$<BOOL:${HAVE_EXPLICIT_BZERO}>:HAVE_EXPLICIT_BZERO>
        DAEMON_CONFIGDIR="${DAEMON_CONFIGDIR}"
        DAEMON_STORAGEDIR="${DAEMON_STORAGEDIR}")
    target_link_libraries(iwd PRIVATE ell eap ${CMAKE_DL_LIBS})
    if(ENABLE_SIM_HARDCODED)
        target_sources(iwd PRIVATE plugins/sim_hardcoded.c)
    endif()
    add_dependencies(iwd builtin.h)
    install(TARGETS iwd)
endif()

install(PROGRAMS iwc iwd_passphrase TYPE BIN)
install(FILES src/iwd.config.5 src/iwd.network.5 DESTINATION "${CMAKE_INSTALL_FULL_MANDIR}/man5")
install(FILES src/iwd.debug.7 DESTINATION "${CMAKE_INSTALL_FULL_MANDIR}/man7")
install(FILES src/iwd.8 DESTINATION "${CMAKE_INSTALL_FULL_MANDIR}/man8")
