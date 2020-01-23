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
    target_compile_definitions(ell INTERFACE $<$<BOOL:${HAVE_EXPLICIT_BZERO}>:HAVE_EXPLICIT_BZERO>)
    target_link_libraries(ell INTERFACE PkgConfig::Ell)
else()
    include(CheckIncludeFile)
    check_include_file(linux/types.h HAVE_LINUX_TYPES_H)
    check_include_file(linux/if_alg.h HAVE_LINUX_IF_ALG_H)

    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/ell")
        file(CREATE_LINK "${CMAKE_CURRENT_SOURCE_DIR}/../ell/ell" "${CMAKE_CURRENT_SOURCE_DIR}/ell" SYMBOLIC)
    endif()
    add_library(ell STATIC
        ell/private.h
        ell/missing.h
        ell/util.c
        ell/test.c
        ell/strv.c
        ell/utf8.c
        ell/queue.c
        ell/hashmap.c
        ell/string.c
        ell/settings.c
        ell/main.c
        ell/idle.c
        ell/signal.c
        ell/timeout.c
        ell/io.c
        ell/ringbuf.c
        ell/log.c
        ell/plugin.c
        ell/checksum.c
        ell/netlink-private.h
        ell/netlink.c
        ell/genl-private.h
        ell/genl.c
        ell/dbus-private.h
        ell/dbus.c
        ell/dbus-message.c
        ell/dbus-util.c
        ell/dbus-service.c
        ell/dbus-client.c
        ell/dbus-name-cache.c
        ell/dbus-filter.c
        ell/gvariant-private.h
        ell/gvariant-util.c
        ell/siphash-private.h
        ell/siphash.c
        ell/hwdb.c
        ell/cipher.c
        ell/random.c
        ell/uintset.c
        ell/base64.c
        ell/asn1-private.h
        ell/pem.c
        ell/pem-private.h
        ell/tls-private.h
        ell/tls.c
        ell/tls-record.c
        ell/tls-suites.c
        ell/tls-extensions.c
        ell/uuid.c
        ell/key.c
        ell/pkcs5-private.h
        ell/pkcs5.c
        ell/file.c
        ell/dir.c
        ell/net.c
        ell/dhcp-private.h
        ell/dhcp.c
        ell/dhcp-transport.c
        ell/dhcp-lease.c
        ell/cert-private.h
        ell/cert.c
        ell/ecc-external.c
        ell/ecc-private.h
        ell/ecc.c
        ell/ecdh.c
        ell/time.c
        ell/path.c)
    target_compile_definitions(ell
        PUBLIC
        $<$<BOOL:${HAVE_EXPLICIT_BZERO}>:HAVE_EXPLICIT_BZERO>
        PRIVATE
        $<$<BOOL:${HAVE_LINUX_IF_ALG_H}>:HAVE_LINUX_IF_ALG_H>
        $<$<BOOL:${HAVE_LINUX_TYPES_H}>:HAVE_LINUX_TYPES_H>)
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

# tests
if(ENABLE_TOOLS)
    add_executable(test-runner tools/test-runner.c)
    target_compile_definitions(test-runner PRIVATE
        DAEMON_CONFIGDIR="${DAEMON_CONFIGDIR}"
        DAEMON_STORAGEDIR="${DAEMON_STORAGEDIR}")
    target_link_libraries(test-runner PRIVATE ell)
endif()

if(BUILD_TESTING)
    enable_testing()

    add_executable(test-eap-sim unit/test-eap-sim.c
        src/crypto.c src/crypto.h
        src/simutil.c src/simutil.h
        src/ie.c src/ie.h
        src/watchlist.c src/watchlist.h
        src/eapol.c src/eapol.h
        src/eapolutil.c src/eapolutil.h
        src/handshake.c src/handshake.h
        src/eap.c src/eap.c src/eap-private.h
        src/util.c src/util.h
        src/simauth.c src/simauth.h
        src/erp.c src/erp.h
        src/eap-sim.c)
    target_link_libraries(test-eap-sim PRIVATE ell)
    add_test(NAME eap-sim COMMAND test-eap-sim)
    
    add_executable(test-cmac-aes unit/test-cmac-aes.c src/crypto.c src/crypto.h)
    target_link_libraries(test-cmac-aes PRIVATE ell)
    add_test(NAME cmac-aes COMMAND test-cmac-aes)

    add_executable(test-arc4 unit/test-arc4.c src/crypto.c src/crypto.h)
    target_link_libraries(test-arc4 PRIVATE ell)
    add_test(NAME arc4 COMMAND test-arc4)

    add_executable(test-hmac-md5 unit/test-hmac-md5.c src/crypto.c src/crypto.h)
    target_link_libraries(test-hmac-md5 PRIVATE ell)
    add_test(NAME hmac-md5 COMMAND test-hmac-md5)

    add_executable(test-hmac-sha1 unit/test-hmac-sha1.c src/crypto.c src/crypto.h)
    target_link_libraries(test-hmac-sha1 PRIVATE ell)
    add_test(NAME hmac-sha1 COMMAND test-hmac-sha1)

    add_executable(test-hmac-sha256 unit/test-hmac-sha256.c src/crypto.c src/crypto.h)
    target_link_libraries(test-hmac-sha256 PRIVATE ell)
    add_test(NAME hmac-sha256 COMMAND test-hmac-sha256)

    add_executable(test-prf-sha1 unit/test-prf-sha1.c src/crypto.c src/crypto.h)
    target_link_libraries(test-prf-sha1 PRIVATE ell)
    add_test(NAME prf-sha1 COMMAND test-prf-sha1)

    add_executable(test-kdf-sha256 unit/test-kdf-sha256.c src/crypto.c src/crypto.h)
    target_link_libraries(test-kdf-sha256 PRIVATE ell)
    add_test(NAME kdf-sha256 COMMAND test-kdf-sha256)

    add_executable(test-ie unit/test-ie.c src/ie.c src/ie.h)
    target_link_libraries(test-ie PRIVATE ell)
    add_test(NAME ie COMMAND test-ie)

    add_executable(test-crypto unit/test-crypto.c src/crypto.c src/crypto.h)
    target_link_libraries(test-crypto PRIVATE ell)
    add_test(NAME crypto COMMAND test-crypto)

    add_executable(test-mpdu unit/test-mpdu.c src/mpdu.c src/mpdu.h src/ie.c src/ie.h)
    target_link_libraries(test-mpdu PRIVATE ell)
    add_test(NAME mpdu COMMAND test-mpdu)

    add_executable(test-eapol unit/test-eapol.c
        src/crypto.c src/crypto.h
        src/ie.c src/ie.h
        src/watchlist.c src/watchlist.h
        src/eapol.c src/eapol.h
        src/eapolutil.c src/eapolutil.h
        src/handshake.c src/handshake.h
        src/eap.c src/eap.h src/eap-private.h
        src/eap-tls.c 
        src/eap-ttls.c
        src/eap-md5.c
        src/util.c
        src/eap-tls-common.c src/eap-tls-common.h
        src/erp.c src/erp.h
        src/mschaputil.c src/mschaputil.h)
    target_compile_definitions(test-eapol PRIVATE CERTDIR="${CMAKE_CURRENT_BUILD_DIR}")
    target_link_libraries(test-eapol PRIVATE ell)
    add_dependencies(test-eapol
        cert-server.pem
        cert-server-key-pkcs8.pem
        cert-client.pem
        cert-client-key-pkcs8.pem
        tls-settings.8021x)
    add_test(NAME eapol COMMAND test-eapol)

    add_executable(test-util unit/test-util.c src/util.c src/util.h)
    target_link_libraries(test-util PRIVATE ell)
    add_test(NAME util COMMAND test-util)

    add_executable(test-ssid-security unit/test-ssid-security.c src/ie.c src/ie.h src/common.c src/common.h)
    target_link_libraries(test-ssid-security PRIVATE ell)
    add_test(NAME ssid-security COMMAND test-ssid-security)

    add_executable(test-wsc unit/test-wsc.c
        src/wscutil.c src/wscutil.h
        src/crypto.c src/crypto.h
        src/ie.c src/ie.h
        src/watchlist.c src/watchlist.h
        src/eapol.c src/eapol.h
        src/eapolutil.c src/eapolutil.h
        src/handshake.c src/handshake.h
        src/eap.c src/eap.c src/eap-private.h
        src/util.c src/util.h
        src/erp.c src/erp.h
        src/eap-wsc.c src/eap-wsc.h)
    target_link_libraries(test-wsc PRIVATE ell)
    add_test(NAME wsc COMMAND test-wsc)

    add_executable(test-eap-mschapv2 unit/test-eap-mschapv2.c
        src/eap-mschapv2.c src/eap-mschapv2.h
        src/eap.c src/eap.h src/eap-private.h
        src/mschaputil.c src/mschaputil.h)
    target_link_libraries(test-eap-mschapv2 PRIVATE ell)
    add_test(NAME eap-mschapv2 COMMAND test-eap-mschapv2)

    add_executable(test-sae unit/test-sae.c
        src/sae.c src/sae.h
        src/crypto.c src/crypto.h
        src/ie.c src/ie.h
        src/handshake.c src/handshake.h
        src/util.c src/util.h
        src/mpdu.c src/mpdu.h)
    target_link_libraries(test-sae PRIVATE ell)
    add_test(NAME sae COMMAND test-sae)

    add_executable(test-p2p unit/test-p2p.c
        src/wscutil.c src/wscutil.h
        src/crypto.c src/crypto.h
        src/ie.c src/ie.h
        src/util.c src/util.h
        src/p2putil.c src/p2putil.h)
    target_link_libraries(test-p2p PRIVATE ell)
    add_test(NAME p2p COMMAND test-p2p)

    add_custom_target(cert-ca-key.pem openssl genrsa -out cert-ca-key.pem 2048)

    add_custom_target(cert-ca.pem openssl req -x509 -new -nodes -extensions ca_ext
        -config "${CMAKE_CURRENT_SOURCE_DIR}/unit/gencerts.cnf"
        -subj "/O=International Union of Example Organizations/CN=Certificate issuer gui/emailADdress=ca@mail.example"
        -key cert-ca-key.pem -sha256 -days 10000 -out cert-ca.pem)
    add_dependencies(cert-ca.pem cert-ca-key.pem)

    add_custom_target(cert-server-key.pem openssl genrsa -out cert-server-key.pem)

    add_custom_target(cert-server-key-pkcs8.pem openssl pkcs8 -topk8 -nocrypt
        -in cert-server-key.pem -out cert-server-key-pkcs8.pem)
    add_dependencies(cert-server-key-pkcs8.pem cert-server-key.pem)

    add_custom_target(cert-server.csr openssl req -new -extensions cert_ext
        -config "${CMAKE_CURRENT_SOURCE_DIR}/unit/gencerts.cnf"
        -subj "/O=Foo Example Organization/CN=Foo Example Organization/emailAddress=foo@mail.example"
        -key cert-server-key.pem -out cert-server.csr)
    add_dependencies(cert-server.csr cert-server-key.pem)

    add_custom_target(cert-server.pem openssl x509 -req -extensions server_ext
        -extfile "${CMAKE_CURRENT_SOURCE_DIR}/unit/gencerts.cnf"
        -in cert-server.csr -CA cert-ca.pem
        -CAkey cert-ca-key.pem
        -CAserial cert-ca.srl
        -CAcreateserial -sha256 -days 10000 -out cert-server.pem)
    add_dependencies(cert-server.pem cert-server.csr cert-ca.pem)

    add_custom_target(cert-client-key.pem openssl genrsa -out cert-client-key.pem)

    add_custom_target(cert-client-key-pkcs8.pem openssl pkcs8 -topk8 -nocrypt
        -in cert-client-key.pem -out cert-client-key-pkcs8.pem)
    add_dependencies(cert-client-key-pkcs8.pem cert-client-key.pem)

    add_custom_target(cert-client.csr openssl req -new -extensions cert_ext
        -config "${CMAKE_CURRENT_SOURCE_DIR}/unit/gencerts.cnf"
        -subj "/O=Bar Example Organization/CN=Bar Example Organization/emailAddress=bar@mail.example"
        -key cert-client-key.pem -out cert-client.csr)
    add_dependencies(cert-client.csr cert-client-key.pem)

    add_custom_target(cert-client.pem openssl x509 -req -extensions cert_ext
        -extfile "${CMAKE_CURRENT_SOURCE_DIR}/unit/gencerts.cnf"
        -in cert-client.csr -CA cert-ca.pem
        -CAkey cert-ca-key.pem
        -CAserial cert-ca.srl
        -CAcreateserial -sha256 -days 10000 -out cert-client.pem)
    add_dependencies(cert-client.pem cert-client.csr cert-ca.pem)

    add_custom_target(tls-settings.8021x "${CMAKE_COMMAND}" -E echo "[Security]" > tls-settings.8021x
        COMMAND "${CMAKE_COMMAND}" -E echo "EAP-Method=TLS" >> tls-settings.8021x
        COMMAND "${CMAKE_COMMAND}" -E echo "EAP-Identity=abs@example.com" >> tls-settings.8021x
        COMMAND "${CMAKE_COMMAND}" -E echo "EAP-TLS-CaCert=embed:ca_cert" >> tls-settings.8021x
        COMMAND "${CMAKE_COMMAND}" -E echo "EAP-TLS-ClientCert=embed:client_cert" >> tls-settings.8021x
        COMMAND "${CMAKE_COMMAND}" -E echo "EAP-TLS-ClientKey=embed:client_key" >> tls-settings.8021x
        COMMAND "${CMAKE_COMMAND}" -E echo "[@pem@ca_cert]" >> tls-settings.8021x
        COMMAND cat cert-ca.pem >> tls-settings.8021x
        COMMAND "${CMAKE_COMMAND}" -E echo "[@pem@client_cert]" >> tls-settings.8021x
        COMMAND cat cert-client.pem >> tls-settings.8021x
        COMMAND "${CMAKE_COMMAND}" -E echo "[@pem@client_key]" >> tls-settings.8021x
        COMMAND cat cert-client-key-pkcs8.pem >> tls-settings.8021x)
    add_dependencies(tls-settings.8021x cert-ca.pem cert-client.pem cert-client-key-pkcs8.pem)
endif()
