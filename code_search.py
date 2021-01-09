import glob
import os
import re
import csv
from util import run_fast_scandir

scan_dir = './input'
output_dir = "./reports"

interesting_files = [
        "web.xml",
        "config",
        "secret",
        ".env"
        "environment"
]

# Set to empty array to search all non-binary files
source_files_extensions = []

def wildcard_wrap(value):
    return re.compile(value)
    # return ".*" + value + ".*"

patterns = [
        ["1_android_access_mode-world-readable.txt", "MODE_WORLD_READABLE"],
        ["1_android_access_mode-world-writeable.txt", "MODE_WORLD_WRITEABLE"],
        ["1_android_ssl_hostname_verifier.txt", "ALLOW_ALL_HOSTNAME_VERIFIER"],
        ["1_android_setWebContentsDebuggingEnabled.txt", "\.setWebContentsDebuggingEnabled\("],
        ["2_android_dexguar_TamperDetector.txt", "TamperDetector"],
        ["2_android_dexguar_CertificateChecker.txt", "CertificateChecker"],
        ["2_android_intents_intent-filter_registerReceiver.txt", "registerReceiver\("],
        ["2_android_webview_setAllowUniversalAccessFromFileURLs.txt", "setAllowUniversalAccessFromFileURLs"],
        ["2_android_webview_setAllowFileAccess.txt", "setAllowFileAccess"],
        ["2_android_SafetyNet.txt", "SafetyNet"],
        ["2_android_AttestationResult.txt", "AttestationResult"],
        ["3_android_access_mode-private.txt", "MODE_PRIVATE"],
        ["3_android_access_rawQuery.txt", "rawQuery\("],
        ["3_android_access_rawQueryWithFactory.txt", "rawQueryWithFactory\("],
        ["3_android_access_compileStatement.txt", "compileStatement\("],
        ["3_android_intents_intent-filter_exported.txt", "android:exported.{0,$WILDCARD_SHORT}true"],
        ["3_android_intents_intent-filter_sendBroadcast.txt", "sendBroadcast\("],
        ["3_android_ssl_x509TrustManager.txt", "X509TrustManager"],
        ["3_android_ssl_trustStrategy.txt", "implements TrustStrategy"],
        ["3_android_setUserAuthenticationValidityDurationSeconds.txt", "setUserAuthenticationValidityDurationSeconds"],
        ["3_android_contentResolver.txt", "ContentResolver"],
        ["3_android_webview_setAllow.txt", "\.setAllow\("],
        ["3_android_system_path.txt", "/system"],
        ["3_android_superuser_apk.txt", "Superuser.apk"],
        ["3_android_supersu.txt", "supersu"],
        ["3_android_ro.secure.txt", "ro\.secure"],
        ["3_android_isDebuggerConnected.txt", "isDebuggerConnected"],
        ["4_android_intents_startActivity.txt", "startActivity\("],
        ["4_android_intents_getIntent.txt", "\.getIntent\("],
        ["4_android_intents_getData.txt", "\.getData\("],
        ["4_android_uri_parse.txt", "Uri.parse\("],
        ["4_android_intents_setData.txt", "\.setData\("],
        ["4_android_intents_RunningAppProcessInfo.txt", "RunningAppProcessInfo"],
        ["4_android_AndroidKeyStore.txt", "AndroidKeyStore"],
        ["4_android_webview_loadData.txt", "\.loadData\("],
        ["4_android_webview_loadUrl.txt", "\.loadUrl\("],
        ["4_android_backupAgent.txt", "BackupAgent"],
        ["5_android_access_openFile.txt", "\.openFile\("],
        ["5_android_access_openAssetFile.txt", "\.openAssetFile\("],
        ["5_android_access_openOrCreate.txt", "\.openOrCreate"],
        ["5_android_access_getDatabase.txt", "\.getDatabase\("],
        ["5_android_access_openDatabase.txt", "\.openDatabase\("],
        ["5_android_access_getShared.txt", "\.getShared"],
        ["5_android_access_getCache.txt", "\.getCache"],
        ["5_android_access_getCodeCache.txt", "\.getCodeCache"],
        ["5_android_access_getExternalCache.txt", "\.getExternalCache"],
        ["5_android_access_getExternalFile.txt", "\.getExternalFile"],
        ["5_android_access_getExternalMedia.txt", "\.getExternalMedia"],
        ["5_android_access_query.txt", "query\("],
        ["5_android_keyStorage.txt", "KeyStore"],
        ["5_android_FLAG_ACTIVITY_NEW_TASK.txt", "FLAG_ACTIVITY_NEW_TASK"],
        ["6_android_logging_error.txt", "Log\.e\("],
        ["6_android_logging_warning.txt", "Log\.w\("],
        ["6_android_logging_information.txt", "Log\.i\("],
        ["6_android_logging_debug.txt", "Log\.d\("],
        ["6_android_logging_verbose.txt", "Log\.v\("],
        ["3_angularjs_sceprovider_enabled.txt", "sceProvider\.enabled\("],

        ["2_c_insecure_c_functions_memcpy.txt", "memcpy\("],
        ["2_c_insecure_c_functions_memset.txt", "memset\("],
        ["2_c_insecure_c_functions_strcat_strncat.txt", "strn?cat\("],
        ["2_c_insecure_c_functions_strcpy_strncpy.txt", "strn?cpy\("],
        ["2_c_insecure_c_functions_sprintf_snprintf.txt", "sn?printf\("],
        ["2_c_insecure_c_functions_fprintf_fnprintf.txt", "fn?printf\("],
        ["2_c_insecure_c_functions_fscanf_scanf.txt", "f?scanf\("],
        ["2_c_insecure_c_functions_gets.txt", "gets\("],
        ["2_c_random.txt", "random\("],
        ["4_c_malloc.txt", "malloc\("],
        ["4_c_realloc.txt", "realloc\("],

        ["1_cryptocred_certificates_and_keys_narrow_private-key.txt", "PRIVATE KEY"],
        ["1_cryptocred_net_user_add.txt", "net user.{0,$WILDCARD_LONG}/add"],
        ["2_cryptocred_encryption_key.txt", "encrypt.{0,$WILDCARD_SHORT}key"],
        ["2_cryptocred_dev_random.txt", "/dev/u?random"],
        ["2_cryptocred_certificates_and_keys_narrow_begin-certificate.txt", "BEGIN CERTIFICATE"],
        ["2_cryptocred_certificates_and_keys_narrow_public-key.txt", "PUBLIC KEY"],
        ["2_cryptocred_default_password.txt", "default.?password"],
        ["2_cryptocred_credentials_narrow.txt", "creden.{0,$WILDCARD_SHORT}=.?[\"'\d]"],
        ["2_cryptocred_passcode_narrow.txt", "pass.?code.{0,$WILDCARD_SHORT}=.?[\"'\d]"],
        ["2_cryptocred_passphrase_narrow.txt", "pass.?phrase.{0,$WILDCARD_SHORT}=.?[\"'\d]"],
        ["2_cryptocred_secret_narrow.txt", "se?3?cre?3?t.{0,$WILDCARD_SHORT}=.?[\"'\d]"],
        ["2_cryptocred_pin_code_narrow.txt", "pin.?code.{0,$WILDCARD_SHORT}=.?[\"'\d]"],
        ["3_cryptocred_crypt_call.txt", "crypt\("],
        ["3_cryptocred_ciphers_rot32.txt", "ROT32"],
        ["3_cryptocred_ciphers_rc2.txt", "RC2"],
        ["3_cryptocred_ciphers_rc4.txt", "RC4"],
        ["3_cryptocred_ciphers_crc32.txt", "CRC32"],
        ["3_cryptocred_ciphers_des.txt", "DES"],
        ["3_cryptocred_ciphers_md2.txt", "MD2"],
        ["3_cryptocred_ciphers_md5.txt", "MD5"],
        ["3_cryptocred_ciphers_sha1_uppercase.txt", "SHA-?1"],
        ["3_cryptocred_ciphers_sha1_lowercase.txt", "sha-?1"],
        ["3_cryptocred_ciphers_sha256.txt", "SHA-?256"],
        ["3_cryptocred_ciphers_sha512.txt", "SHA-?512"],
        ["3_cryptocred_ciphers_PBKDF2.txt", "PBKDF2"],
        ["3_cryptocred_ciphers_hmac.txt", "HMAC"],
        ["3_cryptocred_ciphers_ntlm.txt", "NTLM"],
        ["3_cryptocred_ciphers_kerberos.txt", "kerberos"],
        ["3_cryptocred_password.txt", "pass.?wo?r?d"],
        ["3_cryptocred_encoded_pw.txt", "encoded.?pw"],
        ["3_cryptocred_ssl_usage_require-ssl.txt", "require.{0,$WILDCARD_SHORT}SSL"],
        ["3_cryptocred_ssl_usage_use-ssl.txt", "use.{0,$WILDCARD_SHORT}SSL"],
        ["3_cryptocred_tls_usage_require-tls.txt", "require.{0,$WILDCARD_SHORT}TLS"],
        ["3_cryptocred_tls_usage_use-tls.txt", "use.{0,$WILDCARD_SHORT}TLS"],
        ["4_cryptocred_certificates_and_keys_wide_begin-certificate.txt", "BEGIN.{0,$WILDCARD_SHORT}CERTIFICATE"],
        ["4_cryptocred_certificates_and_keys_wide_private-key.txt", "PRIVATE.{0,$WILDCARD_SHORT}KEY"],
        ["4_cryptocred_certificates_and_keys_wide_public-key.txt", "PUBLIC.{0,$WILDCARD_SHORT}KEY"],
        ["4_cryptocred_pw_capitalcase.txt", "PW.?="],
        ["4_cryptocred_pwd_uppercase.txt", "PWD"],
        ["4_cryptocred_pwd_lowercase.txt", "pwd"],
        ["4_cryptocred_pwd_capitalcase.txt", "Pwd"],
        ["4_cryptocred_credentials_wide.txt", "creden"],
        ["4_cryptocred_passcode_wide.txt", "pass.?code"],
        ["4_cryptocred_passphrase_wide.txt", "pass.?phrase"],
        ["4_cryptocred_secret_wide.txt", "se?3?cre?3?t"],
        ["4_cryptocred_pin_code_wide.txt", "pin.?code"],
        ["4_cryptocred_proxy-authorization.txt", "Proxy.?Authoris?z?ation"],
        ["4_cryptocred_authorization.txt", "Authori[sz]ation"],
        ["4_cryptocred_authentication.txt", "Authentication"],
        ["5_cryptocred_hash.txt", "hash(?!(table|map|set|code))"],
        ["5_cryptocred_salt1.txt", "[Ss]alt"],
        ["5_cryptocred_salt2.txt", "SALT"],
        ["5_cryptocred_hexdigest.txt", "hex.?digest"],

        ["1_dotnet_stringformat_sqli.txt", "string\.Format\(.{0,$WILDCARD_SHORT}SELECT.{0,$WILDCARD_LONG}FROM"],
        ["2_dotnet_validate_request.txt", "ValidateRequest"],
        ["2_dotnet_unsafe_declaration.txt", "unsafe\s"],
        ["2_dotnet_marshal.txt", "Marshal"],
        ["2_dotnet_LayoutKind_explicit.txt", "LayoutKind\.Explicit"],
        ["2_dotnet_SuppressUnmanagedCodeSecurityAttribute.txt", "SuppressUnmanagedCodeSecurityAttribute"],
        ["3_dotnet_viewState.txt", "EnableViewState"],
        ["3_dotnet_console_WriteLine.txt", "Console\.WriteLine"],
        ["3_dotnet_TripleDESCryptoServiceProvider.txt", "TripleDESCryptoServiceProvider"],
        ["3_dotnet_unchecked.txt", "unchecked"],
        ["3_dotnet_ReflectionPermission.txt", "ReflectionPermission"],
        ["3_dotnet_htmlinputhidden.txt", "htmlinputhidden"],
        ["3_dotnet_requestEncoding.txt", "requestEncoding"],
        ["3_dotnet_CustomErrors.txt", "CustomErrors"],
        ["3_dotnet_pipedinputstream.txt", "pipedinputstream"],
        ["3_dotnet_objectstream.txt", "objectstream"],
        ["3_dotnet_AuthenticateRequest.txt", "AuthenticateRequest"],
        ["3_dotnet_AuthorizeRequest.txt", "AuthorizeRequest"],
        ["3_dotnet_Session_OnStart.txt", "Session_OnStart"],
        ["3_dotnet_SecurityCriticalAttribute.txt", "SecurityCriticalAttribute"],
        ["3_dotnet_SecurityPermission.txt", "SecurityPermission"],
        ["3_dotnet_SecurityAction.txt", "SecurityAction"],
        ["3_dotnet_IntPtr.txt", "IntPtr"],
        ["3_dotnet_SqlClient.txt", "SqlClient"],
        ["3_dotnet_UnmanagedCode.txt", "UnmanagedCode"],
        ["3_dotnet_Serializable.txt", "Serializable"],
        ["3_dotnet_CharSet_Auto.txt", "CharSet\.Auto"],
        ["3_dotnet_DllImport.txt", "DllImport"],
        ["4_dotnet_ObjectInputStream.txt", "ObjectInputStream"],

        ["1_general_uris_auth_info_narrow.txt", "://[^ ]{1,$WILDCARD_SHORT}:[^ ]{1,$WILDCARD_SHORT}@"],
        ["1_general_con_str_sql_password.txt", ";Password="],
        ["1_general_con_str_sql_pwd.txt", ";Pwd="],
        ["2_general_html_templating.txt", "<%="],
        ["2_general_superuser.txt", "super.?user"],
        ["2_general_su-binary.txt", "su.{0,3}binary"],
        ["2_general_sudo.txt", "sudo\s"],
        ["2_general_uris_auth_info_wide.txt", "[^ ]{1,$WILDCARD_SHORT}:[^ ]{1,$WILDCARD_SHORT}@"],
        ["2_general_jdbc_uri.txt", "jdbc:"],
        ["2_general_con_str_sqlserver.txt", "Server=.{0,$WILDCARD_SHORT};Database="],
        ["2_general_con_str_localdb.txt", ";Integrated.Security="],
        ["2_general_sql_injection.txt", "sql.{0,$WILDCARD_SHORT}injection"],
        ["2_general_xss_uppercase.txt", "XSS"],
        ["2_general_xss_regularcase.txt", "Xss"],
        ["2_general_xss_lowercase.txt", "xss"],
        ["2_general_hacking_techniques_clickjacking.txt", "click.{0,$WILDCARD_SHORT}jacking"],
        ["2_general_hacking_techniques_xsrf.txt", "xsrf"],
        ["2_general_hacking_techniques_csrf.txt", "csrf"],
        ["2_general_hacking_techniques_buffer-overflow.txt", "buffer.{0,$WILDCARD_SHORT}overflow"],
        ["2_general_hacking_techniques_integer-overflow.txt", "integer.{0,$WILDCARD_SHORT}overflow"],
        ["2_general_obfuscation.txt", "obfuscat"],
        ["2_general_sql_create_login.txt", "CREATE LOGIN"],
        ["2_general_sql_pwdcompare.txt", "PWDCOMPARE\("],
        ["2_general_sql_loginproperty.txt", "LOGINPROPERTY\("],
        ["2_general_sql_sp_addlogin.txt", "sp_addlogin"],
        ["2_general_sql_with_password.txt", "WITH PASSWORD ="],
        ["2_general_sql_rmtpassword.txt", "@rmtpassword"],
        ["3_general_exec_narrow.txt", "exec\s{0,$WILDCARD_SHORT}\("],
        ["3_general_eval_narrow.txt", "eval\s{0,$WILDCARD_SHORT}\("],
        ["3_general_syscall_narrow.txt", "sys.?call\s{0,$WILDCARD_SHORT}\("],
        ["3_general_system_narrow.txt", "system\s{0,$WILDCARD_SHORT}\("],
        ["3_general_pipeline_narrow.txt", "pipeline\s{0,$WILDCARD_SHORT}\("],
        ["3_general_popen_narrow.txt", "popen\s{0,$WILDCARD_SHORT}\("],
        ["3_general_spawn_narrow.txt", "spawn\s{0,$WILDCARD_SHORT}\("],
        ["3_general_session_timeout.txt", "session-?\s?time-?\s?out"],
        ["3_general_setcookie.txt", "setcookie"],
        ["3_general_serialise.txt", "seriali[sz]e"],
        ["3_general_creditcard.txt", "credit.?card"],
        ["3_general_non_ssl_uris_ftp.txt", "ftp://"],
        ["3_general_non_ssl_uris_socket.txt", "socket://"],
        ["3_general_non_ssl_uris_imap.txt", "imap://"],
        ["3_general_non_ssl_uris_file.txt", "file://"],
        ["3_general_con_str_trusted_sqlserver.txt", ";Trusted_Connection="],
        ["3_general_scheme.txt", "scheme"],
        ["3_general_schema.txt", "schema"],
        ["3_general_wsdl.txt", "wsdl"],
        ["3_general_webview.txt", "webview"],
        ["3_general_directory_listing.txt", "directory.{0,$WILDCARD_SHORT}listing"],
        ["3_general_backticks.txt", "\`.{2,$WILDCARD_LONG}\`"],
        ["3_general_sql_select.txt", "SELECT\s.{0,$WILDCARD_LONG}FROM"],
        ["3_general_sql_insert.txt", "INSERT.{0,$WILDCARD_SHORT}INTO"],
        ["3_general_sql_delete.txt", "DELETE.{0,$WILDCARD_LONG}WHERE"],
        ["3_general_sql_sqlcipher.txt", "sqlcipher"],
        ["3_general_base64_word.txt", "base64"],
        ["3_general_swear_stupid.txt", "stupid"],
        ["3_general_swear_fuck.txt", "fuck"],
        ["3_general_swear_shit.txt", "shit"],
        ["3_general_swear_crap.txt", "crap"],
        ["3_general_ip-addresses.txt", "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"],
        ["3_general_referer.txt", "referer"],
        ["3_general_sqli_generic.txt", "from\s.{0,$WILDCARD_LONG}\swhere\s.{0,$WILDCARD_LONG}"],
        ["3_general_ldap_generic.txt", "\(&\(.{0,$WILDCARD_SHORT}="],
        ["3_general_sleep_generic.txt", "sleep"],
        ["4_general_deny.txt", "[Dd]eny"],
        ["4_general_exec_wide.txt", "exec"],
        ["4_general_eval_wide.txt", "eval"],
        ["4_general_syscall_wide.txt", "sys.?call"],
        ["4_general_system_wide.txt", "system"],
        ["4_general_pipeline_wide.txt", "pipeline"],
        ["4_general_popen_wide.txt", "popen"],
        ["4_general_spawn_wide.txt", "spawn"],
        ["4_general_chgrp.txt", "chgrp"],
        ["4_general_chown.txt", "chown"],
        ["4_general_chmod.txt", "chmod"],
        ["4_general_session_timeout.txt", "time-?\s?out"],
        ["4_general_relative_paths.txt", "\./"],
        ["4_general_debugger.txt", "debugger"],
        ["4_general_kernel.txt", "Kernel"],
        ["4_general_hack.txt", "hack"],
        ["4_general_crack.txt", "crack"],
        ["4_general_trick.txt", "trick"],
        ["4_general_exploit.txt", "xploit"],
        ["4_general_bypass.txt", "bypass"],
        ["4_general_backdoor.txt", "back.{0,$WILDCARD_SHORT}door"],
        ["4_general_backd00r.txt", "back.{0,$WILDCARD_SHORT}d00r"],
        ["4_general_fake.txt", "fake"],
        ["4_general_https_urls.txt", "https://"],
        ["4_general_http_urls.txt", "http://"],
        ["4_general_hidden.txt", "hidden"],
        ["4_general_sql_sqlite.txt", "sqlite"],
        ["4_general_sql_cursor.txt", "cursor"],
        ["4_general_base64_content.txt", "(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)"],
        ["4_general_base64_urlsafe.txt", "(?:[A-Za-z0-9_-]{4}){2,}(?:[A-Za-z0-9_-]{2}==|[A-Za-z0-9_-]{3}=)"],
        ["5_general_update.txt", "update"],
        ["5_general_backup.txt", "backup"],
        ["5_general_email.txt", "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}\b"],
        ["5_general_todo_capital_and_lower.txt", "[Tt]odo"],
        ["5_general_todo_uppercase.txt", "TODO"],
        ["5_general_workaround.txt", "workaround"],
        ["5_general_gpl1.txt", "GNU\sGPL"],
        ["5_general_gpl2.txt", "GPLv2"],
        ["5_general_gpl3.txt", "GPLv3"],
        ["5_general_gpl4.txt", "GPL\sVersion"],
        ["5_general_gpl5.txt", "General\sPublic\sLicense"],

        ["2_hmac_with_user_input.txt", "hash_hmac\s{0,$WILDCARD_SHORT}\(.{0,$WILDCARD_LONG}\\\$_"],

        ["4_html_upload_form_tag.txt", "multipart/form-data"],
        ["4_html_upload_input_tag.txt", "type=.?file"],
        ["6_html_autocomplete.txt", "autocomplete"],

        ["2_ios_kCFStreamSSLAllowsExpiredCertificates.txt", "kCFStreamSSLAllowsExpiredCertificates"],
        ["2_ios_kCFStreamSSLAllowsExpiredRoots.txt", "kCFStreamSSLAllowsExpiredRoots"],
        ["2_ios_kCFStreamSSLAllowsAnyRoot.txt", "kCFStreamSSLAllowsAnyRoot"],
        ["2_ios_kCFStreamSSLValidatesCertificateChain.txt", "kCFStreamSSLValidatesCertificateChain"],
        ["2_ios_kSecTrustOptionAllowExpired.txt", "kSecTrustOptionAllowExpired"],
        ["2_ios_kSecTrustOptionAllowExpiredRoot.txt", "kSecTrustOptionAllowExpiredRoot"],
        ["2_ios_NSAllowsArbitraryLoads.txt", "NSAllowsArbitraryLoads"],
        ["2_ios_sqlite3_exec.txt", "sqlite3_exec\("],
        ["2_ios_fts3_tokenizer.txt", "fts3_tokenizer"],
        ["2_ios_allowLocalhostRequest.txt", "allowLocalhostRequest"],
        ["2_ios_GTM_ALLOW_INSECURE_REQUESTS.txt", "GTM_ALLOW_INSECURE_REQUESTS"],
        ["2_ios_registerForRemoteNotificationTypes.txt", "registerForRemoteNotificationTypes"],
        ["2_ios_CFStringCreateWithFormat.txt", "CFStringCreateWithFormat"],
        ["3_ios_loadHTMLString.txt", "loadHTMLString"],
        ["3_ios_stringByEvaluatingJavaScriptFromString.txt", "stringByEvaluatingJavaScriptFromString"],
        ["3_ios_canAuthenticateAgainstProtectionSpace.txt", "canAuthenticateAgainstProtectionSpace"],
        ["3_ios_didReceiveAuthenticationChallenge.txt", "didReceiveAuthenticationChallenge"],
        ["3_ios_willSendRequestForAuthenticationChallenge.txt", "willSendRequestForAuthenticationChallenge"],
        ["3_ios_continueWithoutCredentialForAuthenticationChallenge.txt", "continueWithoutCredentialForAuthenticationChallenge"],
        ["3_ios_ValidatesSecureCertificate.txt", "ValidatesSecureCertificate"],
        ["3_ios_setValidatesSecureCertificate.txt", "setValidatesSecureCertificate"],
        ["3_ios_setAllowsAnyHTTPSCertificate.txt", "setAllowsAnyHTTPSCertificate"],
        ["3_ios_NSHTTPCookieAcceptPolicy.txt", "NSHTTPCookieAcceptPolicy"],
        ["3_ios_file_access_nsfileprotection.txt", "NSFileProtection"],
        ["3_ios_keychain_kSecAttrAccessibleWhenUnlocked.txt", "kSecAttrAccessibleWhenUnlocked[^T]"],
        ["3_ios_keychain_kSecAttrAccessibleAfterFirstUnlock.txt", "kSecAttrAccessibleAfterFirstUnlock[^T]"],
        ["3_ios_keychain_kSecAttrAccessibleWhenPasscodeSet.txt", "kSecAttrAccessibleWhenPasscodeSet[^T]"],
        ["3_ios_keychain_kSecAttrAccessibleAlways.txt", "kSecAttrAccessibleAlways[^T]"],
        ["3_ios_keychain_kSecAttrSynchronizable.txt", "kSecAttrSynchronizable"],
        ["3_ios_kCFStreamPropertySSLSettings.txt", "kCFStreamPropertySSLSettings"],
        ["3_ios_kCFStreamSSLPeerName.txt", "kCFStreamSSLPeerName"],
        ["3_ios_kSecTrustOptionImplicitAnchors.txt", "kSecTrustOptionImplicitAnchors"],
        ["3_ios_NSStreamSocketSecurityLevel.txt", "NSStreamSocketSecurityLevel"],
        ["3_ios_sourceApplication.txt", "sourceApplication:"],
        ["3_ios_SecRandomCopyBytes.txt", "SecRandomCopyBytes"],
        ["3_ios_allowScreenShot.txt", "allowScreenShot"],
        ["3_ios_UIPasteboardNameGeneral.txt", "UIPasteboardNameGeneral"],
        ["3_ios_secureTextEntry.txt", "secureTextEntry"],
        ["3_ios_allowedInsecureSchemes.txt", "allowedInsecureSchemes"],
        ["3_ios_syslog.txt", "syslog\("],
        ["3_ios_UnsafePointer.txt", "UnsafePointer"],
        ["3_ios_UnsafeMutablePointer.txt", "UnsafeMutablePointer"],
        ["3_ios_UnsafeCollection.txt", "UnsafeCollection"],
        ["4_ios_file_access_fileURLWithPath.txt", "fileURLWithPath"],
        ["4_ios_file_access_NSURL.txt", "NSURL"],
        ["4_ios_file_access_NSURLConnection.txt", "NSURLConnection"],
        ["4_ios_file_access_writeToFile.txt", "writeToFile"],
        ["4_ios_loadRequest.txt", "loadRequest"],
        ["4_ios_file_access_nsfilemanager.txt", "NSFileManager"],
        ["4_ios_file_access_nspersistantstorecoordinator.txt", "NSPersistantStoreCoordinator"],
        ["4_ios_keychain_ksecattraccessible.txt", "kSecAttrAccessible"],
        ["4_ios_keychain_secitemadd.txt", "SecItemAdd"],
        ["4_ios_keychain_SecItemUpdate.txt", "SecItemUpdate"],
        ["4_ios_keychain_SecItemCopyMatching.txt", "SecItemCopyMatching"],
        ["4_ios_keychain_KeychainItemWrapper.txt", "KeychainItemWrapper"],
        ["4_ios_willCacheResponse.txt", "willCacheResponse"],
        ["4_ios_CFFTPStream.txt", "CFFTPStream"],
        ["4_ios_NSStreamin.txt", "NSStreamin"],
        ["4_ios_NSXMLParser.txt", "NSXMLParser"],
        ["4_ios_UIPasteboardName.txt", "UIPasteboardName"],
        ["4_ios_FTPURL.txt", "FTPURL"],
        ["4_ios_IOBluetooth.txt", "IOBluetooth"],
        ["4_ios_string_format_initWithFormat_narrow.txt", "initWithFormat:[^@]"],
        ["4_ios_string_format_informativeTextWithFormat_narrow.txt", "informativeTextWithFormat:[^@]"],
        ["4_ios_string_format_format_narrow.txt", "format:[^@]"],
        ["4_ios_string_format_stringWithFormat_narrow.txt", "stringWithFormat:[^@]"],
        ["4_ios_string_format_stringByAppendingFormat_narrow.txt", "stringByAppendingFormat:[^@]"],
        ["4_ios_string_format_appendFormat_narrow.txt", "appendFormat:[^@]"],
        ["4_ios_string_format_alertWithMessageText_narrow.txt", "alertWithMessageText:[^@]"],
        ["4_ios_string_format_predicateWithFormat_narrow.txt", "predicateWithFormat:[^@]"],
        ["4_ios_string_format_NSRunAlertPanel_narrow.txt", "NSRunAlertPanel:[^@]"],
        ["4_ios_CFBundleDocumentTypes.txt", "CFBundleDocumentTypes"],
        ["4_ios_CFBundleURLTypes.txt", "CFBundleURLTypes"],
        ["4_ios_sqlite3_prepare.txt", "sqlite3_prepare"],
        ["4_ios_CFDataRef.txt", "CFDataRef"],
        ["4_ios_CFStringRef.txt", "CFStringRef"],
        ["4_ios_NSString.txt", "NSString"],
        ["4_ios_CFStringAppendFormat.txt", "CFStringAppendFormat"],
        ["5_ios_file_access_nsfile.txt", "NSFile"],
        ["5_ios_writeToUrl.txt", "writeToUrl"],
        ["5_ios_UIWebView.txt", "UIWebView"],
        ["5_ios_shouldStartLoadWithRequest.txt", "shouldStartLoadWithRequest"],
        ["5_ios_file_access_nsdata.txt", "NSData"],
        ["5_ios_keychain_security_h.txt", "Security\.h"],
        ["5_ios_CFStream.txt", "CFStream"],
        ["5_ios_CFHTTP.txt", "CFHTTP"],
        ["5_ios_CFNetServices.txt", "CFNetServices"],
        ["5_ios_string_format_initWithFormat_wide.txt", "initWithFormat:"],
        ["5_ios_string_format_informativeTextWithFormat_wide.txt", "informativeTextWithFormat:"],
        ["5_ios_string_format_format_wide.txt", "format:"],
        ["5_ios_string_format_stringWithFormat_wide.txt", "stringWithFormat:"],
        ["5_ios_string_format_stringByAppendingFormat_wide.txt", "stringByAppendingFormat:"],
        ["5_ios_string_format_appendFormat_wide.txt", "appendFormat:"],
        ["5_ios_string_format_alertWithMessageText_wide.txt", "alertWithMessageText:"],
        ["5_ios_string_format_predicateWithFormat_wide.txt", "predicateWithFormat:"],
        ["5_ios_string_format.txt", ":format"],
        ["5_ios_string_format_NSRunAlertPanel_wide.txt", "NSRunAlertPanel:"],
        ["5_ios_string_format_url_handler_handleOpenURL.txt", "handleOpenURL"],
        ["5_ios_string_format_url_handler_openURL.txt", "openURL"],
        ["5_ios_NSCoding.txt", "NSCoding"],
        ["5_ios_CFBundle.txt", "CFBundle"],
        ["5_ios_NSBundle.txt", "NSBundle"],
        ["5_ios_NSKeyedUnarchiverDelegate.txt", "NSKeyedUnarchiverDelegate"],
        ["5_ios_didDecodeObject.txt", "didDecodeObject"],
        ["5_ios_awakeAfterUsingCoder.txt", "awakeAfterUsingCoder"],
        ["6_ios_NSLog.txt", "NSLog\("],

        ["1_java_jsp_property_to_html_xss.txt", "<%=\s{0,$WILDCARD_SHORT}[A-Za-z0-9_]{1,$WILDCARD_LONG}.get[A-Za-z0-9_]{1,$WILDCARD_LONG}\("],
        ["1_java_jsp_out_print_to_html_xss2.txt", "out.printl?n?\(\"<.{1,$WILDCARD_LONG}\+.{1,$WILDCARD_LONG}\);"],
        ["2_java_crypto_new-SecretKeySpec.txt", "new\sSecretKeySpec\("],
        ["2_java_crypto_new-PBEKeySpec_str.txt", "new\sPBEKeySpec\(""],
        ["2_java_string_comparison_equals_hash.txt", "equals\(.{0,$WILDCARD_SHORT}[Hh][Aa][Ss][Hh]"],
        ["2_java_string_comparison_equalsIgnoreCase_hash.txt", "equalsIgnoreCase\(.{0,$WILDCARD_SHORT}[Hh][Aa][Ss][Hh]"],
        ["2_java_jsp_xss_escape.txt", "escape\s{0,$WILDCARD_SHORT}=\s{0,$WILDCARD_SHORT}'?\"?\s{0,$WILDCARD_SHORT}false"],
        ["2_java_jsp_xss_escapexml.txt", "escapeXml\s{0,$WILDCARD_SHORT}=\s{0,$WILDCARD_SHORT}'?\"?\s{0,$WILDCARD_SHORT}false"],
        ["2_java_spring_stripUnsafeHTML.txt", "stripUnsafeHTML"],
        ["2_java_spring_stripEncodeUnsafeHTML.txt", "stripEncodeUnsafeHTML"],
        ["2_java_struts_deactivated_validation.txt", "validate\s{0,$WILDCARD_SHORT}=\s{0,$WILDCARD_SHORT}'?\"?false"],
        ["2_java_struts_devMode.txt", "struts\.devMode"],
        ["3_java_crypto_new-PBEKeySpec.txt", "new\sPBEKeySpec\("],
        ["3_java_crypto_generateKey.txt", "\.generateKey\("],
        ["3_java_format_string1.txt", "String\.format\(\s{0,$WILDCARD_SHORT}\"[^\"]{1,$WILDCARD_LONG}\"\s{0,$WILDCARD_SHORT}\+"],
        ["3_java_servlet_setMaxInactiveInterval.txt", "setMaxInactiveInterval\("],
        ["3_java_ssl_checkValidity.txt", "\.checkValidity\("],
        ["3_java_checkServerTrusted.txt", "checkServerTrusted\("],
        ["3_java_getPeerCertificates.txt", "getPeerCertificates\("],
        ["3_java_getPeerCertificateChain.txt", "getPeerCertificateChain\("],
        ["3_java_jsp_file_upload.txt", "<s:file\s"],
        ["3_java_spring_mass_assignment.txt", "DataBinder\.setAllowedFields"],
        ["4_java_crypto_keygenerator-getinstance.txt", "KeyGenerator\.getInstance\("],
        ["4_java_crypto_cipher_getInstance.txt", "Cipher\.getInstance\("],
        ["4_java_crypto_messagedigest.txt", "messagedigest"],
        ["4_java_crypto_keypairgenerator.txt", "KeyPairGenerator\("],
        ["4_java_http_setHeader.txt", "\.setHeader\("],
        ["4_java_http_sendRedirect.txt", "\.sendRedirect\("],
        ["4_java_http_addHeader.txt", "\.addHeader\("],
        ["4_java_http_getHeaders.txt", "\.getHeaders\("],
        ["4_java_http_getCookies.txt", "\.getCookies\("],
        ["4_java_http_getRemoteHost.txt", "\.getRemoteHost\("],
        ["4_java_http_getRemoteUser.txt", "\.getRemoteUser\("],
        ["4_java_http_isSecure.txt", "\.isSecure\("],
        ["4_java_http_getRequestedSessionId.txt", "\.getRequestedSessionId\("],
        ["4_java_format_string2.txt", "String\.format\(\s{0,$WILDCARD_SHORT}[^\"]"],
        ["4_java_javax-validation.txt", "javax.validation"],
        ["4_java_jsp_redirect.txt", "\.sendRedirect\("],
        ["4_java_jsp_forward_1.txt", "\.forward\("],
        ["4_java_jsp_forward_2.txt", ":forward"],
        ["4_java_jsp_property_to_html_xss.txt", "\.getParameter\("],
        ["4_java_spring_requestMapping.txt", "@RequestMapping\("],
        ["4_java_spring_servletMapping.txt", "<servlet-mapping>"],
        ["5_java_crypto_random.txt", "new Random\("],
        ["5_java_math_random.txt", "Math.random\("],
        ["5_java_sql_execute.txt", "execute.{0,$WILDCARD_SHORT}\("],
        ["5_java_sql_addBatch.txt", "addBatch\("],
        ["5_java_sql_prepareStatement.txt", "prepareStatement\("],
        ["5_java_http_addCookie.txt", "\.addCookie\("],
        ["5_java_http_getContentType.txt", "\.getContentType\("],
        ["5_java_http_getLocalName.txt", "\.getLocalName\("],
        ["5_java_ProcessBuilder.txt", "ProcessBuilder"],
        ["5_java_persistent_columns_in_database.txt", "@Column\("],
        ["5_java_persistent_tables_in_database.txt", "@Table\("],
        ["5_java_SSLSocketFactory.txt", "SSLSocketFactory"],
        ["5_java_runtime_exec_1.txt", "getRuntime\(\)\.exec\("],
        ["5_java_runtime_exec_2.txt", "Process.{0,$WILDCARD_SHORT}\.exec\("],
        ["5_java_setAttribute.txt", "\.setAttribute\("],
        ["5_java_StreamTokenizer.txt", "StreamTokenizer"],
        ["5_java_getResourceAsStream.txt", "getResourceAsStream"],
        ["6_java_string_comparison_equals.txt", "equals\("],
        ["6_java_string_comparison_equalsIgnoreCase.txt", "equalsIgnoreCase\("],
        ["6_java_http_getParameter.txt", "\.getParameter.{0,$WILDCARD_SHORT}\("],
        ["6_java_persistent_beans.txt", "@Entity|@ManyToOne|@OneToMany|@OneToOne|@Table|@Column"],
        ["6_java_confidential_data_in_strings_password.txt", "string .{0,$WILDCARD_SHORT}password"],
        ["6_java_confidential_data_in_strings_secret.txt", "string .{0,$WILDCARD_SHORT}secret"],
        ["6_java_confidential_data_in_strings_key.txt", "string .{0,$WILDCARD_SHORT}key"],
        ["6_java_confidential_data_in_strings_cvv.txt", "string .{0,$WILDCARD_SHORT}cvv"],
        ["6_java_confidential_data_in_strings_user.txt", "string .{0,$WILDCARD_SHORT}user"],
        ["6_java_confidential_data_in_strings_passcode.txt", "string .{0,$WILDCARD_SHORT}passcode"],
        ["6_java_confidential_data_in_strings_passphrase.txt", "string .{0,$WILDCARD_SHORT}passphrase"],
        ["6_java_confidential_data_in_strings_pin.txt", "string .{0,$WILDCARD_SHORT}pin"],
        ["6_java_confidential_data_in_strings_credit.txt", "string .{0,$WILDCARD_SHORT}credit"],
        ["6_java_getruntime.txt", "getRuntime\("],
        ["6_java_apache_common_openProcess.txt", "openProcess\("],
        ["6_java_printStackTrace.txt", "\.printStackTrace\("],
        ["7_java_crypto_javax-crypto.txt", "javax.crypto"],
        ["7_java_crypto_bouncycastle.txt", "bouncy.{0,$WILDCARD_SHORT}castle"],
        ["7_java_io_java_net.txt", "java\.net\."],
        ["7_java_io_java_io.txt", "java\.io\."],
        ["7_java_io_javax_servlet.txt", "javax\.servlet"],
        ["7_java_io_apache_http.txt", "org\.apache\.http"],
        ["8_java_string_comparison1.txt", "toString\(\s{0,$WILDCARD_SHORT}\)\s{0,$WILDCARD_SHORT}=="],
        ["8_java_string_comparison2.txt", "==\s{0,$WILDCARD_SHORT}toString\(\s{0,$WILDCARD_SHORT}\)"],
        ["8_java_string_comparison3.txt", "==\s{0,$WILDCARD_SHORT}\""],
        ["8_java_backdoor_as_unicode.txt", "\\u00..\\u00.."],
        ["9_java_strings.txt", "\"[^\"]{4,500}\""],
        
        ["2_js_insecure_JSON_parser.txt", "Eaeflnr-u"],
        ["3_js_new_function_eval.txt", "new\sFunction.{0,$WILDCARD_SHORT}"],
        ["3_js_localStorage.txt", "localStorage"],
        ["3_js_sessionStorage.txt", "sessionStorage"],
        ["3_js_createElement_script.txt", "createElement.{0,$WILDCARD_SHORT}script"],
        ["3_js_document_domain.txt", "document.domain\s="],
        ["3_js_postMessage.txt", "postMessage\("],
        ["3_js_addEventListener_message.txt", "addEventListener.{0,$WILDCARD_SHORT}message"],
        ["3_js_AllowScriptAccess.txt", "AllowScriptAccess"],
        ["3_js_mayscript.txt", "mayscript"],
        ["4_js_dom_xss_location-hash.txt", "location\.hash"],
        ["4_js_dom_xss_location-href.txt", "location\.href"],
        ["4_js_dom_xss_location-pathname.txt", "location\.pathname"],
        ["4_js_dom_xss_location-search.txt", "location\.search"],
        ["4_js_dom_xss_appendChild.txt", "\.appendChild\("],
        ["4_js_dom_xss_document_location.txt", "document\.location"],
        ["4_js_dom_xss_window-location.txt", "window\.location"],
        ["4_js_dom_xss_document-referrer.txt", "document\.referrer"],
        ["4_js_dom_xss_document-URL.txt", "document\.URL"],
        ["4_js_dom_xss_document-write.txt", "document\.writel?n?\("],
        ["4_js_dom_xss_innerHTML.txt", "\.innerHTML\s{0,$WILDCARD_SHORT}="],
        ["4_js_react_dom_xss_dangerouslySetInnerHTML.txt", "DangerouslySetInnerHTML\s{0,$WILDCARD_SHORT}="],
        ["4_js_dom_xss_outerHTML.txt", "\.outerHTML\s{0,$WILDCARD_SHORT}="],
        ["4_js_console.txt", "console\."],
        ["4_js_postMessage.txt", "\.postMessage\("],
        
        ["4_malware_viagra.txt", "viagra"],
        ["4_malware_potenzmittel.txt", "potenzmittel"],
        ["4_malware_pharmacy.txt", "pharmacy"],
        ["4_malware_drug.txt", "drug"],
        
        ["2_mobile_root_detection_root-detection.txt", "root.{0,$WILDCARD_SHORT}detection"],
        ["2_mobile_root_detection_root-device.txt", "root.{0,$WILDCARD_SHORT}Device"],
        ["2_mobile_root_detection_isRooted.txt", "is.{0,$WILDCARD_SHORT}rooted"],
        ["2_mobile_root_detection_detectRoot.txt", "detect.{0,$WILDCARD_SHORT}root"],
        ["2_mobile_jailbreak.txt", "jail.{0,$WILDCARD_SHORT}break"],
        
        ["3_modsecurity_ctl_auditEngine.txt", "ctl:auditEngine"],
        ["3_modsecurity_ctl_ruleEngine.txt", "ctl:ruleEngine"],
        ["3_modsecurity_ctl_ruleRemoveById.txt", "ctl:ruleRemoveById"],
        ["4_modsecurity_exec.txt", "exec:"],
        ["4_modsecurity_append.txt", "append:"],
        ["4_modsecurity_SecContentInjection.txt", "SecContentInjection"],
        ["4_modsecurity_inspectFile.txt", "@inspectFile"],
        ["4_modsecurity_SecAuditEngine.txt", "SecAuditEngine"],
        ["4_modsecurity_SecAuditLogParts.txt", "SecAuditLogParts"],
        ["5_modsecurity_block.txt", "block"],
        
        ["1_php_verifypeer-verifypeer.txt", "CURLOPT_SSL_VERIFYPEER"],
        ["1_php_verifypeer-verifyhost.txt", "CURLOPT_SSL_VERIFYHOST"],
        ["1_php_gnutls-certificate-verify-peers.txt", "gnutls_certificate_verify_peers"],
        ["1_php_fsockopen.txt", "fsockopen\s{0,$WILDCARD_SHORT}\("],
        ["1_php_echo_low_volume_POST.txt", "echo.{0,$WILDCARD_LONG}\\\$_POST"],
        ["1_php_echo_low_volume_GET.txt", "echo.{0,$WILDCARD_LONG}\\\$_GET"],
        ["1_php_echo_low_volume_COOKIE.txt", "echo.{0,$WILDCARD_LONG}\\\$_COOKIE"],
        ["1_php_echo_low_volume_REQUEST.txt", "echo.{0,$WILDCARD_LONG}\\\$_REQUEST"],
        ["1_php_print_low_volume_POST.txt", "print.{0,$WILDCARD_LONG}\\\$_POST"],
        ["1_php_print_low_volume_GET.txt", "print.{0,$WILDCARD_LONG}\\\$_GET"],
        ["1_php_print_low_volume_COOKIE.txt", "print.{0,$WILDCARD_LONG}\\\$_COOKIE"],
        ["1_php_print_low_volume_REQUEST.txt", "print.{0,$WILDCARD_LONG}\\\$_REQUEST"],
        ["2_php_passthru.txt", "passthru\s{0,$WILDCARD_SHORT}\("],
        ["2_php_escapeshell.txt", "escapeshell"],
        ["2_php_fopen.txt", "fopen\s{0,$WILDCARD_SHORT}\("],
        ["3_php_proc.txt", "proc_"],
        ["3_php_file_get_contents.txt", "file_get_contents\s{0,$WILDCARD_SHORT}\("],
        ["3_php_sql_pg_query.txt", "pg_query\s{0,$WILDCARD_SHORT}\("],
        ["3_php_sql_mysqli.txt", "mysqli_.{1,$WILDCARD_SHORT}\("],
        ["3_php_sql_mysql.txt", "mysql_.{1,$WILDCARD_SHORT}\("],
        ["3_php_sql_mssql.txt", "mssql_.{1,$WILDCARD_SHORT}\("],
        ["3_php_sql_odbc_exec.txt", "odbc_exec\s{0,$WILDCARD_SHORT}\("],
        ["4_php_get.txt", "\$_GET"],
        ["4_php_post.txt", "\$_POST"],
        ["4_php_cookie.txt", "\$_COOKIE"],
        ["4_php_request.txt", "\$_REQUEST"],
        ["4_php_imagecreatefrom.txt", "imagecreatefrom"],
        ["4_php_link.txt", "link\s{0,$WILDCARD_SHORT}\("],
        ["4_php_include.txt", "include\s{0,$WILDCARD_SHORT}\("],
        ["4_php_include_once.txt", "include_once\s{0,$WILDCARD_SHORT}\("],
        ["4_php_require.txt", "require\s{0,$WILDCARD_SHORT}\("],
        ["4_php_require_once.txt", "require_once\s{0,$WILDCARD_SHORT}\("],
        ["4_php_extract.txt", "extract\s{0,$WILDCARD_SHORT}\("],
        ["5_php_mkdir.txt", "mkdir\s{0,$WILDCARD_SHORT}\("],
        ["5_php_chmod.txt", "chmod\s{0,$WILDCARD_SHORT}\("],
        ["5_php_chown.txt", "chown\s{0,$WILDCARD_SHORT}\("],
        ["5_php_rmdir.txt", "rmdir\s{0,$WILDCARD_SHORT}\("],
        ["5_php_echo_high_volume.txt", "echo"],
        ["5_php_print_high_volume.txt", "print"],
        ["5_php_rand.txt", "rand\s{0,$WILDCARD_SHORT}\("],
        ["5_php_assert.txt", "assert\s{0,$WILDCARD_SHORT}\("],
        ["5_php_preg_replace.txt", "preg_replace\s{0,$WILDCARD_SHORT}\("],
        ["6_php_type_unsafe_comparison.txt", "[^=]==[^=]"],
        ["7_php_file.txt", "file\s{0,$WILDCARD_SHORT}\("],
        
        ["2_python_subprocess_shell_true.txt", "shell=True"],
        ["2_python_shutil_copyfile.txt", "copyfile\s{0,$WILDCARD_SHORT}\("],
        ["3_python_input_function.txt", "input\s{0,$WILDCARD_SHORT}\("],
        ["3_python_assert_statement.txt", "assert\s{1,$WILDCARD_SHORT}"],
        ["3_python_float_equality_left.txt", "\d\.\d{1,$WILDCARD_SHORT}\s{1,$WILDCARD_SHORT}==\s{1,$WILDCARD_SHORT}"],
        ["3_python_float_equality_right.txt", "\s{1,$WILDCARD_SHORT}==\s{1,$WILDCARD_SHORT}\d\.\d{1,$WILDCARD_SHORT}"],
        ["3_python_float_equality_general.txt", "\s{1,$WILDCARD_SHORT}==\s{1,$WILDCARD_SHORT}"],
        ["3_python_double_underscore_general.txt", "self\.__"],
        ["3_python_double_underscore_code.txt", "__code__"],
        ["3_python_tempfile_mktemp.txt", "mktemp\s{0,$WILDCARD_SHORT}\("],
        ["3_python_shutil_move.txt", "move\s{0,$WILDCARD_SHORT}\("],
        ["3_python_yaml_import.txt", "import\s{0,$WILDCARD_SHORT}yaml"],
        ["3_python_pickle_import.txt", "import\s{0,$WILDCARD_SHORT}pickle"],
        ["3_python_pickle_from.txt", "from\s{0,$WILDCARD_SHORT}pickle"],
        ["3_python_shelve_import.txt", "import\s{0,$WILDCARD_SHORT}shelve"],
        ["3_python_shelve_from.txt", "from\s{0,$WILDCARD_SHORT}shelve"],
        ["3_python_jinja2_import.txt", "import\s{0,$WILDCARD_SHORT}jinja2"],
        ["3_python_jinja2_from.txt", "from\s{0,$WILDCARD_SHORT}jinja2"],
        ["4_python_is_object_identity_operator_left.txt", "\d\s{1,$WILDCARD_SHORT}is\s{1,$WILDCARD_SHORT}"],
        ["4_python_is_object_identity_operator_right.txt", "\s{1,$WILDCARD_SHORT}is\s{1,$WILDCARD_SHORT}\d"],
        ["4_python_is_object_identity_operator_general.txt", "\sis\s"],

        ["2_ruby_http_basic_authenticate_with.txt", "http_basic_authenticate_with"],
        ["2_ruby_yaml.txt", ":YAML"],
        ["2_ruby_load.txt", ":load"],
        ["2_ruby_load_documents.txt", ":load_documents"],
        ["2_ruby_load_stream.txt", ":load_stream"],
        ["2_ruby_parse_documents.txt", ":parse_documents"],
        ["2_ruby_parse_stream.txt", ":parse_stream"],
        ["2_ruby_show_detailed_exceptions.txt", ":show_detailed_exceptions"],
        ["2_ruby_capture.txt", ":capture"],
        ["2_ruby_protect_from_forgery.txt", "protect_from_forgery"],
        ["2_ruby_redirect_to.txt", ":redirect_to"],
        ["2_ruby_verify_authenticity_token.txt", "verify_authenticity_token"],
        ["2_ruby_validates_format_of.txt", "validates_format_of"],
        ["3_ruby_content_tag.txt", "content_tag"],

        # .NET
        
        ["BinaryFormatter", "BinaryFormatter"],
        ["SoapFormatter", "SoapFormatter"],
        ["LosFormatter", "LosFormatter"],
        ["NetDataContractSerializer", "NetDataContractSerializer"],
        ["ObjectStateFormatter", "ObjectStateFormatter"],

        ["XmlSerializer", "XmlSerializer"],
        ["DataContractSerializer", "DataContractSerializer"],
        ["NetDataContractSerializer", "NetDataContractSerializer"],
        ["FastJson", "FastJson"],
        ["FsPickler", "FsPickler"],
        ["JavaScriptSerializer", "JavaScriptSerializer"],
        ["Json.Net", "Json\.Net"],
        ["SharpSerializerBinary", "SharpSerializerBinary"],
        ["SharpSerializerXml", "SharpSerializerXml"],
        ["YamlDotNet", "YamlDotNet"],
        ["Xaml", "Xaml"],

        ["TypeNameHandling", "TypeNameHandling"],
        ["JavaScriptTypeResolver", "JavaScriptTypeResolver"],
        # AAEAAAD///// in Base64

        ["BinaryReader", "BinaryReader"],
        ["BinaryWriter", "BinaryWriter"],

        # JS
        ["document.write", "document.write\(", re.IGNORECASE],

        # Common
        ["SELECT", "SELECT", re.IGNORECASE],

        # Python
        ["yaml.load", "yaml\.load"],
        ["pickle.loads", "pickle\.loads"],
        ["pickle", "pickle"],

        # Java
        ["java_XMLdecoder", "XMLdecoder"],
        ["java_fromXML", "fromXML"],
        ["java_readObject", "readObject"],
        ["java_readObjectNodData", "readObjectNodData"],
        ["java_readResolve", "readResolve"],
        ["java_readExternal", "readExternal"],
        ["java_readUnshared", "readUnshared"],
        # Java from https://www.floyd.ch/?p=565
        ["java_crypto", "javax.crypto|bouncy.*?castle|new\sSecretKeySpec\(|messagedigest|new\sPBEKeySpec\(|\.generateKey\(|KeyGenerator\.getInstance\(|Cipher\.getInstance\(|KeyPairGenerator\(|"],
        ["", "new Random\(|Math.random\(|"]
        ["java_general_wrong_string_comparison", "==\s{0,10}\"|toString\(.{0,10}\) *==|== *toString\(.{0,10}\)|\" *==|== *\""],
        ["java_general_exec", "\.exec\("],
        ["java_general_io", "java\.net\.|java\.io\.|javax\.servlet|org\.apache\.http"],
        ["java_persistent_beans", "@Entity|@ManyToOne|@OneToMany|@OneToOne|@Table|@Column"],
        ["java_persistent_tables_and_columns_in_database", "@Table\(|@Column\("],
        ["java_confidential_data_in_strings", "string .{0,10}password|string .{0,10}secret|string .{0,10}key|string .{0,10}cvv|string .{0,10}user|string .{0,10}hash(?!(table|map|set|code))|string .{0,10}passcode|string .{0,10}passphrase|string .{0,10}user|string .{0,10}pin|string .{0,10}credit", re.IGNORECASE],
        ["","equals\(.{0,10}[Hh][Aa][Ss][Hh]|equalsIgnoreCase\(.{0,10}[Hh][Aa][Ss][Hh]"]
        ["","equals\(|equalsIgnoreCase\("]
        ["","execute.{0,10}\("]
        ["","addBatch\("]
        ["","prepareStatement\("]
        ["","\.setHeader\(|\.addHeader\(|.getHeaders("]
        ["\.addCookie\(|.getCookies("]
        ["\.sendRedirect\("]
        ["\.getRemoteHost\("]
        ["\.getRemoteUser\("]
        [ "\.isSecure\("]
        ["\.getRequestedSessionId\("]
        # Java Spring from https://www.floyd.ch/?p=565
        ["java_spring_mass_assignment", "DataBinder\.setAllowedFields"],
        
        # JSP from https://www.floyd.ch/?p=565
        ["java_jsp_xss", "escape\s*=\s*\"?\s*false|escape\s*=\s*\'?\s*false"],
        ["java_jsp_file_upload", "<s:file "]

        # Android specific from https://www.floyd.ch/?p=565
        ["android_logging", "\.printStackTrace\(|Log\.(e|w|i|d|v)\("]
        ["android_access", "MODE_|\.openFile\(|\.openOrCreate|\.getDatabase\(|\.openDatabase\(|\.getShared|\.getCache|\.getExternalCache|query\(|rawQuery\(|compileStatement\("]
        ["android_intents", "<intent-filter>|\.getIntent\(\)\.getData\(\)|RunningAppProcessInfo"]

        # iOS
        ["ios_file_access", "NSFileProtection|NSFileManager|NSPersistantStoreCoordinator|NSData"]
        ["ios_keychain", "kSecAttrAccessible|SecItemAdd|KeychainItemWrapper|Security\.h"]
        ["ios_network", "CFBundleURLSchemes|kCFStream|CFFTPStream|CFHTTP|CFNetServices|FTPURL|IOBluetooth"]
        ["ios_logging", "NSLog\("]
        ["ios_string_format_functions", "initWithFormat:|informativeTextWithFormat:|format:|stringWithFormat:|appendFormat:|predicateWithFormat:|NSRunAlertPanel"]
        ["ios_url_handler", "handleOpenURL:|openURL:"]
        # AC ED 00 05 in Hex
        # rO0 in Base64
        # application/x-java-serialized-object in Content-Type

        # PHP 
        ["global_var", "\$_"],
        ["global_globals", "\$GLOBALS"],
        ["global_var_echo", "\$_.*echo"],

        ["php_crypt_call", "crypt\("]

        ["mysql_query", "mysql_query"],
        ["sql", "\$sql"],

        ["shell_exec", "shell_exec"],
        ["system", "system"],
        ["exec", "exec"],
        ["popen", "popen"],
        ["passthru", "passthru"],
        ["proc_open", "proc_open"],
        ["pcntl_exec", "pcntl_exec"],

        ["eval", "eval"],
        ["assert", "assert"],
        ["preg_replace", "preg_replace"],
        ["create_function", "create_function"],

        ["phpinfo", "phpinfo"],
        ["debug", "debug"],

        ["file_include", "file_include"],
        ["include", "include"],
        ["require", "require"],

        ["file_get_contents", "file_get_contents"],

        # Detection
        ["HTTP_USER_AGENT", "HTTP_USER_AGENT"],
        ["header", "header\("],

        ["credential", "credential"],
        ["password", "password"],
        ["username", "username"],
        ["auth", "auth"],
        ["secret", "secret"],
        ["pass", "pass"],
        ["key", "key"],       

        ["general_email", "\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,4}\b", re.IGNORECASE]
        ["general_work_in_progress", "todo|workaround", re.IGNORECASE]
        ["general_exploit", "hack|crack|exploit|bypass|backdoor|backd00r", re.IGNORECASE]
        ["general_flag", "flag", re.IGNORECASE]
        ["https_and_http_urls", "https?://", re.IGNORECASE]
        ["no_ssl_uris", "http://|ftp://|imap://|file://"]

        ["initialisation", "malloc\(|realloc\("]
        ["insecure_c_functions", "memcpy\(|memset\(|strcat\(|strcpy\(|strncat\(|strncpy\(|sprintf\(|gets\("]

        ["keys", "default.?password|passwo?r?d|passcode|hash.?(?!(table|map|set|code))|pass.?phrase|salt|encryption.?key|encrypt.?key|BEGIN CERTIFICATE---|PRIVATE KEY---|Proxy-Authorization|pin"]
        ["root", "root.*?detection|rooted.*?Device|is.*?rooted|detect.*?root|jail.*?break"]
        ["hacking_techniques", "sql.{0,10}injection|xss|click.{0,10}jacking|xsrf|directory.{0,10}listing|buffer.{0,10}overflow|obfuscate"]
        ["backticks", "`.{2,100}`"]
        ["dom_xss", "location\.hash|location\.href|location\.pathname|location\.search|eval\(|\.appendChild\(|document\.write\(|document\.writeln\(|\.innerHTML\s*?=|\.outerHTML\s*?="]
        ["sql", "SELECT.*?FROM|INSERT.*?INTO|DELETE.*?WHERE|sqlite"]
        ["base64", "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$"]
        ["gpl", "GNU\sGPL|GPLv2|GPLv3|GPL\sVersion|General\sPublic\sLicense"]
        ["swear", "stupid|fuck|shit|crap"]


]

processes_patterns = []
for pattern in patterns:
    name = pattern[0]
    value = pattern[1]
    compiled = None
    if len(pattern) > 2: 
        params = pattern[2]
        compiled = re.compile(value, params)
    else:
        compiled = re.compile(value)
    processes_patterns.append([name, compiled])


result = []
# for x in os.walk("."):
#    for y in glob.glob(os.path.join(x[0], '*.txt'), recursive=True):
#        result.append(y)
# print(result)

subfolders, files = run_fast_scandir(scan_dir, names=interesting_files)
if len(files) > 0:
    with open('_interesting_files.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        for file in files:
            writer.writerows(file)

subfolders, files = run_fast_scandir(scan_dir, ext=source_files_extensions)

data = {}
for pattern in processes_patterns:
    data[pattern[1].pattern] = []

for foundFile in files:
    try:
        prevLine = ""
        for i, line in enumerate(open(foundFile)):
            for pattern in processes_patterns:
                for match in re.finditer(pattern[1], line):
                    print('Found pattern %s on line %s of %s: %s' % (pattern[1].pattern, i+1, foundFile, match.group()))
                    data[pattern[1].pattern].append([foundFile, i+1, match.group(), line])
    except UnicodeDecodeError as e:
        print("Skipping binary file: " + foundFile)

for pattern in processes_patterns:
    if len(data[pattern[1].pattern]) > 0:
        with open(output_dir + "/" + pattern[0] + '.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerows(data[pattern[1].pattern])


# find meng in all files under a specific directory 
# switches i - case insensitive, r - recurrsive, H - show file and path, n - line number
# grep -irHn 'meng' current/
 
# you can count using c
# grep -irc 'meng' current/
 
# you can use regex
# grep -ire ^d current/

# search files in current direct for any line that starts with d or D
# make sure e is an the end for example I want line numbers
# grep -irne ^d current/
 
# to skip binary files use I (uppercase i)
# grep -iIHrn 'meng' current/

# https://github.com/MohitDabas/sastgriper
# https://github.com/dustyfresh/PHP-vulnerability-audit-cheatsheet
# https://littlemaninmyhead.wordpress.com/2019/08/04/dont-underestimate-grep-based-code-scanning/
# https://www.floyd.ch/?p=565
# https://github.com/floyd-fuh/crass/blob/master/find-it.sh
# https://github.com/wireghoul/graudit/tree/master/signatures