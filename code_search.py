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