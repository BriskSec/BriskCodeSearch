# Note: Most of the patterns are derived from the following:
#  https://github.com/MohitDabas/sastgriper
#  https://github.com/dustyfresh/PHP-vulnerability-audit-cheatsheet
#  https://littlemaninmyhead.wordpress.com/2019/08/04/dont-underestimate-grep-based-code-scanning/
#  https://www.floyd.ch/?p=565
#  https://github.com/floyd-fuh/crass/blob/master/find-it.sh
#  https://github.com/wireghoul/graudit/tree/master/signatures
# git clone https://github.com/nviennot/jd-core-java.git
# grep -iRn "Example" --color .
import glob
import os
import re
import csv
from util import run_fast_scandir
from data_interesting_files import interesting_files
from data_patterns import patterns

scan_dir = './input'
output_dir = "./reports"

extract_files = ['.war', '.ear', '.zip', '.tar', '.gz']
jd_decompile_files = ['.jar']

WILDCARD_SHORT = 20
WILDCARD_LONG = 200

processes_patterns = []
for pattern in patterns:
    name = pattern[0]
    value = pattern[1]

    value.replace("$WILDCARD_SHORT", str(WILDCARD_SHORT))
    value.replace("$WILDCARD_LONG", str(WILDCARD_LONG))

    # print(value)
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

dir_path = os.path.dirname(os.path.realpath(__file__))

subfolders, files = run_fast_scandir(scan_dir, ext=extract_files)
for foundFile in files:
    extract = input('Found ' + foundFile + '. Extract? Y = yes, N = no\n')
    if extract.lower() == 'y':
        splits = foundFile.rsplit('/', 1)
        if foundFile.endswith('tar'):
            os.system("cd " + splits[0] + "; tar -xf -C " + splits[1] + "_extracted " + splits[1])
        elif foundFile.endswith('tar.gz'):
            os.system("cd " + splits[0] + "; tar -xzf -C " + splits[1] + "_extracted " + splits[1])
        elif foundFile.endswith('gz'):
            os.system("cd " + splits[0] + "; tar -xzf -C " + splits[1] + "_extracted " + splits[1])
        else:
            os.system("cd " + splits[0] + "; unzip -n -d " + splits[1] + "_extracted " + splits[1])

subfolders, files = run_fast_scandir(scan_dir, names=jd_decompile_files)
for foundFile in files:
    decompile = input('Found ' + foundFile + '. Decompile? Y = yes, N = no\n')
    if decompile.lower() == 'y':
        if foundFile.endswith('jar'):
            splits = foundFile.rsplit('/', 1)
            os.system("cd " + splits[0] + "; java -jar " + dir_path + "/tools/jd-core-java-1.2.jar " + splits[1] + " " + splits[1] + "_decompiled")

subfolders, files = run_fast_scandir(scan_dir, names=interesting_files)
if len(files) > 0:
    with open(output_dir + "/_interesting_files.csv", 'w', newline='\r\n') as f:
        f.write('\n'.join(files) + '\n')

subfolders, files = run_fast_scandir(scan_dir)

data = {}
for pattern in processes_patterns:
    data[pattern[1].pattern] = []

totalFiles = len(files)
currentCount = 1
for foundFile in files:
    try:
        prevLine = ""
        for i, line in enumerate(open(foundFile)):
            for pattern in processes_patterns:
                for match in re.finditer(pattern[1], line):
                    # print('Found pattern %s on line %s of %s: %s' % (pattern[1].pattern, i+1, foundFile, match.group()))
                    with open(output_dir + "/" + pattern[0] + '.csv', 'a', newline='') as f:
                        findRecord = [
                            [foundFile, i+1, line.replace("\n", "").replace("\r", "")]]
                        writer = csv.writer(f)
                        writer.writerows(findRecord)
        print("%d/%d done (%d%%). Completed file: %s" % (currentCount,
                                                         totalFiles, (currentCount / totalFiles) * 100, foundFile))
    except UnicodeDecodeError as e:
        print("Skipping binary file: " + foundFile)
    currentCount = currentCount + 1


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
