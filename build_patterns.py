# pip3 install XlsxWriter
# pip3 install pandas
# pip3 install openpyxl

import requests
import re
import json
import pandas as pd
import os

# From: https://stackoverflow.com/questions/35583963/writing-heirarchical-json-data-to-excel-xls-from-python
header_written = False
def json_to_excel(ws, data, row=0, col=0):
    global header_written
    if isinstance(data, list):
        row -= 1
        for value in data:
            row = json_to_excel(ws, value, row+1, col)
    elif isinstance(data, dict):
        max_row = row
        start_row = row
        for key, value in data.items():
            row = start_row
            if not header_written:
                ws.write(row, col, key)
                row = json_to_excel(ws, value, row+1, col)
            else:
                row = json_to_excel(ws, value, row, col)
            max_row = max(max_row, row)
            col += 1
        header_written = True
        row = max_row
    else:
        ws.write(row, col, data)

    return row

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

data_array = []

url = "https://raw.githubusercontent.com/floyd-fuh/crass/master/grep-it.sh"
resp = requests.request('GET', url, verify=False)
search_string = resp.text
search_pattern = re.compile('\ssearch\s\".*\n.*\n.*\n.*\n.*', re.MULTILINE)
for match in re.finditer(search_pattern, search_string):
    splits = re.findall('["\'].*["\']', match.group())
    data = {
        'tool': 'https://github.com/floyd-fuh/crass',
        'description': splits[0][1:-1],
        'example': splits[1][1:-1],
        'regex': splits[3][1:-1],
        'output_file': splits[4][1:-1]
    }
    data_array.append(data)

print(str(len(data_array)) + " items found")




create_file = False
if os.path.isfile('patterns.xlsx'):
    overwrite = input('patterns.xlsx already exists. Overwrite? Y = yes, N = no\n')
    if overwrite.lower() == 'y':
        create_file = True
else:
    create_file = True

if create_file:
    df = pd.DataFrame(data_array)
    writer = pd.ExcelWriter('patterns.xlsx', 
                        engine='xlsxwriter', 
                        options={'strings_to_urls': False, 
                                 'strings_to_formulas': False,
                                 'strings_to_numbers': False})
    df.to_excel(writer, sheet_name='Sheet1', index=False)
    writer.save()

create_file = False
if os.path.isfile('patterns.json'):
    overwrite = input('patterns.json already exists. Overwrite? Y = yes, N = no\n')
    if overwrite.lower() == 'y':
        create_file = True
else:
    create_file = True

if create_file:
    df = pd.read_excel('patterns.xlsx')
    data_array = df.to_numpy()
    json_data_array = []
    for data in data_array:
        json_data = {
            'tool': data[0],
            'description': data[1],
            'example': data[2],
            'regex': data[3],
            'output_file': data[4]
        }
        json_data_array.append(json_data)
    with open("patterns.json", "w") as f:
        json.dump(json_data_array, f, indent=4)