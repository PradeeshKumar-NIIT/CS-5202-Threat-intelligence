import requests
import time
import csv

def valueCheck(value, listData):
    if value in listData.keys():
        try:
            if listData[value] is None:
                return ""
            else:
                return listData[value]
        except NameError:
            return ""
    else:
        return ""


API_KEY = '936c241ef8c58a2e1a702e280cfc9b1e94c000b22f1a5fbacec4001168e888f9'
fieldnames = ['vhash', 'creation_date', 'type_description', 'type_tag', 'meaningful_name', 'size', 'sha256',
              'type_extension', 'sha1', 'md5']
with open("data.csv", "wt", newline='', encoding='utf-8') as file:
    writer = csv.writer(file, delimiter=',')
    writer.writerow(fieldnames)
    with open('sha256.txt', 'r') as f:
        for sha in f:
            sha = sha.rstrip()
            headers = {'x-apikey': API_KEY}
            response = requests.get('https://www.virustotal.com/api/v3/search?query=' + sha, headers=headers)
            data = response.json()
            if len(data['data']) == 0:
                print('not in Virus Total')
            else:
                rows = []
                for value in fieldnames:
                    rows.append(valueCheck(value, data['data'][0]['attributes']))

            writer.writerow(rows)
            time.sleep(15)
    f.close()
