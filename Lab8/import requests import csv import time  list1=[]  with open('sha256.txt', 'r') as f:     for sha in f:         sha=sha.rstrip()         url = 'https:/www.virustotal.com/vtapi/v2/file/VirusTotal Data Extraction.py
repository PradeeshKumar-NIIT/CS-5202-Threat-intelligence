import requests
import csv
import time

list1=[]

with open('sha256.txt', 'r') as f:
    for sha in f:
        sha=sha.rstrip()
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': '936c241ef8c58a2e1a702e280cfc9b1e94c000b22f1a5fbacec4001168e888f9', 'resource': sha}
        response = requests.get(url, params=params)
        data = response.json()
        response = int(data.get('response_code'))
        if response == 0:
                print('not in Virus Total')
        elif response == 1:
            sha256 = data['sha256']
            sha1 = data['sha1']
            md5 = data['md5']
            positives = data['positives']
            total = data['total']
            rows = [sha256, sha1, md5, positives, total]
            list1.append(rows)
        else:
            print("could not be searched. Please try again later.")
        time.sleep(15)
f.close()

fieldnames = ['sha256', 'sha1', 'md5', 'positives', 'total']
with open("data.csv", "wt",  newline='', encoding='utf-8') as file:
    writer = csv.writer(file,delimiter=',')
    writer.writerow(fieldnames)
    writer.writerows(list1)
