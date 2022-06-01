# N-gram.py

# Used Module: scapy, pandas

import string
import scapy.all as sc
import pandas as pd

from urllib import parse

# pd.set_option("display.max_rows", None)
# pd.set_option("display.max_columns", None)

pcap = sc.rdpcap("Packets.pcapng")

attack, benign = 0, 0  # Attack/Benign Packet Count

alphabet = string.ascii_lowercase  # 소문자 26개 리스트 생성

columns = []
for i in alphabet:
    for j in alphabet:
        columns.append(i + j)
columns.append("label")

data = []

for packet in pcap:
    try:
        url = packet["Raw"].load.decode().split("\r\n")[0]
    except UnicodeDecodeError:
        continue

    if '?' in url:
        label = 0
        print("(1) Original URL:", url)
        url = parse.unquote(url)  # URL Decode
        print("(2) Decoded URL:", url)
        url = url.lower()  # Lowercase
        print("(3) Lowercase URL:", url)

        if "sqli" in url or "xss_r" in url:  # 공격 패킷 Label = 1
            label = 1
            attack += 1
        else:  # 정상 패킷 Label = 2
            label = 0
            benign += 1

        try:
            url = url.split(' ')[1]  # 질의문 추출 1
            url = url.split('?')[1]  # 질의문 추출 2
        except IndexError:
            continue
        print("(4) Extract Query:", url)

        url = ''.join([i for i in url if not i.isdigit()])  # 숫자 제거
        url = ''.join([c for c in url if c.isalnum()])  # 특수 문자 제거
        url = url.replace(' ', '')  # 공백 제거
        print("(5) Preprocess:", url)

        url = list(url)
        bigrams = [url[i:i + 2] for i in range(0, len(url))]  # bigram 수행
        print("(6) Bigram:", bigrams)

        features = []
        count = [0 for _ in range(676)]  # Feature의 개수를 저장할 변수
        count.append(label)  # Label 값 추가(1 또는 0)

        for i in alphabet:
            for j in alphabet:
                features.append([i, j])  # aa ab ac ~ zz까지 Feature 생성
        print("(7) Feature:", features)

        for bigram in bigrams:
            for index, feature in enumerate(features):
                if bigram == feature:  # Feature와 bigram한 값이 같으면 count 증가
                    count[index] += 1
        print("(8) Count:", count)

        data.append(count)  # data에 count 값 저장

        print('=' * 300)
    else:
        continue

print("Attack Packet:", attack)
print("Benign Packet:", benign)
print("Total Packet:", attack + benign)

result = pd.DataFrame(data, columns=columns)  # Dataframe으로 만들고
result.to_csv("Dataset.csv", encoding="utf-8")  # 저장
