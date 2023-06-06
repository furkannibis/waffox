import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import train_test_split
import joblib
import time
import threading

from scapy.all import *


class FOX:
    def __init__(self):

        self.vectorizer = TfidfVectorizer()
        self.model = None

    def load_data(self, file_path):
        df = pd.read_csv(file_path)
        df = df.dropna()
        X = df['payload']
        y = df['attack_type']
        return X, y

    def train_model(self, X_train, y_train, save_path='model.sav'):
        X_train_vectorized = self.vectorizer.fit_transform(X_train)

        try:
            self.model = joblib.load(save_path)
        except FileNotFoundError:
            self.model = LogisticRegression()
            self.model.fit(X_train_vectorized, y_train)
            joblib.dump(self.model, save_path)

    def evaluate_model(self, X_test, y_test):
        X_test_vectorized = self.vectorizer.transform(X_test)
        y_test_pred = self.model.predict(X_test_vectorized)

        confusion_mat = confusion_matrix(y_test, y_test_pred)
        accuracy = accuracy_score(y_test, y_test_pred)
        precision = precision_score(y_test, y_test_pred, average='weighted')
        recall = recall_score(y_test, y_test_pred, average='weighted')
        f1 = f1_score(y_test, y_test_pred, average='weighted')

        print("Confusion Matrix:")
        print(confusion_mat)
        print("Accuracy:", accuracy)
        print("Precision:", precision)
        print("Recall:", recall)
        print("F1 Score:", f1)

    def predict(self, user_input):
        user_input_vectorized = self.vectorizer.transform([user_input])
        predicted_attack_type = self.model.predict(user_input_vectorized)
        return predicted_attack_type[0]


class WAF:
    def __init__(self):
        threading.Thread(target=self.check_blacklist).start()
        self.rules = {}
        self.load_rules('rules/rules.txt')
        self.blocklist = []
        self.classifier = FOX()
        self.X, self.y = self.classifier.load_data('data/dataset2.csv')
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(self.X, self.y, test_size=0.2,
                                                                                random_state=42)
        self.classifier.train_model(self.X_train, self.y_train, save_path='model/model.sav')
        self.classifier.evaluate_model(self.X_test, self.y_test)

    def load_rules(self, path):
        with open(path, 'r') as f:
            for line in f:
                rules, run = line.strip().split('=')
                self.rules[rules] = run
        return self.rules

    def check(self, pkt):
        if pkt.haslayer(Ether):
            if pkt.haslayer(IP):
                if pkt.haslayer(TCP):
                    ether_dst = pkt[Ether].dst
                    ether_src = pkt[Ether].src
                    ether_type = pkt[Ether].type

                    ip_dst = pkt[IP].dst
                    ip_src = pkt[IP].src
                    ip_version = pkt[IP].version
                    ip_ihl = pkt[IP].ihl
                    ip_tos = pkt[IP].tos
                    ip_len = pkt[IP].len
                    ip_id = pkt[IP].id
                    ip_flags = pkt[IP].flags
                    ip_ttl = pkt[IP].ttl
                    ip_proto = pkt[IP].proto
                    ip_chksum = pkt[IP].chksum

                    tcp_dport = pkt[TCP].dport
                    tcp_sport = pkt[TCP].sport
                    tcp_seq = pkt[TCP].seq
                    tcp_ack = pkt[TCP].ack
                    tcp_dataofs = pkt[TCP].dataofs
                    tcp_reserved = pkt[TCP].reserved
                    tcp_flags = pkt[TCP].flags
                    tcp_window = pkt[TCP].window
                    tcp_chksum = pkt[TCP].chksum
                    tcp_urgptr = pkt[TCP].urgptr
                    tcp_options = pkt[TCP].options

                    if pkt.haslayer(Raw):
                        payload = str(pkt[Raw].load.decode('utf-8', 'ignore'))
                    else:
                        payload = ''

                    self.packet_request = {
                        'timestamp': time.time(),
                        'ether_dst': ether_dst,
                        'ether_src': ether_src,
                        'ether_type': ether_type,
                        'ip_dst': ip_dst,
                        'ip_src': ip_src,
                        'ip_version': ip_version,
                        'ip_ihl': ip_ihl,
                        'ip_tos': ip_tos,
                        'ip_len': ip_len,
                        'ip_id': ip_id,
                        'ip_flags': ip_flags,
                        'ip_ttl': ip_ttl,
                        'ip_proto': ip_proto,
                        'ip_chksum': ip_chksum,
                        'tcp_dport': tcp_dport,
                        'tcp_sport': tcp_sport,
                        'tcp_seq': tcp_seq,
                        'tcp_ack': tcp_ack,
                        'tcp_dataofs': tcp_dataofs,
                        'tcp_reserved': tcp_reserved,
                        'tcp_flags': tcp_flags,
                        'tcp_window': tcp_window,
                        'tcp_chksum': tcp_chksum,
                        'tcp_urgptr': tcp_urgptr,
                        'tcp_options': tcp_options,
                        'payload': payload
                    }
                    df = pd.read_csv('log/log.csv')
                    packet_request_df = pd.DataFrame([self.packet_request])
                    df = pd.concat([df, packet_request_df], ignore_index=True)
                    df.to_csv('log/log.csv', index=False, escapechar='\\')
                    pred = self.classifier.predict(payload)

                    if self.rules['sqli_protection'] == '1':
                        if pred == 'sqli':
                            print('SQLi detected from ' + ip_src)
                            self.add_to_blacklist(ip_src, 'SQLi')
                            self.drop()
                    if self.rules['xss_protection'] == '1':
                        if pred == 'xss':
                            print('XSS detected from ' + ip_src)
                            self.add_to_blacklist(ip_src, 'XSS')
                            self.drop()
                    if self.rules['cmdi_protection'] == '1':
                        if pred == 'cmdi':
                            print('CMDi detected from ' + ip_src)
                            self.add_to_blacklist(ip_src, 'CMDi')
                            self.drop()
                    if self.rules['path_traversal_protection'] == '1':
                        if pred == 'path-traversal':
                            print('Path Traversal detected from ' + ip_src)
                            self.add_to_blacklist(ip_src, 'Path Traversal')
                            self.drop()
                    if self.rules['jsi_protection'] == '1':
                        if pred == 'jsi':
                            print('JSI detected from ' + ip_src)
                            self.add_to_blacklist(ip_src, 'JSI')
                            self.drop()
                    if self.rules['ban_word'] == '1':
                        for word in self.rules['ban_word_list'].split(','):
                            if word in payload:
                                print('Ban word detected from ' + ip_src)
                                self.add_to_blacklist(ip_src, 'Ban Word')
                                self.drop()
                    if self.rules['dos_protection'] == '1':
                        self.dos_protection()

    def add_to_blacklist(self, ip, reason):
        df = pd.read_csv('blacklist/blocklist.csv')
        if ip in df['ip'].values:
            df.loc[df['ip'] == ip, 'ban_end_time'] = time.time() + int(self.rules['ban_time'])
            df.to_csv('blacklist/blocklist.csv', index=False)
            print('IP ' + ip + ' already in blacklist, updated ban time')
        else:
            packet_request_df = pd.DataFrame(columns=['ban_start_time', 'ban_end_time', 'ip', 'reason'],
                                             data=[
                                                 [time.time(), time.time() + int(self.rules['ban_time']),
                                                  ip, reason]])
            df = pd.concat([df, packet_request_df], ignore_index=True)
            df.to_csv('blacklist/blocklist.csv', index=False)
            print('IP ' + ip + ' added to blacklist')

    def dos_protection(self):
        df = pd.read_csv('log/log.csv')
        df = df[df['ip_src'] == self.packet_request['ip_src']]
        df = df[df['timestamp'] > self.packet_request['timestamp'] - int(self.rules['dos_protection_time'])]
        if len(df) > int(self.rules['dos_protection_count']):
            print('DoS detected from ' + self.packet_request['ip_src'])
            self.add_to_blacklist(self.packet_request['ip_src'], 'DoS')
            self.drop()

    def check_blacklist(self):
        while True:
            df = pd.read_csv('blacklist/blocklist.csv')
            for index, row in df.iterrows():
                if row['ban_end_time'] < time.time():
                    df.drop(index, inplace=True)
                    df.to_csv('blacklist/blocklist.csv', index=False)
                    print('IP ' + row['ip'] + ' removed from blacklist')
            time.sleep(1)

    def drop(self):
        if self.rules['drop_inject'] == '1':
            df = pd.read_csv('blacklist/blocklist.csv')
            if self.packet_request['ip_dst'] in df['ip'].values:
                print('Dropping packet from ' + self.packet_request['ip_dst'])
                os.system(f"iptables -A OUTPUT -d {self.packet_request['ip_dst']} -j DROP")

    def capture(self):
        sniff(iface=self.rules['iface'], prn=self.check)


if __name__ == "__main__":
    waffox = WAF()
    waffox.capture()
