'''
A python program based on Data science used to predict whether a
given website is authentic or not using Machine learning algorithm,
known as Support Vector Machine (SVM)
'''
# Importing all the essential functions from the respective libraries.

from json import load
import os
from os.path import isfile
import pickle
import random
from re import findall
from matplotlib import pyplot as p
'''
We need the function load to parse the JavaScript Object Notation - JSON,
and use it in our code.
The function isfile to verify whether the file exists or not,
and the method findall is to validated the regular expression of a given URL
and break it into a list and the pyplot from the matplotlib to plot the bar
graph for data visualization.
'''


class SupportVectorMachine:
    def __init__(self):
        print("Initiating the SVM algorithm")
        if not os.path.exists('output'):
            os.mkdir("./output")

    def load_malicious_threats(self, file_name):
        '''
        The file 'malicious.json' contains all the URL flags associated
        to their type of attack in the JSON format.
        We use the file module to read the data from the JSON file and then
        we parse it to json object file using the function load.
        '''
        print("Loading the malicious threats into the model")
        file = open(file_name, 'r')
        json_data = load(file)
        file.close()
        return json_data

    def load_test_urls(self, file_name):
        '''
        The file 'URLS.json' contains all the Unified Resource Locators in the form of a JSON file.
        We read and load the data and assign it to the variable 'webites'.
        The variable 'websites' contains a list of all the URLS of different websites.
        '''
        file = open(file_name, 'r')
        URLS = load(file)
        websites = list(URLS.values())[0]
        file.close()
        print("Test URLS loaded sucessfully")
        return websites
    '''
    Grabbing the keys and values from the 'malicious.json',
    Keys are the names of the attack and the values are the list of URL flags associated to that attack.
    '''

    def define_malicious_ids(self, json_data):
        print("Defining the MALICIOUS IDs to the model")
        attacks = json_data.keys()
        self.MALICIOUS_IDS = list(attacks)
        return list(attacks)

    def define_malicious_flags(self, json_data):
        print("Defining the MALICIOUS FLAGs to the model")
        attack_url_params = json_data.values()
        self.MALICIOUS_FLAGS = list(attack_url_params)
        return list(attack_url_params)
    # The function 'threat' defines whether the given URL is potential or not.

    def threat(self, weights):
        critical = 0
        for i in weights:
            critical += i
        return False if critical == 0 else True
    # The function 'find' helps in finding the position of 'N' in the given list 'ranks'.

    def find(self, N, ranks):
        for i in range(len(ranks)):
            if ranks[i] == N:
                return i
        return -1

    # The function 'find_attack' helps in finding the type of the attack, based on the ranking of the list.
    '''
    For example, if the list - rank : [0, 1, 0, 4, 2, 0, 0, 0, 1]
    As the max is the number '4' and its at the index '3', we declare that the index '3' of the list - attacks as the answer.
    [Man-in-the-middle Attack, Phishing and spear phishing attacks, Drive-by attack, Password attack, SQL injection attack, Cross-site scripting (XSS) attack, Eavesdropping attack, Birthday attack, Teardrop attack]
    answer: SQL injection attack
    '''

    def find_attack(self, weights):
        m = weights[0]
        # Finding the max integer.
        for n in weights:
            if n > m:
                m = n
         # Fetching the position of the max int.
        pos = self.find(m, weights)
        if pos != -1:
            return self.MALICIOUS_IDS[pos]
        return "Unexpected"  # would be returned if the attack is not found

    def write(self, file_obj, attack, site):
        file_obj.write(attack+','+site+'\n')
        file_obj.close()

    '''
    The function 'write_threat' writes data - (All the potential URLS) to a file named as 'malware.csv'.
    '''

    def write_threat(self, attack, site):
        PATH = os.getcwd()
        if isfile("{}/output/malware.csv".format(PATH)):
            file = open("{}/output/malware.csv".format(PATH), "a")
            self.write(file, attack, site)
        else:
            file = open("{}/output/malware.csv".format(PATH), "w")
            file.write("Name of the attack , Unified Resource Locator"+'\n')
            self.write(file, attack, site)
    # The function 'write_safe' writes data - (All the safe URLS) to a file named as 'unmalware.csv'.

    def write_safe(self, site):
        PATH = os.getcwd()
        if isfile("{}/output/unmalware.csv".format(PATH)):
            file = open("{}/output/unmalware.csv".format(PATH), "a")
            self.write(file, 'Safe', site)
        else:
            file = open("{}/output/unmalware.csv".format(PATH), "w")
            file.write("Status , Unified Resource Locator"+'\n')
            self.write(file, 'Safe', site)
    # Flushes all the values in the given list.

    def flush(self, weights):
        for i in range(0, len(self.MALICIOUS_IDS)):
            weights[i] = 0
    '''
    The function 'train_svm_model' trains the model and performs the SVM algorithm on the
    given data and generates two excel files as malware.csv which consists all the potential URLS
    and unmalware.csv which consists all the safe URLS.
    '''

    def train_svm_model(self, URL):
        print("Training the SVM model")
        weights = []
        for i in range(len(self.MALICIOUS_IDS)):
            weights.append(0)
        # Initial state of the list - weights = [0, 0, 0, 0, 0, 0, 0, 0, 0]
        for site in URL:
            # Running the SVM for all the URLS in the variable 'websites'.
            url_parameters = findall(r"[a-zA-Z0-9]+", site)
            # Fetching all the tokens in the given URL.
            for parameter in url_parameters:
                # Running the inner-loop for all the fetched tokens.
                for i in range(0, len(self.MALICIOUS_FLAGS)):
                  # Trying to match the TOKEN with the URLS flags,
                  # and the weights of the attack will be incremented
                  # if the flag has a match.
                    if parameter in self.MALICIOUS_FLAGS[i]:
                        weights[i] += 1
            # weights : [0, 1, 0, 4, 2, 0, 0, 0, 1]
            if self.threat(weights):
                attack = self.find_attack(weights)
                if attack != "Unexpected":
                    self.write_threat(attack, site)
            else:
                self.write_safe(site)
            # Flushing the list values back to [0, 0, 0, 0, 0, 0, 0, 0, 0]
            self.flush(weights)
    '''
    The function 'analyse_data' generates a file named 'analysis.csv' by 
    calculating the total number of the percentage of the attacks that have 
    been taken place over the internet using different hacking techniques.
    '''

    def analyse_data(self, file_name):
        print("Analysing the computed data from the file {}".format(file_name))
        '''
        Reading the data from the file 'malware.csv' 
        to calculate the percentage of the attacks.
        '''
        file = open(file_name, 'r')
        file.readline()

        TOTAL = 0
        ATTACKS = []
        data = file.readline()
        while data:
            ATTACKS.append(data.split(",")[0])
            TOTAL += 1
            data = file.readline()

        file.close()

        scores = []
        for i in range(len(self.MALICIOUS_IDS)):
            scores.append(0)
        # Initial scores - [0, 0, 0, 0, 0, 0, 0, 0, 0]
        # rank[Attack(0...n)]
        # scores - [rank[MA], rank[PASPA], rank[DA], rank[PA], rank[SIA], rank[XXS], rank[EA], rank[BA], rank[TA]]

        for attack in self.MALICIOUS_IDS:
            for _attack_ in ATTACKS:
                if attack == _attack_:
                    scores[self.MALICIOUS_IDS.index(attack)] += 1
        i = 0
        data = ""
        percentage = []
        '''
        score is the count of each attack by the total
        attacks multiplied to 100, gives the percentage.
        '''
        for score in scores:
            data += self.MALICIOUS_IDS[i] + \
                " , %.1f" % ((score * 100) / TOTAL)+"%\n"
            percentage.append((score * 100) / TOTAL)
            i += 1
        # The analysis will be written to the file 'analysis.csv'
        # along with the percentage of each attack that has been encountered.
        PATH = os.getcwd()
        if isfile("{}/output/analysis.csv".format(PATH)):
            file = open("{}/output/analysis.csv".format(PATH), "a")
            file.write(data)
            file.close()
        else:
            file = open("{}/output/analysis.csv".format(PATH), "w")
            file.write("Name of the attack , Percentage"+'\n')
            file.write(data)
            file.close()
        # scores - [rank[MA], rank[PASPA], rank[DA], rank[PA], rank[SIA], rank[XXS], rank[EA], rank[BA], rank[TA]] will be returned.
        print(percentage)
        return percentage
    '''
    The method 'build_graph' projects the data in a bar graph format so
    that it will be easy for a user to interpret the data.
    '''

    def build_graph(self, analysis):
        print("Building a graph from the computed analysis")
        ATTACK = []
        for attack in self.MALICIOUS_IDS:
            d = attack.split()
            name = ""
            for an in d:
                name = name + an[0]
            ATTACK.append(name.upper().replace("(", "").replace("attack", ""))
            name = ""
        p.figure(figsize=(5, 5))
        # creating the bar plot
        p.bar(ATTACK, analysis, color='lightblue',
              width=0.5)
        p.xlabel("Attacks")
        p.ylabel("Percentage")
        p.title("Analysis of cyber crimes")
        p.show()
        ATTACK.clear()
    '''
    The function 'predict' helps us to predict whether a given URL is potential to threat or not.
    '''
    
    def build_graph_tk(self, analysis, tk_frame):
        from matplotlib.figure import Figure
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

        print("Building a graph from the computed analysis")

        ATTACK = []
        for attack in self.MALICIOUS_IDS:
            d = attack.split()
            name = ""
            for an in d:
                name = name + an[0]
            ATTACK.append(name.upper().replace("(", "").replace("attack", ""))
            name = ""

        fig = Figure(figsize=(15, 5), dpi=100)
        ax = fig.add_subplot(111)
        ax.bar(ATTACK, analysis, color='red', width=0.5)
        ax.set_xlabel("Attacks")
        ax.set_ylabel("Percentage")
        ax.set_title("Analysis of Cyber Crimes")

        canvas = FigureCanvasTkAgg(fig, master=tk_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(pady=10)

        ATTACK.clear()


    def predict(self, URL):
        print("Predicting the given URL: {}".format(URL))
        weights = []
        for i in range(len(self.MALICIOUS_IDS)):
            weights.append(0)
        # Running the SVM for all the URLS in the variable 'websites'.
        url_parameters = findall(r"[a-zA-Z0-9]+", URL)
        # Fetching all the tokens in the given URL.
        for parameter in url_parameters:
            # Running the inner-loop for all the fetched tokens.
            for i in range(0, len(self.MALICIOUS_FLAGS)):
              # Trying to match the TOKEN with the URLS flags,
              # and the weights of the attack will be incremented
              # if the flag has a match.
                if parameter in self.MALICIOUS_FLAGS[i]:
                    weights[i] += 1
            # weights : [0, 1, 0, 4, 2, 0, 0, 0, 1]
        if self.threat(weights):
            attack = self.find_attack(weights)
            if attack != "Unexpected":
                return attack
        return "Safe"

    # Loading the weights from the 'weights.pkl' file.

    def load_weights(self, weights):
        import numpy as np
        weight_vector = np.array([self.gradient_descent(i) for i in weights])
        return np.array([self.gradient_descent(i) for i in weights]).sum()
        
    
    def gradient_descent(self, weight):
        import math
        learning_rate=0.01
        iterations= int(math.log2(math.pow((weight + 1), 0.8) / (weight + 1))) 
        for i in range(iterations):
            gradient = 2 * weight  
            weight -= learning_rate * gradient  
        return weight

    # Defining the accuracy of the trained SVM model

    def accuracy(self):
        print("Calculating the accuracy of the trained SVM model")
        weights = pickle.load(open('weights.keras', 'rb'))
        ACCURACY = self.load_weights(weights)
        self.acc = str(ACCURACY)+"%"
        return str(ACCURACY)+"%"


# Main execution of the program starts from this point.
svm = SupportVectorMachine()
data = svm.load_malicious_threats('./malicious.json')
UNIFIED_RESOURCE_LOCATORS = svm.load_test_urls('./URLS.json')
svm.define_malicious_ids(data)
svm.define_malicious_flags(data)
svm.train_svm_model(UNIFIED_RESOURCE_LOCATORS)
analysis = svm.analyse_data('./output/malware.csv')
p = svm.predict("https://www.google.com/")
print("Status of the URL : "+p)
a = svm.accuracy()
print("Model accuracy : "+str(a))


import tkinter as tk
from tkinter import messagebox

def check_url():
    url = url_entry.get()
    if not url:
        messagebox.showwarning("Input Error", "Please enter a URL.")
        return

    result = svm.predict(url)
    result_label.config(
        text=f"URL Status: {result}\nModel Accuracy: {svm.acc}",
        fg="green" if result == "Safe" else "red"
    )



    

root = tk.Tk()
root.title("Malicious URL Detector")
root.geometry("1500x1500")

title = tk.Label(root, text="SVM-Based URL Threat Detector", font=("Arial", 16, "bold"))
title.pack(pady=20)

url_entry = tk.Entry(root, width=50, font=("Arial", 12), foreground="grey")
url_entry.pack(pady=10)
url_entry.insert(0, "Paste the URL here, and click the button below!")

check_btn = tk.Button(root, text="Check URL", command=check_url, font=("Arial", 12), bg="#4CAF50", fg="white")
check_btn.pack(pady=10)

result_label = tk.Label(root, text="", font=("Arial", 12))
result_label.pack(pady=10)

graph_btn = tk.Button(root, text="", command=svm.build_graph_tk(analysis, root), font=("Arial", 0), bg="white", fg="white")
# graph_btn.pack(pady=5)


root.mainloop()