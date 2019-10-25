# coding: utf-8

import os

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cross_validation import train_test_split
from sklearn.linear_model import LogisticRegression
import urllib
import time
import pickle
import html

class WAF(object):

    def __init__(self):
        good_query_list = self.get_query_list('goodqueries.txt')
        bad_query_list = self.get_query_list('badqueries.txt')
        
        good_y = [0 for i in range(0,len(good_query_list))]
        bad_y = [1 for i in range(0,len(bad_query_list))]

        queries = bad_query_list+good_query_list
        y = bad_y + good_y

        #converting data to vectors  Defining a vectorization instance
        self.vectorizer = TfidfVectorizer(tokenizer=self.get_ngrams)

        #Convert a list of irregular text strings into a regular matrix of [ [i,j], tdidf values)        
        # for the next training classifier lgs
        X = self.vectorizer.fit_transform(queries)

        # Split the X y list with train_test_split         
        # X_train The number of matrices corresponds to the number of y_train lists (one-to-one correspondence) -->> Used to train the model         
        # X_test The number of matrices corresponds to (one-to-one correspondence) -->> Used to test the accuracy of the model
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=20, random_state=42)

        # Theorem logistic regression method model
        self.lgs = LogisticRegression()

        # Train a model instance using logistic regression lgs
        self.lgs.fit(X_train, y_train)

        # Use test values ​​to calculate the accuracy of the model
        print('Model accuracy:{}'.format(self.lgs.score(X_test, y_test)))
    
    # Forecast the new request list
    def predict(self,new_queries):
        new_queries = [urllib.parse.unquote(url) for url in new_queries]
        X_predict = self.vectorizer.transform(new_queries)
        res = self.lgs.predict(X_predict)
        res_list = []
        for q,r in zip(new_queries,res):
            tmp = 'Normal request'
            if r == 0 
            else 'Malicious request'
            # print('{}  {}'.format(q,tmp))
            q_entity = html.escape(q)
            res_list.append({'url':q_entity,'res':tmp})
        print("List of predicted results:{}".format(str(res_list)))
        return res_list
        

    # Get the list of requests in the text
    def get_query_list(self,filename):
        directory = str(os.getcwd())
        # directory = str(os.getcwd())+'/module/waf'
        filepath = directory + "/" + filename
        data = open(filepath,'r').readlines()
        query_list = []
        for d in data:
            d = str(urllib.parse.unquote(d))   #converting url encoded data to simple string
            # print(d)
            query_list.append(d)
        return list(set(query_list))


    #tokenizer function, this will make 3 grams of each query
    def get_ngrams(self,query):
        tempQuery = str(query)
        ngrams = []
        for i in range(0,len(tempQuery)-3):
            ngrams.append(tempQuery[i:i+3])
        return ngrams

if __name__ == '__main__':
    # If the model file is detected lgs.pickle Does not exist, you need to train the model first.
    # w = WAF()
    # with open('lgs.pickle','wb') as output:
    # pickle.dump(w,output)

    with open('lgs.pickle','rb') as input:
        w = pickle.load(input)

    # X has 46 features per sample; expecting 7  youqude  cuowu  
    w.predict(['www.foo.com/id=1<script>alert(1)</script>','www.foo.com/name=admin\' or 1=1','abc.com/admin.php',
    '"><svg onload=confirm(1)>','test/q=<a href="javascript:confirm(1)>','q=../etc/passwd'])
    

