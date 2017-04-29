import sys
progfile=sys.argv[1]
list={}
filename='name.txt'
def printlis(list):
    name='output'+str(sys.argv[1])
    file=open('output.txt','a')
    if len(list)>1:
        file.write("FILE NAME"+name+"\n")
    for key,value in list.items():
        file.write(key+"\n")
        words=value.split('$')
        for i in words:
            file.write ("....line"+str(i)+"\n")
        file.write("\n")
def populate(filename):
    wordlist = []
    f = open("name.txt", 'r')
    for line in f:
        wordlist.append(line.replace("\n", ""))
    return wordlist

def insert(word,content,line):
    if word in list:
        list[word]=str(str(list[word])+"$"+str(num)+":  "+str(content))
    else:
        list[word]=str(num)+":  "+content
f=open(progfile,'r')
wordlist=populate(filename)
for num,line in enumerate(f,1):
    for j in range(0,len(wordlist)):
        if wordlist[j] in line:
            insert(wordlist[j],line.replace("\n",""),num)
            #insert(line,num)
printlis(list)
#print(list)

