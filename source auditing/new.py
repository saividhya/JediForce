progfile=input("enter filename with path")
list={}
filename='name.txt'
def printlis(list):
    file=open('output.txt','w')
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
print(list)

