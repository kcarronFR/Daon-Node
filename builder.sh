#!/bin/sh
/Users/kcarron/Downloads/tomcat/bin/shutdown.sh

cd /Users/kcarron/Repositories/Idx-Auth-Tree-Node/
mvn clean install

rm -f /Users/kcarron/Downloads/tomcat/logs/*

rm /Users/kcarron/Downloads/tomcat/webapps/openam/WEB-INF/lib/idxAuthRequestNode-1.7.1.jar

cp /Users/kcarron/Repositories/Idx-Auth-Tree-Node/target/idxAuthRequestNode-1.7.1.jar /Users/kcarron/Downloads/tomcat/webapps/openam/WEB-INF/lib/

sleep 3
/Users/kcarron/Downloads/tomcat/bin/startup.sh

tail -f /Users/kcarron/Downloads/tomcat/logs/catalina.out