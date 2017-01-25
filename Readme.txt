Read the PS4.pptx to understand the project description.

Ensure that "unlimited strength JCE policy jar files" are included in the java path.

for java version 1.8, download from:
http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html

Extract the jar files from the zip and save them in ${java.home}/jre/lib/security/.



Commands to run the application on command prompt:



On the server:

javac -classpath ".:/Path-to-jars-folder/*" Secure.java

javac -classpath ".:/Path-to-jars-folder/*" ChatServer.java

java -classpath ".:/Path-to-jars-folder/*" ChatServer 1500



On the client/clients:

javac -classpath ".:/Path-to-jars-folder/*" ChatClient.java

java -classpath ".:/Path-to-jars-folder/*" ChatClient 127.0.0.1 1500




