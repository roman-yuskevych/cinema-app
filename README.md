# Cinema-service

### *Project description:*
A simple web-application that supports authentication, registration and basic features of the ticket
reservation service, based on Hibernate and Spring frameworks using REST principles.

### *Features:*
+ register and login as a USER:
  + find movies;
  + find cinema halls;
  + find available movie sessions;
  + add tickets to shopping cart;
  + view shopping cart;
  + make an order;
  + view own orders history;
+ login as ADMIN:
  + create and find movies;
  + create and find cinema halls;
  + create, find, update and delete movie sessions;
  + find user by email.

### *Used technologies:*
+ Java 11, Hibernate Framework, Spring Framework;
+ Database: MySQL;
+ Web-server: Apache Tomcat;
+ Tools: Maven, IntelliJ IDEA.

### *How to run:*
1. Clone the repo https://github.com/roman-yuskevych/cinema-app
2. Install MySQL and create a new schema
3. Add you DB properties to db.properties file
4. Add you ADMIN username and password to app.properties file
5. Configure and start Apache Tomcat v9.0.71:
   + Artifact: war-exploded artifact
   + Application context: /
6. Application is ready to use.