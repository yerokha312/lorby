# Lorby - Auth project

This project is an assignment for 8th week of Neobis Club's Freshman program.
It is a sample application for Spring Security and JWT tokens implementation.

### Table of Contents

- [About](#about)
- [Getting Started](#getting-started)
- [Installation](#installation)
- [Usage](#usage)
- [Built With](#built-with)
- [Authors](#authors)
- [Contact](#contact)


### About
This is a sample Java Spring Boot application that consists of Security, JWT token, Java Mail Sender features.
Key Features:
* Register a new user
* Log in
* Token management
* Reset password
* Mailing

### Getting Started

These instructions will get you a copy of the project up and running on your local machine for
development and testing purposes.

#### Prerequisites

Requirements to run this project:
* Java 17
* Maven 3.5+
* Spring Boot 3.2+
* PostgreSQL 15+
* Redis
* Gmail

### Installation

To install the application you need:
1. run `git clone https://github.com/yerokha312/lorby.git`
2. `cd neo-tour`
3. run maven command `mvn clean install`, if you have maven installed locally. Or `./mvnw clean install` if you have no maven installed.

#### Testing

To run tests just open terminal in root directory and type `mvn clean test`. All test cases could be found in test directory of the project.

#### How To Run

After successful installation the app needs several variables:
- type into terminal `cd target/`
- `java -jar *.jar DATABASE_URL= --ENCRYPTION_KEY=
  --GMAIL_PASSWORD= --GMAIL_USERNAME= --LINK=`

#### How To Use

Please go to [http://neotour.netlify.app/](https://crazy-zam.github.io/neo-auth/#/auth/login) and test the site made in cooperation with frontend developer.

### Usage

* Users can register
* Login after confirming email address
* Reset password after receiving and following the link sent to email address

### Built With

[Spring Boot](https://spring.io/projects/spring-boot/) - Server framework

[Maven](https://maven.apache.org) - Build and dependency management

[PostgreSQL](https://www.postgresql.org) - Database

[Redis Databse](https://redis.io) - Redis for managing confirmation token and access token

### Authors

[Yerbolat Yergaliyev](https://github.com/yerokha312)

[Azamat Malikov](https://github.com/crazy-zam)

### Contact
For support, questions or suggestions please contact:

[linkedIn](https://lnkd.in/ddpDGKY2) - Yerbolat Yergaliyev

[erbolatt@live.com](mailto:erbolatt@live.com)

`date` Creation date: 26 February 2024
