# Flask Restaurant API

Rest API for Online Collection of Restaurants, written in Python and Flask, with a few other Flask Extensions([See Reference](#reference)). Please note that as of this time this Project is still under development.  
___
#### Table Of Content

- [Description](#description)
- [Documentation](#documentation)
- [Installation and Setup](#installation-and-setup)
- [Features](#features)
- [Reference](#reference)
- [Author Info](#author-info)

---
## Description
This API will provide regular and existing restaurants an extra platform for sales. And will especially provide users of these restaurants the ease of restaurant services anywhere and at anytime. 

It is a mobile food vendor to customer services. Food vendors will place food items they have on their profile, with cost price(including delivery), customers will scan through, find what they want and place orders. Payments will be made to the platform, vendors can withdraw from their account at anytime.

A host of exciting features will be added to enhance user experiences, like displaying available food items for the day, placing special orders for food items not on the list and some others.


---

## Documentation
See the [Docs](https://documenter.getpostman.com/view/20762208/2s83zjt47y) or [Postman Json file](api_collection.json) for more detailed guide on how to test and use the API

To quickly test the API you can also use the [Postman Json file](api_collection.json), with all requests defined.

---

## Installation and Setup
__Note__ this project can only run as localhost for now, as it is still under developement.

__Install Python__

Python3 and Pip: 

 Python3.8 and above is recommended. [Visit for Python installation](https://www.python.org/)

__Install Virtualenv__

_For Linux & MacOS_
```bash
    pip3 install virtualenv
```

_For Windows_

```bash
    pip install virtualenv
```

__Create and Activate Virtualenv__

_For Linux & MacOs_
```bash
    python3 -m venv <env-name>
    source <env-name>/bin/activate
```

_For Windows_
```bash
    py -m venv <env-name>
    <your-env>\Scripts\activate
```
__Install Dependencies__

_Windows, Linux, MacOS_
```bash
    pip install -r requirements.txt
```

__.env configurations__

Create .env file in the parent folder, and add the following;

```python
    MAILGUN_DOMAIN=
    MAILGUN_API_KEY=
    SECRET_KEY=
    DATABASE_URI=
```
* This project integrates with Mailgun for email sending services, head over to [Mailgun](https://www.mailgun.com/) to register and get your sandbox domain(MAILGUN_DOMAIN) with API key(MAILGUN_API_KEY)

* Add a secure, secret key to the application(SECRET_KEY), preferrably random characters of string

* This project works well with SQL databases, SQLite and PostgresQL. You can also use MySQL. Add your preferred database uri to the DATABASE_URI

_Run application_ 
```bash 
    python app.py
```
[Top](#flask-restaurant-api)

---
## Features
This is a Restful API, with Flask-Resful.
It completely adheres to the Rest Architecture.
As of this time, this project have only following features;
    
    - JWT Authentication
    - E-mail sending with Mailgun API
    - ORM with SQLAlchemy
    - Secure passwords hashing, with Bcrypt
    - Serialization and Deserialization of data, with Marshmallow
    - Image Uploads

[Top](#flask-restaurant-api)

---

## Reference
- [Flask](https://flask.palletsprojects.com/en/2.2.x/)
- [Flask-Restful](https://flask-restful.readthedocs.io/en/latest/)
- [Flask-JWT-Extended](https://flask-jwt-extended.readthedocs.io/en/stable/)
- [Flask-SQLAlchemy](https://flask-sqlalchemy.palletsprojects.com/en/3.0.x/)
- [Flask-Marshmallow](https://flask-marshmallow.readthedocs.io/en/latest/)
- [Marshmallow-SQLAlchemy](https://marshmallow-sqlalchemy.readthedocs.io/en/latest/)


## Author Info
* Rest API developer, Web developer in Python and Flask
    * Email: oduazubike@gmail.com
    * Twitter [@Azubuikemadu](https://twitter.com/Azubuikemadu)

[Top](#flask-restaurant-api)