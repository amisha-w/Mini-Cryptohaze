<div align="center">
  <img src="./static/icons/lock.svg" width="150px" height="150px"></img>

# `Cryptohaze`

![Made-With-Python](https://img.shields.io/badge/Made_with-Python-informational?style=for-the-badge&logo=python) ![Made-With-Flask](https://img.shields.io/badge/Made_with-Flask-informational?style=for-the-badge&logo=flask)

</div>

Cryptohaze is a high performance, open source, network-enabled cross-platform GPU and OpenCL accelerated password auditing tools for security professionals. It enables Penetration Testing by providing the facility of cracking the hashes of passwords in an organisation's database.

**We propose to implement a similar tool with some chosen features of Cryptohaze and some other useful features described as follows:**

✅Identify & Crack Hash <br>
✅ Crack from File <br>
✅ Crack from Directory <br>
✅ Concurrently Crack Hashes <br>
✅ Crack using Default WordList <br>
✅ Crack using Custom WordList <br>
✅ Password Strength Checker <br>
✅ Encrypt from File <br>
✅ View & Download Logs <br>


**Optimisation Measures** <br>
We use a Cache for the hashes cracked frequently; so as to reduce the computation power required for cracking hashes each time

---

## Demo

### Home

<img src="./demo/images/Home1.png">
<img src="./demo/images/Home2.png">

### Identify and Crack Hash

<img src="./demo/images/CrackHash.png">

### Crack From File

With default wordlist
<img src="./demo/images/CrackFile-Default.png">

With custom wordlist
<img src="./demo/images/CrackFile-Custom.png">

### Crack From Directory

<img src="./demo/images/CrackDirectory-Custom.png">

Download Results
<img src="./demo/images/DownloadCrackDir.png">

### Crack Concurrently

![Demo](./demo/gifs/CrackConcurrent.gif)

### Statistics

<img src="./demo/images/Statistics.png">

### Password Strength Checker

<img src="./demo/images/PasswordStrengthChecker.png">

### Encrypt From File

<img src="./demo/images/Encrypt.png">

### View & Download Logs

<img src="./demo/images/Logs1.png">

<img src="./demo/images/Logs2.png" width="600px" height="550px">

---

## Getting Started

### Prerequisites

-   Flask Framework
-   SQLite database

### Setup

Setup project environment with virtualenv and pip.

```
$ virtualenv venv
$ venv/scripts/activate
$ pip install -r https://github.com/kjsomaiya/css-assignment-1-coding-cryptohaze/blob/master/requirements.txt


$ cd projectname/
```

### Database Setup

Create SQLite Database (Lightweight Database):

```
$ from app import db
$ db.create_all()
```

---

### Running the app

```
$ python app.py
```

## Contributors

-   1711058 [Gayatri Srinivasan](https://github.com/gayatri-01)
-   1711059 [Girish Thatte](https://github.com/girishgr8)
-   1711063 [Amisha Waghela](https://github.com/amisha-w)

---
