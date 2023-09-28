<link rel="preload" href="http://storage.waramik.nl/css/fonts.css">

<p align="center">
  <a href="" rel="noopener">
 <img width=150px src="http://storage.waramik.nl/img/favicon.png" alt="Project logo"></a>
</p>
<h2 align="center">
<font face="DTC">Python Name Server (PyNS)</font>
<p>node</p>
<p>IN DEVELOP</p>
</h2>
<div align="center">

[![Status](http://storage.waramik.nl/img/status.svg)]()
[![GitHub Issues](http://storage.waramik.nl/img/issues.svg)](https://github.com/SkySai1/dnspy/issues)
[![GitHub Pull Requests](http://storage.waramik.nl/img/pull_requests.svg)](https://github.com/SkySai1/dnspy/pulls)
[![License](http://storage.waramik.nl/img/license.svg)](/LICENSE)

</div>

---

<p align="center"> PyNS - DNS server realeased on Python3. This is a node version.
    <br> 
</p>

## 📝 Table of Contents

- [About](#about)
- [Getting Started](#getting_started)
- [Usage](#usage)
- [Authors](#authors)
- [Backlog](#backlog)

## 🧐 About <a name = "about"></a>

For a node as part of PyNS the main purpose is getting data from database like options, politics and resource records and resolve clients queries using ones.

At this time the node working only with PostgreSQL database. Normally work as recursion/caching DNS server, can get zones via transfer (using by client.py) and resolving queries from this zones.

For some database debug there is "client.py" tool (at now can print zones and cache tables).


## 🏁 Getting Started <a name = "getting_started"></a>


### Prerequisites

At first you need to install some libraries

```
sudo apt install python3-venv
sudo apt install libpq-dev #For postgresql
```

### Installing

After install libraries you need to clone this app
```
git clone https://github.com/SkySai1/dnspy.git ./pyns
cd ./pyns
```

Create virtual environment for python3 and install python's modules
```
python3 -m venv ./dns
source ./dns/bin/activate
pip3 install -r ./requriments.txt
```

At the end you need to change interprete's path via venvadapt.sh
```
./venvadapt.sh
```

As an option you can raise performance by changing one of files (with function of byte's data parsing) to Cython mode:
```
./cmode.sh
```

## 🎈 Usage <a name="usage"></a>

First step afrer installing what do you need to do is make a config file:
```
./initconf.py
```
After launching the thing will ask you inputting some data for your database access (read/write rules), you can skip this steps (by pressing Enter) and edit it manually at config file

For enable recursion quries you need to change it to True:
```
...
[RECURSION]
enable = True
...
```

## ✍️ Authors <a name = "authors"></a>

- [@skysail](https://github.com/SkySai1) - idea creator and first developers


## ⌛ Backlog <a name = "backlog"></a>

### GENERAL
- ✅ **Async queries resolving.** *Done. Asyncio with multiproccessing*
- ✅ **Configuration from file.** *Done.*
- 🚩 **Logging mechanism** ...
- 🚩 **Expand settings and politics** ...
- 🚩 **Debug mode** ...

### CACHING
- ✅ **Put and Get mechanism.** *Done. Via class*.
- ✅ **Sync beetwen forks.** *Done. Multiproccessing Manager.*
- ✅ **Fast cache lookup.** *Done. set() for each fork.*
- ✅ **Precache data from DB.** *Done.*
- ✅ **Save flags in DB.** *Done.*
- ✅ **Raise perfomance via C** *Done. Cython function*
- ✅ **Cache and set() clean** *Added limit for 1st lvl cache (set) and timer to clean it*
- ✅ **Sync beetwen node and database** *Upload to DB, download from DB, and pops exceeded keys from local cache*
- 🚩 **Enableable of node's cache upload** *Abilty to upload local cache to DB for this node*

### RECURSION
- ✅ **Recursion mechanism.** *Done.*
- ✅ **Switch Recursion enabling in config.** *Done.*
- ✅ **Caching data afer recursion.** *Done.*


### AUTHORITY
- ✅ **Keep DNS domains in DB.** *Done.*
- ✅ **Get zones via trasnsfer.** *Done. With TSIG and without*
- ✅ **Download domains to 2nd lvl cache** *Done.*
- ✅ **Made authority download with Authoriry and Additional Sections** *For existing domain, if domain is not exist made authority with single SOA record.Done*
- ✅ **CNAME construct via all zones** *Done.*
- ✅ **Return zones via transfer** *Done. Need to realese download keys from DB*
- 🚩 **Politics and settings for zones** ... 
- 🚩 **TSIG keeping with zones binding** ...
- 🚩 **Retransfer and zone purging** ...


### DATABASE
- ✅ **Database scheme**. *Done.*
- ✅ **Zones with domains** *Done. Foreign key one to many*
- ✅ **Cache table** *Done.*
- 🚩 **Store TSIG keys into DB** *With zone binding*
- 🚩 **Nodes table with nodes groups**
- 🚩 **Bind all zones to nodes groups**

### FRONTEND
- 🚩 **Domain and Cache managment form** ...
