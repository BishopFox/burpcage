# burpcage-python

This is an example of a Burp extension that does edits an HTTP response to have a different response body.

## Loading in Burp

First, enable Python support within Burp by going to Extender > Options and selecting the Jython JAR file.

Then, go to Extender > Extensions, press Add, select Python, and navigate to the `burpcage.py` extension file.

## Development

Jython / Burp has no support for Python3, so you unfortunately must do all development in Python 2.7.x.

I recommend starting by creating a virtualenv with Python 2.7 support:

```bash
# Linux / macOS example
virtualenv venv -p /bin/python2
```

Then, you can enter the Python virtual environment and install the dependency:

```bash
# Linux / macOS example
source venv/bin/activate; pip install burp
```

After this, you can set up your IDE of choice with the virtual environment.
