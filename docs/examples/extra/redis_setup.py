"""
This example demonstrates how to store Schwabdev tokens in Redis.

Install the optional redis extra first:
    pip install 'schwabdev[redis]'
"""

import logging
import os

from dotenv import load_dotenv
import schwabdev

# place your app key and app secret in the .env file
load_dotenv()

# warn user if they have not added their keys to the .env
if not len(os.getenv('app_key')) > 0 or not len(os.getenv('app_secret')) > 0:
    raise Exception("Add your app key and app secret to the .env file.")

logging.basicConfig(level=logging.INFO)

# Point tokens_db at a redis URL to use the redis token store. The first run
# triggers the browser auth flow; subsequent runs (and any other process using
# the same URL) share the stored tokens. Refresh coordination uses a short-lived
# redis distributed lock so only one instance refreshes at a time.
client = schwabdev.Client(
    os.getenv('app_key'),
    os.getenv('app_secret'),
    os.getenv('callback_url'),
    tokens_db="redis://localhost:6379/0",
)

print(client.quotes("AMD").json())
