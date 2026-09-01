"""
This example demonstrates how to store Schwabdev tokens in a JSON file instead
of the default sqlite database.
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

# A tokens_db path ending in ".json" selects the JSON file backend. Tokens are
# written atomically (temp file + rename) so a crash never leaves a truncated
# file. Cross-process coordination uses a best-effort file lock; for concurrent
# multi-process use the sqlite default is still recommended.
client = schwabdev.Client(
    os.getenv('app_key'),
    os.getenv('app_secret'),
    os.getenv('callback_url'),
    tokens_db="~/.schwabdev/tokens.json",
)

print(client.quotes("AMD").json())
