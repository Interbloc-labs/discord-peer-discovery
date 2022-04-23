# Cosmos Peer Discovery
This tool will discovery any available node/peer and then send it to a discord webhook. Everything it needs is the rpc endpoint of a node (any cosmos coin works) and the webhook url to send the message. 

## Usage
* Rename the .env.dev to .env with ```cp .env.dev .env```
* Install the requirements with ``pip install -r requirements.txt``
* Add your rpc node and webhook url. The more connections the rpc node has the better
* Execute the main.py with ``python main.py``