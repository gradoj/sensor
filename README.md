# sensor
Mock sensor code to send lorawan otta join command from gateway. All OTAA join packets forwarded from every hotspot are visible in the console. This allows antenna placement tweaking or comparison very easily.

Create a new device in Helium console and add the dev_eui, app_eui and app_key into sensor.py. Note the devnonce starts and 0 and increments every packet. Helium drops packets if nonce is repeated. 

Currently need to stop miner to run.
