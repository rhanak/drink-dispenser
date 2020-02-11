import json
import os
import boto3
import logging
import hashlib
import hmac

# Create a logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Create an iam client
try:
  iotClient = boto3.client('iot')
  iotDataclient = boto3.client('iot-data')
except Exception as e:
  resource.init_failure(e)
  
GITHUB_TOKEN = os.environ['GITHUB_TOKEN'].encode("utf-8")

def lambda_handler(event, context):
    logger.info(GITHUB_TOKEN)
   
    logger.info("Event: %s" % json.dumps(event))
    
    if 'headers' in event:
        headers = event["headers"]
        payload = event["body"]
        logger.info("Signature \"%s\"" % headers["X-Hub-Signature"])
        
        # assuming that the 'payload' variable keeps the content sent by github as plain text
        # and 'headers' variable keeps the headers sent by GitHub
        signature = hmac.new(GITHUB_TOKEN, payload.encode("utf-8"), hashlib.sha1).hexdigest()
        if hmac.compare_digest(signature, headers['X-Hub-Signature'].split('=')[1]):

            response = iotDataclient.update_thing_shadow(
                thingName='Dispenser',
                payload=b'{ "state": { "desired": { "welcome": "aws-iot", "led_ring": { "count": 1, "color": "#FFFFFF" }, "led": "on", "dispense_time_ms": 800, "request": { "command": "dispense" } } } }'
            )
            logger.info("Update shadow: %s" % str(response))
            
            return {
                'statusCode': 200,
                'body': json.dumps('Hello from Lambda!')
            }
        else:
            logger.info("Not authorized.")
        
    else:
        logger.info("No headers passed.")
    
    

