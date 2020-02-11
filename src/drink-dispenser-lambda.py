import json
import os
import boto3
import logging
import hashlib
import hmac
from datetime import datetime

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
   
    # Dump the event for debugging purposes
    logger.debug("Event: %s" % json.dumps(event))
    
    # Ensure some preconditions are met
    if event.get("headers", {}).get("X-Hub-Signature"):
        # Pull out the headers and body for later verification
        headers = event["headers"]
        payload = event["body"]
        logger.debug("Signature \"%s\"" % headers["X-Hub-Signature"])
        
        # Check we have been provided a valid signature
        if len(headers['X-Hub-Signature'].split('=')) == 2 and len(payload) > 10:
            providedSignature = headers['X-Hub-Signature'].split('=')[1]
        else:
            return {
                'statusCode': 403,
                'body': "Not Authorized"
            }
        
         # Using the secret key and the payload generate a signature
        signature = hmac.new(GITHUB_TOKEN, payload.encode("utf-8"), hashlib.sha1).hexdigest()
            
        # Compare the signature we have generated matches the one on the incoming request
        if hmac.compare_digest(signature, providedSignature):

            response = iotDataclient.update_thing_shadow(
                thingName='Dispenser',
                payload=b'{ "state": { "desired": { "welcome": "aws-iot", "led_ring": { "count": 1, "color": "#FFFFFF" }, "led": "on", "dispense_time_ms": 500, "request": { "command": "dispense" } } } }'
            )
            logger.info("Update shadow: %s" % str(response))
            
            return {
                'statusCode': 200,
                'body': "Updated shadow at %s." % datetime.now()
            }
        else:
            logger.info("Not authorized.")
        
    else:
        logger.info("No headers passed.")
        
    return {
        'statusCode': 403,
        'body': "Not Authorized"
    }
