# Oracle-OCI-IAM-to-ATP-S-integration

The pythonscript is a example script of how to build a complete flow of identity management inegrated with OCI IAM Domain.
OCI IAM Domains emits evens that can be configured to call a custom function, triggered by createdelete user event, add/remove group membership events.
The script works as follows:
- Retrieve the json payload from the configred event
- Extract the username/group name
- Lookup the basic auth credentials as OCI Vault Secrets. The OCID to teh secrets are parameters to the function
- Create a OAUTH JWT for the Autonomous REST API
- Execute create user/drop user/ grant role/recvoke role, based on actin extracted  form the event payload
- The SQl are executed as ORDS REST API POST wih the dynamic generated SQL statement as JSON payload

The following steps needs to be undertaken for confiurin the solution
- Enable REST AP for a Atinomous database users with sufficient privilege
- Create a OCI Vault and store the database basic auth credentailas as secrets
- Create a OCI serverless funtion
- Configure the serverless funtion with  parametes, database URL and OCID to teh secrets created above
- Optional objectstorage for logging of funtion execution, but the funtion uses standard OCI Logging as default
- Deploy the funtion
- Create a event that is linked to teh function

Supporting documentation
[AutonomousREST/ORDS primer](https://blog.cloudnueva.com)ords-and-rest-enabled-sql)<BR>
[OCI Function primer] (https://docs.oracle.com/en-us/iaas/Content/Events/Concepts/eventsoverview.htm)<BR>
[OCI Vault] (https://www.youtube.com/watch?v=6OyrVWSL_D4)<BR>
[OCI Events] (https://www.youtube.com/watch?v=rrhCazXO5tQ)<BR>
[OCI IAM Domain events] (https://docs.oracle.com/en-us/iaas/Content/Events/Reference/eventsproducers.htm#iam-events)<BR>
