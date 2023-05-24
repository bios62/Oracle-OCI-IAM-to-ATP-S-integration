# Oracle-OCI-IAM-to-ATP-S-integration

The pythonscript is a example script of how to build a complete flow of identity management inegrated with OCI IAM Domain.
OCI IAM Domains emits events that can be configured to call a custom function, triggered by created/elete user event, add/remove group membership events.<BR>
Oracle Autonomous supports database operations with REST API with Oracle Rest Data Services, ORDS. The REST API require a valid JWT,
  which is the initial step to create based on basic auth.<BR>
The script works as follows:
- Deployed as a funtion invoked by a defined event
- Retrieve the json payload from the configured event
- Extract the username/group name from the payload
- Lookup the basic auth credentials as OCI Vault Secrets. The OCID to the secrets are parameters to the function
- Create a OAUTH JWT for the Autonomous REST API
- Execute create user/drop user/ grant role/recvoke role, based on action extracted form the event payload
- The SQL are executed as ORDS REST API POST wih the dynamic generated SQL statement as JSON payload

The following steps needs to be undertaken for confiurin the solution
- Enable REST AP for a Autinomous database users with sufficient privilege
- Create a OCI Vault and store the database basic auth credentailas as secrets
- Create a OCI serverless funtion
- Configure the serverless funtion with  parametes, database URL and OCID to teh secrets created above
- Optional objectstorage for logging of funtion execution, but the funtion uses standard OCI Logging as default
- Deploy the funtion
- Create a event that is linked to the function

Supporting documentation<BR>
[AutonomousREST/ORDS primer](https://blog.cloudnueva.com/apex-ords-and-rest-enabled-sql)<BR>
[OCI Function primer](https://docs.oracle.com/en-us/iaas/Content/Events/Concepts/eventsoverview.htm)<BR>
[OCI Vault](https://www.youtube.com/watch?v=6OyrVWSL_D4)<BR>
[OCI Events](https://www.youtube.com/watch?v=rrhCazXO5tQ)<BR>
[OCI IAM Domain events](https://docs.oracle.com/en-us/iaas/Content/Events/Reference/eventsproducers.htm#iam-events)<BR>
