# Oracle-OCI-IAM-to-ATP-S-integration

The pythonscript is a example script of how to build a complete flow of identity management inegrated with OCI IAM Domain.
OCI IAM Domains emits evens that can be configured to call a custom function, triggered by createdelete user event, add/remove group membership events.
The script works as follows:
- Retrieve the json payload from 
