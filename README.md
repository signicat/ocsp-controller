# ocsp-controller

## Project mission
The project handle OCSP stapling for certificates. The initial idea was to include this logic in the cert-manager's next certificate lifecycle flow. Original issue https://github.com/cert-manager/cert-manager/issues/5785.
The current Solution combines 2 approaches:

Periodic certificate scan and OCSP staple update if needed
Handling OCSP Stapling while cert-manager creates or updates certificate object

To handle certificate updates we are using mutating admission webhook https://medium.com/ovni/writing-a-very-basic-kubernetes-mutating-admission-webhook-398dbbcb63ec. Periodic updates are handled with a Cron Job.
