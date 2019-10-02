Enable an authentication service within DAP. This authentication service can be applied to a namespace which in turn can then be applied to an application within that namespace.

## Help
```
SYNOPSIS
    cam enable COMMAND SERVICE_ID

COMMANDS
    authn-iam - Enable authn-iam authentication service
    authn-k8s - Enable authn-k8s authentication service

Mandatory argument 'enableAction' is required. Valid arguments are 'authn-iam, authn-k8s'
```

## Usage

### authn-iam
```
$ cam enable authn-iam devIAMServiceID
```

### authn-k8s
```
$ cam enable authn-K8S devK8sServiceID
```
