Get or list resource(s) or items from conjur.

## Help
```
SYNOPSIS
    cam get COMMAND [RESOURCE_ID]

COMMANDS
    secret     - Print the value of a secret
    secrets    - List all of the secrets
    template   - Print a specific template
    templates  - List all of the templates
    resources  - List all of the DAP resources
    namespaces - List all of the namespaces
    namespace  - List safes, apps and authentication services namespace contains
    apps       - List all applications
    app        - List safes and authentication services app contains
    safes      - List all safes
    authns     - List all enabled authentication services

Mandatory argument 'resource' is required. Valid arguments are 'secret, template, secrets, templates, resources, namespaces, namespace, full-namespace, apps, app, safes, authns'
```

## Usage
### secrets
```
$ cam get secrets
...
secrets/frontend/nginx_user
secrets/frontend/nginx_pwd
secrets/frontend/nginx_address
secrets/backend/postgres_user
secrets/backend/postgres_pwd
secrets/backend/postgres_address
...
```

### secret
```
$ cam get secret secrets/frontend/nginx_user
nginxUser
```

### namespace
```
$ cam get namespace aamteam
{
  "Name": "aamteam",
  "Safes": [
    "DevOps_Safe",
    "WindowsDualAccount"
  ],
  "Authenticators": [
    "iam/prod"
  ],
  "Apps": [
    "FirstApp",
    "SecondApp",
    "DevOps_Safe",
    "ThirdApp",
    "MyNewApp"
  ]
}
```

### app
Must be in a namespace by using the `cam namespace namespaceName` command.

```
$ cam get app FirstApp
{
  "Namespace": "aamteam",
  "App": "FirstApp",
  "Safes": [
    "DevOps_Safe"
  ],
  "Authenticators": [
    "host/aamteam/FirstApp/6647778464/iam-role-name",
    "host/aamteam/FirstApp/7746654667/iam-role-name"
  ],
  "ApiKey": ""
}
```
