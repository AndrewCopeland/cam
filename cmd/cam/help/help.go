package help

import "fmt"

var Version string = "0.0.1"

var Action string = fmt.Sprintf(`NAME
    cam - cyberark application manager

SYNOPSIS
    cam [global options] command [command options] [arguments...]

VERSION
    %s

GLOBAL OPTIONS
    --help    - Show this message
    --version - Display the program version

COMMANDS
    init          - Create the ~/.conjurrc file
    login         - Login to DAP. Create the ~/.netrc file
    get           - Get a specific item
    set           - Set a specific item
    enable        - Enable an authentication service
    sync          - Sync templates or applications into DAP
    new-namespace - Create a new namespace within DAP
    namespace     - Open a namespace
    new-app       - Create an application within a namespace
    policy        - Append, replace, delete or rollback a DAP policy (recommended for advanced DAP users)
`, Version)

var Get string = `SYNOPSIS
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
`

var Set string = `SYNOPSIS
    cam set COMMAND RESOURCE_ID NEW_VALUE

COMMANDS
    secret    - Set the value of a secret
    template  - Set the content of a template
    namespace - Set a safe or authentication service for a namespace
    app       - Set a safe or authentication service for an app
`

var Policy string = `SYNOPSIS
    cam policy COMMAND POLICY_BRANCH [POLICY_FILE]

COMMANDS
    append         - Append the policy and concatinate to the policy variable
    replace        - Replace the policy on the specified branch
    rollback       - Rollback a policy
    delete         - Delete specified resources within a policy branch
    append-no-save - Append the policy but DO NOT concatinate policy to the policy variable
`
var Enable string = `SYNOPSIS
    cam enable COMMAND SERVICE_ID

COMMANDS
    authn-iam - Enable authn-iam authentication service
    authn-k8s - Enable authn-k8s authentication service
`

var Sync string = `SYNOPSIS
    cam sync COMMAND [APPLICATION_NAME]

COMMANDS
    application  - Sync application from Cyberark into DAP
    applications - Sync all DAP applications from Cyberark into DAP
    templates    - Sync template folder into DAP
`

var SetNamespace string = `SYNOPSIS
    cam set namespace NAMESPACE_NAME COMMAND VALUE(S)

COMMANDS
    safe      - Set safe for a namespace
    authn-iam - Set iam authentication service for a namespace
    authn-k8s - Set k8s authentication service for a namespace
`

var SetApp string = `SYNOPSIS
    cam set app APP_NAME COMMAND VALUE(S)

COMMANDS
    safe      - Set safe for an app
    authn     - Set api key authentcation for an app
    authn-iam - Set iam authentication service for an app
    authn-k8s - Set k8s authentication service for an app
`
