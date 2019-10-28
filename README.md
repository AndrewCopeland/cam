# cam
Cyberark Application Manager for [Cyberark](https://cyberark.com) and [Conjur](https://conjur.org)

---

### **Status**: Alpha

#### **Warning: Naming and APIs are still subject to breaking changes! Do not use in production**

---
## Install

Pre-built binaries and packages are available from GitHub releases
[here](https://github.com/AndrewCopeland/cam/releases).

#### Windows

Currently not supported


#### Linux (Debian and Red Hat flavors)

[Install](https://github.com/AndrewCopeland/cam/releases/download/v0.0.1/cam)


#### Mac

[Install](https://github.com/AndrewCopeland/cam/releases/download/v0.0.1/cam-mac)


#### Auto Install

Currently not supported


#### Manual Install
Otherwise, download the [latest release](https://github.com/AndrewCopeland/summon-provider-cp/releases)

## Terminology

CAM is a utility to help manage applications within conjur. It supports the ability to create namespaces and applications either within conjur via CAM or syncronize applications from cyberark into conjur.

#### Namespaces
A namespace is a logical repersentation of a team or a group of teams. Namespaces contain a services account, safes, authentication services and applications.

#### Service Account
Each namespace will have one service account which is used to manage the namespace. This service account has the ability to create applications and grant applications to specific authentication services or safes the namespace has access to.

#### Safes
Namespace safes are granted by the conjur admin to the namespace. Once a namespace has access to a safe it can give applications access to this safes. Safes represent a safe synced from cyberark which contain accounts and the metadata associated with these accounts.

#### Authentication Services
Namespace authentications services are granted by the conjur admin to the namespace. Once a namespace has access to an authentication service it can give applications access to this authenticator service.

#### Applications 
Namespace applications are created by the namespace owner or service account. Once a application is created safes and authenticators can be granted to this application by the service account.


## Usage

* CAM must be installed on a host and the executable should be placed in the PATH environment variable.

```
$ cam
NAME
    cam - cyberark application manager

SYNOPSIS
    cam [global options] command [command options] [arguments...]

VERSION
    0.0.1

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
    new-safe      - Create a new safe within a namespace
    new-secret    - Create a new secret within a safe
    policy        - App
```
