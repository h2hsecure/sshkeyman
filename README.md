# SSH KEY MANAGEMENT

Managing SSH keys across a server farm is a non-trivial and error-prone task.  
**SSH Key Management** provides a centralized way to manage users and their SSH public keys from a single identity source such as **Keycloak**, **LDAP**, or a custom web backend.

The tool ensures that SSH access on servers always reflects the current state of your identity system — no manual key copying, no stale access.

---

## Why SSH Key Management?

- Manual SSH key distribution does not scale
- Revoked users often keep lingering access
- Keys are rarely audited or rotated
- Identity and access data already exists elsewhere

This project bridges the gap between **identity management** and **SSH authentication**.

---

## How It Works

SSH Key Management periodically fetches SSH public keys from a backend identity store (Keycloak, web service, etc.) and synchronizes them to the local system in a safe and deterministic way.

When a user attempts to log in, **standard SSH public key authentication** is used — no SSH changes or patches are required.

### Components

There are two main components:

- **libnss module**
  - Integrates with the Linux Name Service Switch (NSS)
  - Resolves users dynamically from the identity backend

- **SSH key sync executable**
  - Periodically fetches public keys from the backend
  - Writes them to the appropriate `authorized_keys` locations
  - Automatically removes revoked or deleted keys

Both components must be installed and configured correctly for the system to work.

---

## Architecture Overview

```
[ Identity Backend ]
(Keycloak / Web API)
        |
        v
[ SSH Key Management ]
   - NSS module
   - Sync executable
        |
        v
[ Linux Server ]
~/.ssh/authorized_keys
```

---

## Installation

From the source directory, run:

```bash
make install
```

This will:

- Build two Go binaries
- Install the NSS module into the appropriate system location
- Install the SSH key sync executable
- Prepare default configuration paths

> Root permissions are required.

---

## Configuration

SSH Key Management is configured using a YAML file.  
This file defines how users are resolved via NSS, how SSH keys are fetched from Keycloak, and where local state is stored.

### Example Configuration

```yaml
nss:
  suffix:
    - "<your organization suffix>"

  groupid: 1000
  minuid: 10000
  shell: "/bin/bash"

  # Override existing local users if they already exist
  override: true

keycloak:
  username: "<keycloak api username>"
  password: "<keycloak api password>"
  client_id: "<client id for authentication>"
  server: "https://keycloak.example.com"
  realm: "<keycloak realm name>"

db_path: "/var/lib/sshkeyman/user.db"
home: "/home/%s"
```

---

## Home Directory Creation

### Q&A

**Q: Can home directories be created automatically for users?**  
**A:** Yes.

Add the following line to `/etc/pam.d/common-session`:

```shell
session    required    pam_mkhomedir.so skel=/etc/skel/ umask=0022
```

This ensures that a home directory is created on first login.

---

## Security Considerations

- Only **public SSH keys** are handled
- No private keys are generated or stored
- Backend access can be configured as read-only
- `authorized_keys` files are updated atomically
- Revoked users and keys are automatically removed

---

## Limitations

- Linux-only (due to NSS integration)
- Requires root access for installation
- Backend availability affects key sync freshness

---

## TODO / Roadmap

- Additional backend support (LDAP, generic REST, OIDC)
- Group-based and role-based key filtering
- Per-host access control
- Audit logs and change history
- systemd service and timer support
- Kubernetes / cloud-init integration

---

## Contributing

Contributions are welcome via pull requests and issues.

---

## License

MIT License.