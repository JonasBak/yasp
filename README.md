# yasp

> Yet Another SSH Proxy

Expose a local port on a public server, possibly behind authentication.

## Examples

```bash
# Connect to server, exposing localhost:3000 on foo.example.com
# by default, traffic will be blocked, but can be allowed with the interface
ssh -R foo:80:localhost:3000 -p 2222 example.com
```

![image](https://user-images.githubusercontent.com/16608915/100785875-92634600-3411-11eb-9897-3c03b6f00850.png)

```bash
# To connect without starting as blocking, connect with the command 'open'
# the '-t' argument forces pty allocation when command is added
ssh -R foo:80:localhost:3000 -p 2222 -t example.com open
```

![image](https://user-images.githubusercontent.com/16608915/100785980-be7ec700-3411-11eb-89e9-53bb0850d3e0.png)

```bash
# To set an initial password, use the command 'pass=...'
# the password can be set/changed from the interface
# the proxy will now be behind http basic auth, with the username 'yasp'
ssh -R foo:80:localhost:3000 -p 2222 -t example.com open pass=bar
```

![image](https://user-images.githubusercontent.com/16608915/100786070-e2daa380-3411-11eb-9f0f-144e0f46a7fb.png)

The service also works without a pty (if no pty is requested, the proxy is always non-blocking)

## Configuration

The service can be configures with environment variables:

- `KEY_LOCATION`: optional, path to the server's ssh key, will generate a key if no key file is provided
- `AUTHORIZED_KEYS_DIR`: optional, path to folder containing files with public ssh keys. If the file `foobar` contains an ssh key, the user foobar will be able to connect with that key.
- `ADMIN_PASSWORD`: optional, password for authentication without key
- `SERVICE_URL`: the hostname where the service runs (e.g. example.com)

If both `AUTHORIZED_KEYS_DIR` and `ADMIN_PASSWORD` are empty, the server will allow all requests.
