# knot-ssh

An SSH server designed as the git frontend for [tangled.sh](https://tangled.sh), authenticating users via public keys
fetched from a companion Knot API and proxying git operations to local repositories.

I'd probably recommend just running openssh, this is just madness.

## Requirements

- Go 1.25 or later
- A running Knot API instance

## Running

The server listens on port `:22` by default. All configuration is done via command-line flags or environment variables.

## Configuration

| Flag             | Environment Variable | Default            | Description                                          |
|------------------|----------------------|--------------------|------------------------------------------------------|
| `-knot-api`      | `KNOT_API`           | `http://knot:5444` | Base URL of the Knot API                             |
| `-git-dir`       | `GIT_DIR`            | `/home/git`        | Root directory for bare git repositories             |
| `-ssh-addr`      | `SSH_ADDR`           | `:22`              | Listen address for the SSH server                    |
| `-host-key-file` | `HOST_KEY_FILE`      | `/keys/host_key`   | Path to the SSH host key (auto-generated if missing) |
| `-log.level`     | `LOG_LEVEL`          | `info`             | Log level (`debug`, `info`, `warn`, `error`)         |
| `-log.format`    | `LOG_FORMAT`         | `text`             | Log format (`text` or `json`)                        |

## MOTD

Place a file named `motd` in your git directory (`$GIT_DIR/motd`) to display a welcome message to users when they
connect. If the file is absent, a default message is shown.

## How It Works

1. A user connects via SSH and presents a public key
2. The server fetches registered keys from the Knot API and authenticates the user
3. The user's git command (`git push`, `git pull`, `git archive`) is parsed and validated
4. The Knot API authorises the operation and resolves the repository path
5. The server proxies the session to the appropriate local `git` command
6. For pushes, a `post-receive` hook notifies the Knot API with the updated ref data
