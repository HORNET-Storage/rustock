# Peg-out monitoring and alerting

Watches the two-way peg and reports movements above configurable thresholds.
Off unless configured.

```
rustock --alerts-config ./pegout-alerts.toml ...
```

See [`alerts.example.toml`](../alerts.example.toml) for a
commented file.

## What it watches

| | default | source |
|---|---|---|
| A single peg-out request | > 100 BTC | `release_requested` log |
| A single output of a peg-out transaction awaiting signature | > 100 BTC | `pegoutsWaitingForSignatures` |
| Total value in transit | > 200 BTC | `pegoutsWaitingForConfirmations` |

Two other watches share this file and this mail transport:
[node health](alerts-node-health.md), and
[large transfers in and out of smart contracts](alerts-contract-value.md).
The second is the only one here that is not a read — it re-executes the block,
because a value transfer leaves nothing behind to read.

Every peg-out event is logged regardless of threshold —
`release_request_received`, `release_requested`, `release_btc`,
`pegout_confirmed`, `pegout_transaction_created` — at `info` on target
`rustock::pegout_alerts`.

**In transit** is the set of peg-outs whose Bitcoin transaction the Bridge has
built but which have not yet reached the required confirmations (4,000 on
mainnet), so they have not yet been handed to the signers. Entries older than
that have been confirmed and moved on, and stop counting.

**Outputs awaiting signature** are read from the set the signers are handed, so
the per-output check sees the transaction as the PowHSM will.

## It cannot slow the node down

There is no hook in execution or sync. The watcher is a separate task that polls
the node's own database for blocks it has already committed, then reads
receipts and Bridge state at that block's state root. Consequences worth being
explicit about:

- A blocked or slow mail server delays only further alerts.
- A panic or a bug in this module cannot change what the node computes.
- Alerts lag by up to `poll_interval_secs`, which is the price of that isolation.

## Federation change

A peg-out transaction pays end users and may also return change to the
federation. Change is not a transfer to anyone and should not alert, but the raw
transaction alone does not say which output is which.

So change scripts are configured explicitly, in
`federation_change_scripts`. **When the list is empty every output is treated as
a user output.** That over-alerts on a large change output and never hides a
real transfer — the safe direction to fail. The alert body names the
`scriptPubKey` so a change output can be added to the list.

A future improvement is deriving the federation's script from Bridge state
automatically; it was left out deliberately rather than guessed at, because a
wrong derivation would *suppress* alerts.

## Repeated alerts

A condition that persists is reported once, not once per poll. Peg-out and
output alerts are keyed by transaction and output index.

The in-transit alert is different in kind: it is a running total, not an event.
It is therefore evaluated **only for a block that requested a new peg-out**, and
keyed by that block. That gives one alert per new peg-out that leaves the total
above the threshold. The total is still logged at debug level on every block
that touches the Bridge, so the running figure is observable without mail.

The alternative -- alerting whenever the total changes -- was rejected: the
total also moves *downwards* as peg-outs reach their 4000 confirmations and
leave the queue, which would mail you about peg-outs completing normally.

## Changing thresholds without a restart

The watcher stats its configuration file on every poll and re-reads it when the
modification time changes. Edit the file and the new values take effect on the
next poll — no restart, no dropped blocks.

Only settings that can take effect immediately are adopted:

| Live | Needs a restart |
|---|---|
| `pegout_alert_btc` | `enabled` |
| `output_alert_btc` | `start_block` |
| `in_transit_alert_btc` | `max_queued_alerts` |
| `confirmations` | everything under `[pegout_alerts.email]` |
| `poll_interval_secs` | |
| `federation_change_scripts` | |

An edit in the second column is **not** silently ignored: it is logged as a
warning naming the field and saying a restart is required. Mail settings are
deliberately excluded because the transport is built once at startup, and
because the running configuration holds credentials already expanded from the
env file — re-reading the file yields the `${SMTP_PASSWORD}` placeholder, not
the secret, so adopting it would break delivery.

A file that does not parse, or whose `federation_change_scripts` are not hex,
leaves the running configuration untouched and logs an error. The modification
time is recorded even when the parse fails, so a broken file is reported once
rather than on every poll. Both cases keep the watcher alive: a monitoring
component that exits because of a typo in its own settings is worse than one
that keeps watching with the previous thresholds.

What is logged on a successful reload:

```
INFO reloaded /etc/rustock/alerts.toml: pegout_alert_btc: 100 -> 0.01
WARN /etc/rustock/alerts.toml changed email.to: a@b -> c@d, which needs a node restart to take effect
```

## Credentials

**Secrets never go in the configuration file.** It sits next to the code and
gets copied, diffed and pasted. Put them in a file owned by the node user with
mode 0600 and refer to them as `${NAME}`:

```toml
[pegout_alerts.email]
env_file = "/etc/rustock/alerts.env"
username = "${SMTP_USER}"
password = "${SMTP_PASSWORD}"
```

```
# /etc/rustock/alerts.env, chmod 600
SMTP_USER=...
SMTP_PASSWORD=...
```

The file is `KEY=VALUE`, tolerating `export `, quotes, blanks and `#` comments,
so a shell can source the same file. Values also fall back to the process
environment.

Two refusals, both deliberate:

- **A group- or world-readable env file is refused, not warned about.** A
  credential other users on the box can read is already disclosed, and starting
  anyway would imply otherwise.
- **An unresolved `${NAME}` is an error.** Leaving the literal text as the
  password would authenticate as that string and fail later with a confusing
  message from the server.

Validate before restarting the node, without sending anything:

```
cargo run --release -p rustock-cli --example check_alerts_config -- /etc/rustock/alerts.toml
```

It reports whether each secret resolved and its length — never its value.

`.gitignore` covers `*.env` and `pegout-alerts.toml` so a stray copy in the
working tree cannot be committed.

## Email

Off until `[pegout_alerts.email] enabled = true` and a host, sender and at least
one recipient are set; a configuration claiming to send mail without them is
rejected at startup rather than at the moment an alert needs to go out. `tls`
is `none`, `starttls` or `implicit`.

A bad alert configuration logs an error and leaves the node running. An
observability feature should not stop a node from syncing.
