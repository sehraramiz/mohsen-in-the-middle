Try [mitmproxy](https://github.com/mitmproxy/mitmproxy/) as a pre-proxy or alternative to your main intercepting proxy software. you’ll thank yourself later

1. Install uv
2. Run `$ uv install` in project's root
3. set `.env` variables
4. `uv run mitmproxy -s config.py -s filter_view.py -s flow_highlighter.py -s repeater.py -s nonoise.py -s harvester.py`

Recommended Key Bindings:
```bash
$ cp .mitmproxy/keys.yaml ~/.mitmproxy
```

- `Crtl + r` to send flow to "Repeater"
- `Shift + r`/`R` to show the "Repeater"
- `Shift + h`/`H` to highlight a flow

Custom Commands:
- `:nojs` hide javascript flows
- `:noimage` hide image flows
- `:nostyle` hide style related flows
- `:repeat` send a copy of the current focused flow to repeater
- `:repeater` show repeater
- `:highlight` highlight current focused flow
- `:freeze` freeze a flow
- `:freezer` show freezed flows
- `:rotate` rotate upstream tor ip

Set scope on addon with @scope() decorator
```python
@scope()
def request(flow: http.HTTPFlow):
    ...
```

### Addons
- [Flow Highlighter](./flow_highlighter.py) highlight the focused flow row
- [Repeater](./repeater.py) like burpsuite repeater (mark flows as R and show/hide them)
- [Sampler](./harvester.py) to extract json fields, query parameters, headers from request/response flows and save to a file for later fuzzing.
- [No Noise](./nonoise.py) to drop analytic and ad related request so they dont reach the upstream proxy (BurpSuite/Caido/Zap).
- [Flow Freezer](./freezer.py) to capture and freeze a flow’s response to serve the frozen response for any future requests to the same url.
- [Rotator](./rotator.py) use Tor as upstream proxy and rotate IPs. See [Tor Setup](#tor-upstream-with-rotator) below.
- [Cache Oracle](./cache_oracle.py) detect cached responses by inspecting response headers for CDN signals (CF-Cache-Status, X-Cache, Age, max-age, custom header regex, hit/miss value patterns)


## Tor upstream with Rotator

Add `-s rotator.py` to the mitmproxy command. It requires a Tor daemon configured with an HTTP tunnel port and a control port.

### 1. Configure torrc

```
ControlPort 9051
HashedControlPassword <your-hashed-password>
HTTPTunnelPort 9080
```

Generate `HashedControlPassword` with: `tor --hash-password <your-password>`

### 2. Set mitmproxy options

Via CLI `--set` flags:
```bash
uv run mitmproxy -s rotator.py --set tor_control_password=<your-password> --set tor_http_port=9080 --set requests_per_ip=1000
```

Or via the console `:set`:
```
:set tor_control_password=<your-password>
```

| Option | Default | Description |
|---|---|---|
| `tor_host` | `127.0.0.1` | Tor daemon host |
| `tor_http_port` | `9080` | Tor HTTP tunnel port |
| `tor_control_port` | `9051` | Tor control port |
| `tor_control_password` | _(empty)_ | Tor control password (required) |
| `requests_per_ip` | `100` | Requests before automatic IP rotation |
