Try mitmproxy as a pre-proxy or alternative to your main intercepting proxy software. you’ll thank yourself later

1. Install uv
2. Run `$ uv install` in project's root
3. set `.env` variables
4. `uv run mitmproxy -s config.py -s flow_highlighter.py -s repeater.py -s nonoise.py -s sampler.py`

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

Set scope on addon with @scope() decorator
```python
@scope()
def request(flow: http.HTTPFlow):
    ...
```

### Addons
- [Flow Highlighter](./flow_highlighter.py) highlight the focused flow row
- [Repeater](./repeater.py) like burpsuite repeater (mark flows as R and show/hide them)
- [Sampler](./sampler.py) to extract json fields, query parameters, headers from request/response flows and save to a file for later fuzzing.
- [No Noise](./nonoise.py) to drop analytic and ad related request so they dont reach the upstream proxy (BurpSuite/Caido/Zap).
