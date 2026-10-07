# Maxpanel

Web panel for scanning IP ranges for open ports with [masscan](https://github.com/robertdavidgraham/masscan) and, optionally, querying the results as Minecraft servers (Server List Ping).

Only scan networks you own or have explicit permission to test.

## Requirements

- Python 3.9+
- `masscan` available in `PATH` (on Windows the bundled `masscan64.exe` is used)
- Root/administrator privileges for raw packet scanning

## Setup

```bash
pip install -r requirements.txt
export FLASK_SECRET_KEY="a-long-random-string"
python main.py
```

The panel listens on `http://127.0.0.1:5000` by default.

## Configuration

| Variable           | Default       | Description                  |
| ------------------ | ------------- | ---------------------------- |
| `FLASK_SECRET_KEY` | `CHANGEME_SECRET` | Session signing key      |
| `FLASK_HOST`       | `127.0.0.1`   | Bind address                 |
| `FLASK_PORT`       | `5000`        | Bind port                    |
| `FLASK_DEBUG`      | unset         | Set to `1` to enable debug   |

## License

See [LICENSE](LICENSE).
