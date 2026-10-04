import time


def sensor_status(name: str, age_s: float, **extra) -> dict:
    now = time.time()
    return {
        "name": name,
        "hostname": f"{name}-host",
        "platform": "Windows 11",
        "interface": "Wi-Fi",
        "filter": "",
        "state": "running",
        "started_at": now - 3600,
        "last_seen": now - age_s,
        "packets": 12345,
        "packets_per_s": 42.5,
        "flows_sent": 678,
        "flows_buffered": 0,
        "flows_dropped": 0,
        "capture_drops": 0,
        "active_flows": 9,
        **extra,
    }


def test_sensors_are_listed_with_health(client, viewer_headers, redis_client):
    redis_client.hset("sentinel:sensors:laptop", mapping=sensor_status("laptop", 2))
    redis_client.hset("sentinel:sensors:edge", mapping=sensor_status("edge", 30))
    redis_client.hset("sentinel:sensors:old", mapping=sensor_status("old", 600))
    redis_client.hset("sentinel:sensors:gone", mapping=sensor_status("gone", 1, state="stopped"))

    body = client.get("/api/v1/sensors", headers=viewer_headers).json()

    assert [(s["name"], s["status"]) for s in body["items"]] == [
        ("laptop", "online"),
        ("edge", "stale"),
        ("gone", "offline"),
        ("old", "offline"),
    ]
    laptop = body["items"][0]
    assert laptop["packets"] == 12345 and laptop["packets_per_s"] == 42.5
    assert laptop["interface"] == "Wi-Fi" and laptop["hostname"] == "laptop-host"
    assert body["backlog"] is None


def test_engine_backlog_on_the_flow_stream(client, viewer_headers, redis_client):
    redis_client.xgroup_create("sentinel:flows", "engine", id="$", mkstream=True)
    for i in range(3):
        redis_client.xadd("sentinel:flows", {"v": "1", "sensor": "s", "data": str(i)})
    redis_client.xreadgroup("engine", "engine", {"sentinel:flows": ">"}, count=1)

    body = client.get("/api/v1/sensors", headers=viewer_headers).json()

    assert body["items"] == []
    assert body["backlog"] == {"pending": 1, "lag": 2}


def test_garbage_status_fields_do_not_break_the_list(client, viewer_headers, redis_client):
    redis_client.hset("sentinel:sensors:odd", mapping={"packets": "lots", "last_seen": "x"})

    body = client.get("/api/v1/sensors", headers=viewer_headers).json()

    assert body["items"][0]["name"] == "odd"
    assert body["items"][0]["status"] == "offline" and body["items"][0]["packets"] == 0


def test_sensors_require_authentication(client):
    assert client.get("/api/v1/sensors").status_code == 401
