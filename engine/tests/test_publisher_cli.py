import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from argus_engine import publisher as publisher_module
from argus_engine.__main__ import main
from argus_engine.publisher import RedisPublisher


class FlakyPipeline:
    def __init__(self, store: list, fail: bool) -> None:
        self.store, self.fail, self.batch = store, fail, []

    def xadd(self, _stream, fields, **_kwargs) -> None:
        self.batch.append(fields)

    def execute(self) -> None:
        if self.fail:
            raise RedisConnectionError("redis down")
        self.store.extend(self.batch)


class FlakyRedis:
    def __init__(self) -> None:
        self.down, self.store = True, []

    def pipeline(self, transaction=False):
        return FlakyPipeline(self.store, self.down)


def test_detections_are_buffered_while_redis_is_down(monkeypatch):
    monkeypatch.setattr(publisher_module, "MAX_PENDING", 3)
    out = RedisPublisher("redis://localhost:1/0")
    out.redis = FlakyRedis()

    out.detections([{"n": 1}, {"n": 2}])  # does not raise
    out.detections([{"n": 3}, {"n": 4}])  # buffer full: the oldest is dropped
    assert [d["n"] for d in out.pending] == [2, 3, 4]

    out.redis.down = False
    out.detections([{"n": 5}])
    assert len(out.redis.store) == 4 and out.pending == []


def test_inject_requires_a_scenario(capsys):
    with pytest.raises(SystemExit):
        main(["inject"])
    assert "--scenario" in capsys.readouterr().err
