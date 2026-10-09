import math

import pytest

from sentinel_engine.flows import FlowTable
from sentinel_engine.packets import Packet

C, S = "10.0.0.1", "10.0.0.2"  # client, server


def tcp(ts, src, dst, sport, dport, payload=0, flags="A", window=None):
    return Packet(ts, src, dst, sport, dport, "tcp", payload, flags, window)


def http_exchange(t0=100.0):
    """Handshake, request, two-part response, FIN in both directions, final ACK."""
    return [
        tcp(t0 + 0.000, C, S, 40000, 80, 0, "S", 29200),
        tcp(t0 + 0.010, S, C, 80, 40000, 0, "SA", 28960),
        tcp(t0 + 0.020, C, S, 40000, 80, 0, "A"),
        tcp(t0 + 0.030, C, S, 40000, 80, 300, "PA"),
        tcp(t0 + 0.050, S, C, 80, 40000, 1000, "A"),
        tcp(t0 + 0.060, S, C, 80, 40000, 500, "PA"),
        tcp(t0 + 0.070, C, S, 40000, 80, 0, "FA"),
        tcp(t0 + 0.080, S, C, 80, 40000, 0, "FA"),
        tcp(t0 + 0.090, C, S, 40000, 80, 0, "A"),
    ]


def build(packets, sweep_at):
    table = FlowTable()
    for p in packets:
        table.add(p)
    return table, table.sweep(sweep_at)


def test_tcp_exchange_produces_one_bidirectional_flow_with_cic_style_features():
    table, records = build(http_exchange(), sweep_at=100.7)

    assert len(records) == 1 and len(table) == 0
    r = records[0]
    f = r["features"]
    assert (r["src_ip"], r["dst_ip"], r["src_port"], r["dst_port"]) == (C, S, 40000, 80)
    assert (r["packet_count"], r["byte_count"]) == (9, 1800)
    assert f["flow_duration_s"] == pytest.approx(0.09)
    assert (f["fwd_packets"], f["bwd_packets"]) == (5, 4)
    assert (f["fwd_bytes"], f["bwd_bytes"]) == (300, 1500)
    assert (f["fwd_pkt_len_max"], f["fwd_pkt_len_min"], f["fwd_pkt_len_mean"]) == (300, 0, 60)
    assert f["bwd_pkt_len_mean"] == 375
    assert f["bwd_pkt_len_std"] == pytest.approx(478.7135, rel=1e-4)  # sample std
    assert f["flow_iat_mean"] == pytest.approx(0.01125)
    assert f["flow_iat_max"] == pytest.approx(0.02)
    assert f["fwd_iat_total"] == pytest.approx(0.09)
    assert f["bwd_iat_total"] == pytest.approx(0.07)
    assert (f["syn_flag_count"], f["fin_flag_count"], f["rst_flag_count"]) == (2, 2, 0)
    assert (f["psh_flag_count"], f["fwd_psh_flags"], f["ack_flag_count"]) == (2, 1, 8)
    assert (f["init_win_bytes_fwd"], f["init_win_bytes_bwd"]) == (29200, 28960)
    assert f["down_up_ratio"] == 0  # 4 // 5, an integer like CICFlowMeter
    assert f["active_mean"] == f["idle_mean"] == 0


def test_finished_flow_waits_for_the_trailing_ack():
    packets = http_exchange()
    table, early = build(packets, sweep_at=100.1)  # FINs seen 0.02 s ago

    assert early == [] and len(table) == 1


def test_rst_closes_and_silence_alone_does_not_end_a_flow():
    table = FlowTable(preview_after=None)
    table.add(tcp(0.0, C, S, 1, 2, 0, "S", 1024))
    table.add(tcp(0.001, S, C, 2, 1, 0, "RA", 0))
    table.add(Packet(0.0, C, "10.0.0.9", 5353, 53, "udp", 40))

    first = table.sweep(1.0)  # RST flow done, UDP still open
    quiet = table.sweep(60.0)  # silent for a minute: still one open flow
    still_open = len(table)
    later = table.sweep(120.0)  # CICFlowMeter's flow timeout

    assert [r["dst_port"] for r in first] == [2]
    assert first[0]["features"]["init_win_bytes_bwd"] == 0
    assert quiet == [] and still_open == 1
    assert [r["protocol"] for r in later] == ["udp"]
    assert later[0]["features"]["init_win_bytes_fwd"] == -1  # no TCP window


def test_long_silence_splits_active_and_idle_periods_within_one_flow():
    """CICFlowMeter keeps a flow open through a pause and records it as an
    idle period; ending flows on 5 s of silence made these features 0."""
    packets = [
        tcp(0.0, C, S, 1, 2, 10),
        tcp(1.0, S, C, 2, 1, 10),
        tcp(8.0, C, S, 1, 2, 10),  # 7 s gap > activity gap
        tcp(9.0, S, C, 2, 1, 10),
    ]
    table = FlowTable(preview_after=None)
    for p in packets[:2]:
        table.add(p)
    assert table.sweep(7.0) == []  # the pause does not end the flow
    for p in packets[2:]:
        table.add(p)

    records = table.flush()

    assert len(records) == 1
    f = records[0]["features"]
    assert f["idle_mean"] == pytest.approx(7.0)
    assert f["active_mean"] == pytest.approx(1.0)


def test_flow_timeout_cuts_endless_flows():
    table = FlowTable(flow_timeout=10, preview_after=None)
    for i in range(12):
        table.add(tcp(float(i), C, S, 1, 2, 1))

    records = table.sweep(11.5)

    assert len(records) == 1
    assert math.isclose(records[0]["features"]["flow_duration_s"], 10.0)
    assert len(table) == 1  # the packet past the timeout opened the next flow


def test_open_flows_are_previewed_once_and_marked_when_they_end():
    table = FlowTable()
    table.add(tcp(0.0, C, S, 40000, 80, 0, "S", 1024))  # half-open, no reply

    assert table.sweep(4.0) == []
    previews = table.sweep(5.0)
    assert table.sweep(6.0) == []  # one preview per flow

    assert len(previews) == 1 and previews[0]["preview"] is True
    assert previews[0]["features"]["syn_flag_count"] == 1
    assert len(table) == 1  # a preview leaves the flow open

    final = table.sweep(120.0)
    assert len(final) == 1
    assert final[0]["previewed"] is True and "preview" not in final[0]


def test_short_flows_are_not_previewed():
    _, records = build(http_exchange(), sweep_at=100.7)

    assert records[0]["previewed"] is False and "preview" not in records[0]


def test_table_size_is_capped_by_finishing_the_stalest_flows():
    table = FlowTable(max_flows=3, preview_after=None)
    for i in range(5):
        table.add(tcp(float(i), f"10.1.0.{i}", S, 1000 + i, 80, 0, "S", 1024))

    records = table.sweep(5.0)

    assert sorted(r["src_port"] for r in records) == [1000, 1001]
    assert len(table) == 3
