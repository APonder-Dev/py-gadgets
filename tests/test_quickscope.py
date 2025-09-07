import py_gadgets.tools.quickscope as qs


def test_parse_ports_common_includes_22():
    assert 22 in qs.parse_ports("common")


def test_parse_ports_ranges_and_dedupe():
    assert qs.parse_ports("5-7,7-9,22") == [5,6,7,8,9,22]


def test_parse_exclude_range():
    assert qs.parse_exclude("80-81,443") == {80,81,443}


def test_expand_targets_cidr_order_and_dedupe():
    ips = qs.expand_targets(["192.168.0.0/30", "192.168.0.1"])
    assert "192.168.0.1" in ips  # /30 hosts() includes .1 and .2
