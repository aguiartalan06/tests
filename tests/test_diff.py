from netmon.diff import diff_scans


def test_diff_detects_all_change_types(baseline_scan, current_scan):
    diff = diff_scans(baseline_scan, current_scan)

    assert [d.ip for d in diff.new_devices] == ["192.168.1.50"]
    assert diff.new_devices[0].vendor == "Amazon Technologies"

    assert [d.ip for d in diff.missing_devices] == ["192.168.1.30"]
    assert diff.missing_devices[0].vendor == "Sonos"

    changes = {c.current.key: c for c in diff.changed_devices}
    assert set(changes) == {"b8:27:eb:12:34:56", "da:12:34:56:78:9a"}

    pi = changes["b8:27:eb:12:34:56"]
    assert pi.new_ports == [5900]
    assert pi.closed_ports == []
    assert pi.is_alert is True
    assert pi.ip_changed is False

    phone = changes["da:12:34:56:78:9a"]
    assert phone.ip_changed is True
    assert phone.previous.ip == "192.168.1.40" and phone.current.ip == "192.168.1.41"
    assert phone.new_ports == [] and phone.is_alert is False

    assert diff.unchanged_count == 2
    assert diff.new_port_count == 1
    assert diff.has_alerts is True
    assert diff.has_changes is True
    assert diff.reference_label == "baseline"


def test_diff_identical_scans(baseline_scan, make_scan, baseline_devices):
    again = make_scan(list(baseline_devices), scan_id=2)
    diff = diff_scans(baseline_scan, again)
    assert diff.new_devices == [] and diff.missing_devices == [] and diff.changed_devices == []
    assert diff.unchanged_count == len(baseline_devices)
    assert diff.has_alerts is False and diff.has_changes is False


def test_closed_port_is_change_but_not_alert(make_scan, make_device):
    before = make_scan([make_device("10.0.0.2", "aa:bb:cc:dd:ee:ff", ports=[22, 80])], scan_id=1, is_baseline=True)
    after = make_scan([make_device("10.0.0.2", "aa:bb:cc:dd:ee:ff", ports=[22])], scan_id=2)
    diff = diff_scans(before, after)
    assert len(diff.changed_devices) == 1
    assert diff.changed_devices[0].closed_ports == [80]
    assert diff.has_changes is True
    assert diff.has_alerts is False


def test_hostname_change_is_informational(make_scan, make_device):
    before = make_scan([make_device("10.0.0.2", "aa:bb:cc:dd:ee:ff", hostname="old.local")], scan_id=1)
    after = make_scan([make_device("10.0.0.2", "aa:bb:cc:dd:ee:ff", hostname="new.local")], scan_id=2)
    diff = diff_scans(before, after)
    assert diff.changed_devices[0].hostname_changed is True
    assert diff.has_alerts is False


def test_hostname_appearing_is_not_a_change(make_scan, make_device):
    before = make_scan([make_device("10.0.0.2", "aa:bb:cc:dd:ee:ff", hostname=None)], scan_id=1)
    after = make_scan([make_device("10.0.0.2", "aa:bb:cc:dd:ee:ff", hostname="new.local")], scan_id=2)
    diff = diff_scans(before, after)
    assert diff.changed_devices == [] and diff.unchanged_count == 1


def test_devices_without_mac_match_by_ip(make_scan, make_device):
    before = make_scan([make_device("10.0.0.9", None, ports=[80])], scan_id=1)
    after = make_scan([make_device("10.0.0.9", None, ports=[80, 8080])], scan_id=2)
    diff = diff_scans(before, after)
    assert diff.new_devices == [] and diff.missing_devices == []
    assert diff.changed_devices[0].new_ports == [8080]


def test_mac_case_is_ignored_when_matching(make_scan, make_device):
    before = make_scan([make_device("10.0.0.2", "AA:BB:CC:DD:EE:FF")], scan_id=1)
    after = make_scan([make_device("10.0.0.2", "aa:bb:cc:dd:ee:ff")], scan_id=2)
    diff = diff_scans(before, after)
    assert diff.unchanged_count == 1 and not diff.has_changes


def test_reference_label_for_previous_scan(make_scan):
    ref = make_scan([], scan_id=7)
    diff = diff_scans(ref, make_scan([], scan_id=8))
    assert diff.reference_label == "scan #7"


def test_results_are_sorted_by_ip(make_scan, make_device):
    before = make_scan([], scan_id=1)
    after = make_scan(
        [make_device("10.0.0.20", "aa:00:00:00:00:01"), make_device("10.0.0.3", "aa:00:00:00:00:02"),
         make_device("10.0.0.100", "aa:00:00:00:00:03")],
        scan_id=2,
    )
    diff = diff_scans(before, after)
    assert [d.ip for d in diff.new_devices] == ["10.0.0.3", "10.0.0.20", "10.0.0.100"]
