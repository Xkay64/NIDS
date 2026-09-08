import simple_nids


def test_invalid_interface(monkeypatch, capsys):
    monkeypatch.setattr(
        simple_nids,
        "get_if_list",
        lambda: ["lo", "eth0"]
    )

    result = simple_nids.start_sniff(
        "fake0",
        quiet=True
    )

    captured = capsys.readouterr()

    assert result == 2
    assert "was not found" in captured.err


def test_valid_interface(monkeypatch):
    monkeypatch.setattr(
        simple_nids,
        "get_if_list",
        lambda: ["lo", "eth0"]
    )

    monkeypatch.setattr(
        simple_nids,
        "sniff",
        lambda **kwargs: None
    )

    result = simple_nids.start_sniff(
        "eth0",
        quiet=True
    )

    assert result == 0


def test_permission_error(monkeypatch, capsys):
    monkeypatch.setattr(
        simple_nids,
        "get_if_list",
        lambda: ["eth0"]
    )

    def fake_sniff(**kwargs):
        raise PermissionError

    monkeypatch.setattr(
        simple_nids,
        "sniff",
        fake_sniff
    )

    result = simple_nids.start_sniff(
        "eth0",
        quiet=True
    )

    captured = capsys.readouterr()

    assert result == 1
    assert "Permission denied" in captured.err
