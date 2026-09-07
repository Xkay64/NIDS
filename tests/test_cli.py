from simple_nids import build_parser


def test_interface_argument():
    parser = build_parser()

    args = parser.parse_args([
        "--interface",
        "eth0"
    ])

    assert args.interface == "eth0"
    assert args.quiet is False


def test_quiet_argument():
    parser = build_parser()

    args = parser.parse_args([
        "-i",
        "eth0",
        "--quiet"
    ])

    assert args.interface == "eth0"
    assert args.quiet is True
