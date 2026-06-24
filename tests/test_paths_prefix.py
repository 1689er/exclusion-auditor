"""Tests for CrowdStrike any-volume prefix handling in path_is_under.

Regression for the bug where EXCL-PATH-002/004 and EXCL-PROC-002 never fired on
real Falcon exclusions because their values begin with `**\\` or
`\\Device\\HarddiskVolume*\\`, which the drive-anchored matcher rejected.
"""

from exclusion_auditor.paths import path_is_under

TEMP = r"C:\Users\*\AppData\Local\Temp"
ROAMING = r"C:\Users\*\AppData\Roaming"
SYS32 = r"C:\Windows\System32"


def test_double_star_prefix_matches_writable_base():
    assert path_is_under(r"**\Users\a-1\AppData\Local\Temp\x\y\App.exe", TEMP)


def test_device_volume_prefix_matches_writable_base():
    assert path_is_under(r"\Device\HarddiskVolume3\Users\bob\AppData\Roaming\Code\x", ROAMING)


def test_double_star_prefix_matches_system_dir():
    assert path_is_under(r"**\Windows\System32\drivers\x.sys", SYS32)


def test_plain_drive_path_still_matches_anchored():
    assert path_is_under(r"C:\Users\bob\AppData\Local\Temp\x", TEMP)


def test_unrelated_path_does_not_match():
    assert not path_is_under(r"**\Program Files\Vendor\app.exe", TEMP)


def test_value_wildcard_does_not_overmatch_concrete_base():
    # value "*" must not be treated as matching a concrete base segment
    assert not path_is_under(r"**\Users\*\Documents\x", r"C:\Users\*\AppData\Local\Temp")


def test_anyvolume_prefix_requires_full_base_run():
    # AppData present but not the Local\Temp tail -> not under Temp
    assert not path_is_under(r"**\Users\bob\AppData\Roaming\Code\x", TEMP)
