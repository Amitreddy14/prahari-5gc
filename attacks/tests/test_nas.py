"""NAS Registration Request builder: validity (pycrate_mobile) and the probe as oracle."""

from __future__ import annotations

import os
import subprocess

import pytest

from prahari_attacks import nas

PROBE = os.environ.get("PRAHARI_PROBE_BIN")


def test_default_is_a_valid_registration_request() -> None:
    name, err = nas.describe(nas.registration_request())
    assert (name, err) == ("5GMMRegistrationRequest", 0)


def test_patched_suci_is_valid_and_distinct() -> None:
    a = nas.registration_request("001010000000042")
    b = nas.registration_request("001010000000777")
    assert nas.describe(a) == ("5GMMRegistrationRequest", 0)
    assert nas.describe(b) == ("5GMMRegistrationRequest", 0)
    assert a != b != nas.registration_request()


@pytest.mark.parametrize("bad", ["123", "00202" + "0" * 10, "00101abc00000042", "001010000000001x"])
def test_rejects_bad_imsi(bad: str) -> None:
    with pytest.raises(ValueError, match=r"imsi|MSIN|PLMN"):
        nas.registration_request(bad)


@pytest.mark.skipif(not PROBE, reason="set PRAHARI_PROBE_BIN to cross-check with the C++ probe")
@pytest.mark.parametrize("imsi", [None, "001010000000042"])
def test_cpp_probe_decodes_registration_request(imsi: str | None) -> None:
    assert PROBE is not None
    out = subprocess.run(
        [PROBE, "decode-nas", nas.registration_request(imsi).hex()],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert '"message":"RegistrationRequest"' in out
    assert '"registration_type":1' in out
    assert '"has_supi":true' in out
