"""NAS 5GS (TS 24.501) building for N2 attacks, via pycrate_mobile.

The N2 attacks need one NAS message: an initial Registration Request, carried inside
the Initial UE Message. The default is the real one captured from the testbed (the
AMF accepts it as-is); passing an `imsi` rewrites only the SUCI subscriber digits so a
registration storm can present distinct subscribers. pycrate_mobile is imported lazily
so the CLI and the N4/SBI attacks never need it.
"""

from __future__ import annotations

from prahari_attacks import ngap

HOME_PLMN = "00101"  # testbed PLMN 001/01; SUCI PLMN of every UE


def registration_request(imsi: str | None = None) -> bytes:
    """A 5GMM Registration Request. `imsi` (e.g. "001010000000042") rewrites the SUCI
    MSIN; its PLMN must be the testbed's, and its MSIN the same length as the template's.
    Returns the untouched real template when `imsi` is None."""
    template = ngap.templated_nas()
    if imsi is None:
        return template
    if len(imsi) != 15 or not imsi.isdigit():
        raise ValueError(f"imsi must be 15 digits, got {imsi!r}")
    if not imsi.startswith(HOME_PLMN):
        raise ValueError(f"imsi must be in testbed PLMN {HOME_PLMN}, got {imsi!r}")
    msin = imsi[len(HOME_PLMN) :]  # 10 MSIN digits
    from pycrate_mobile.NAS5G import parse_NAS5G  # noqa: PLC0415

    msg, err = parse_NAS5G(template)
    if err:
        raise RuntimeError(f"template NAS failed to parse: err {err}")  # pragma: no cover
    # 5GSID -> SUCI_IMSI -> Output is an Alt; its selected BufBCD holds the MSIN digits.
    msg["5GSID"]["5GSID"]["Value"]["Output"].get_alt().set_val(msin)
    return bytes(msg.to_bytes())


def describe(nas: bytes) -> tuple[str, int]:
    """(message name, parse error code) -- used by tests to confirm validity."""
    from pycrate_mobile.NAS5G import parse_NAS5G  # noqa: PLC0415

    msg, err = parse_NAS5G(nas)
    return (msg._name if msg is not None else "", err)
