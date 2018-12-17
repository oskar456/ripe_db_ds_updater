
import datetime
from copy import deepcopy

import requests
from glom import glom
import dns.resolver
import dns.flags

import config as c


def get_maintained_domains(mntner):
    params = {
        "query-string": mntner,
        "inverse-attribute": "mnt-by",
        "type-filter": "domain",
        "flags": ["no-referenced", "no-irt", "no-filtering", ],
        "source": "RIPE",
    }
    r = requests.get(c.RIPE_DB_API_URL + "/search.json", params=params).json()
    yield from glom(r, "objects.object")


def _iterate_attrs(obj, callback, **kwargs):
    for a in glom(obj, "attributes.attribute"):
        r = callback(a["name"], a["value"], **kwargs)
        if r is not None:
            yield r


def _get_rpsl(key, value):
    return "{:19} {}\n".format(key + ":", value)


def _get_attr(key, value, attr):
    if key == attr:
        return value.lower()


def get_attrs(obj, attr):
    return _iterate_attrs(obj, _get_attr, attr=attr)


def get_single_attr(obj, attr):
    return next(get_attrs(obj, attr))


def ripe_obj_to_rpsl(obj):
    yield from _iterate_attrs(obj, _get_rpsl)


def delete_ds_rdata(obj):
    attrs = glom(obj, "attributes.attribute")
    for a in list(attrs):
        if a["name"] == "ds-rdata":
            attrs.remove(a)
    return obj


def append_ds_rdata(obj, ds_rdataset):
    attrs = glom(obj, "attributes.attribute")
    index = -1
    for i, a in enumerate(attrs):
        if a["name"] == "nserver":
            index = i + 1
    attrs[index:index] = [
        {"name": "ds-rdata", "value": d, }
        for d in ds_rdataset
    ]
    return obj


def print_rpsl_object(obj):
    print("".join(ripe_obj_to_rpsl(obj)))


def _clear_object(obj):
    """ Remove unneeded keys before submission. Return deep copy. """
    obj = deepcopy(obj)
    attrs = glom(obj, "attributes.attribute")
    for a in list(attrs):
        if a["name"] in ["created", "last-modified"]:
            attrs.remove(a)
    return obj


def put_object_to_ripe_db(obj, password, dry_run=True):
    domain = get_single_attr(obj, "domain")
    uri = f"{c.RIPE_DB_API_URL}/ripe/domain/{domain}"
    obj = _clear_object(obj)
    json = {"objects": {"object": [obj, ], }, }
    params = {"password": password, }
    if dry_run:
        params["dry-run"] = True
    headers = {"Accept": "application/json", }
    r = requests.put(uri, json=json, params=params, headers=headers).json()
    if "errormessages" in r:
        for e in glom(r, "errormessages.errormessage"):
            print(f"{e['severity']}: {e['text']}")
    return glom(r, "objects.object")[0]


def process_cds_records(obj, dry_run=True):
    domain = get_single_attr(obj, "domain")
    print(f"Domain: {domain}")
    lm = get_single_attr(obj, "last-modified")
    lm = datetime.datetime.strptime(lm, "%Y-%m-%dT%H:%M:%SZ")
    lm = lm.replace(tzinfo=datetime.timezone.utc)

    resolver = dns.resolver.Resolver()
    resolver.set_flags(dns.flags.RD | dns.flags.AD)
    resolver.use_edns(0, dns.flags.DO, 512)
    try:
        a = resolver.query(domain + ".", "CDS")
        assert a.response.rcode() == 0, "DNS response failure"
        assert a.response.flags & dns.flags.AD, "Unauthenticated DNS response"
        asig = a.response.find_rrset(
            a.response.answer,
            a.qname,
            a.rdclass,
            dns.rdatatype.RRSIG,
            a.rdtype,
        )
        inception = datetime.datetime.fromtimestamp(
            asig[0].inception,
            datetime.timezone.utc,
        )
        dns_ds_rdataset = {rd.to_text() for rd in a}
        ripe_ds_rdataset = set(get_attrs(obj, "ds-rdata"))
        print(f"Inception: {inception}, last modified: {lm}")
        print(f"RIPE rdataset: {ripe_ds_rdataset}")
        print(f"DNS  rdataset: {dns_ds_rdataset}")
        assert inception > lm, "Signature inception too early"
        if dns_ds_rdataset and dns_ds_rdataset != ripe_ds_rdataset:
            delete_ds_rdata(obj)
            if not (
                len(a) == 1 and  # Special Delete DS record
                a[0].key_tag == 0 and
                a[0].algorithm == 0 and
                a[0].digest_type == 0 and
                a[0].digest == b'\x00'
            ):
                append_ds_rdata(obj, dns_ds_rdataset)
            print("updating DB record")
            o = put_object_to_ripe_db(obj, c.UPDATER_PW, dry_run=dry_run)
            print_rpsl_object(o)

    except dns.exception.DNSException as e:
        print(f"DNS exception: {e}")
    except AssertionError as e:
        print(f"Assertion error: {e}")


def main(dry_run=True):
    for d in get_maintained_domains(c.UPDATER_MNT):
        process_cds_records(d, dry_run)


if __name__ == "__main__":
    main()
