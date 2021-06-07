This repository is archived
===========================

CDS scanning is now `run by RIPE NCC`_ using a tool called rcdss_ which is an evolution of this script. This repository is therefore no longer maintained.

.. _run by RIPE NCC: https://www.ripe.net/manage-ips-and-asns/db/support/configuring-reverse-dns#4--automated-update-of-dnssec-delegations
.. _rcdss: https://github.com/RIPE-NCC/rcdss

RIPE DB DS record updater
=========================

This is a very early version of Python script to update `ds-rdata` attribute of
RIPE database domain objects, according to DNSSEC-validated `CDS` record
in the delegated zone.

More documentation to come later.
