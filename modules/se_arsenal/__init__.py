"""Social engineering arsenal — turns passive recon into attack primitives.

Submodules here consume the output of ``modules.recon`` (phishing target
CSV, committer list, subdomain map) and produce the three things a
red-team operator needs after enumeration is done:

* ``lookalike``     — homoglyph / typosquat / TLD-swap domain candidates
* ``gophish_client`` — push target groups into an existing GoPhish server
* ``pretext``       — LLM-driven personalized phishing email drafts

The package is opt-in: nothing here runs during a normal scan. Import
the required module explicitly from an authorized integration.
"""
