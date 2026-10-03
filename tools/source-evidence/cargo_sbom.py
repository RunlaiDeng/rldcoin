#!/usr/bin/env python3
"""Export resolved Cargo inventory as SPDX 2.3; not a binary linkage audit."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import tomllib


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--metadata', type=Path, required=True)
    parser.add_argument('--lock', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--source-tree-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    for value, size in [(args.source_commit, 40), (args.source_tree_sha256, 64)]:
        if len(value) != size or any(c not in '0123456789abcdef' for c in value):
            parser.error('source identities must be canonical hexadecimal')
    metadata = json.loads(args.metadata.read_text())
    locked = tomllib.loads(args.lock.read_text())['package']
    checksums = {(p['name'], p['version'], p.get('source')): p.get('checksum') for p in locked}
    package_ids = {p['id']: 'SPDXRef-Crate-' + hashlib.sha256(p['id'].encode()).hexdigest()[:24]
                   for p in metadata['packages']}
    packages = []
    for p in sorted(metadata['packages'], key=lambda p: p['id']):
        identity = (p['name'], p['version'], p.get('source'))
        if identity not in checksums:
            raise ValueError('metadata package missing from supplied lock: ' + p['name'])
        registry = p.get('source') == 'registry+https://github.com/rust-lang/crates.io-index'
        item = dict(SPDXID=package_ids[p['id']], name=p['name'], versionInfo=p['version'],
                    downloadLocation=(f"https://crates.io/api/v1/crates/{p['name']}/{p['version']}/download"
                                      if registry else 'NOASSERTION'),
                    filesAnalyzed=False, licenseConcluded='NOASSERTION',
                    licenseDeclared=p.get('license') or 'NOASSERTION', copyrightText='NOASSERTION',
                    externalRefs=[dict(referenceCategory='PACKAGE-MANAGER', referenceType='purl',
                                       referenceLocator=f"pkg:cargo/{p['name']}@{p['version']}")])
        checksum = checksums[identity]
        if checksum:
            item['checksums'] = [dict(algorithm='SHA256', checksumValue=checksum)]
        packages.append(item)
    relationships = [dict(spdxElementId='SPDXRef-DOCUMENT', relationshipType='DESCRIBES',
                          relatedSpdxElement=package_ids[p]) for p in metadata['workspace_members']]
    for node in metadata['resolve']['nodes']:
        for dep in node['deps']:
            relationships.append(dict(spdxElementId=package_ids[node['id']], relationshipType='DEPENDS_ON',
                                      relatedSpdxElement=package_ids[dep['pkg']]))
    # Package IDs include paths for workspace crates. The namespace binds the input
    # metadata too, so two inventories with different resolution cannot collide.
    inventory_hash = hashlib.sha256(args.metadata.read_bytes()).hexdigest()
    document = dict(spdxVersion='SPDX-2.3', dataLicense='CC0-1.0', SPDXID='SPDXRef-DOCUMENT',
                    name='Rldcoin Cargo resolved source inventory',
                    documentNamespace=f'https://rldcoin.org/spdx/{args.source_commit}/{inventory_hash}',
                    creationInfo=dict(created=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                                      creators=['Tool: rld-cargo-sbom-1']),
                    comment=f'Source commit {args.source_commit}; source tree SHA256 {args.source_tree_sha256}. '
                            'Cargo locked resolution across all targets, including build/dev dependencies. '
                            'Not a per-binary linkage inventory, vulnerability assessment, license review, or release approval.',
                    packages=packages, relationships=relationships)
    with args.output.open('x') as output:
        json.dump(document, output, indent=2, sort_keys=True)
        output.write('\n')
    print(json.dumps(dict(packages=len(packages), relationships=len(relationships),
                          sha256=hashlib.sha256(args.output.read_bytes()).hexdigest())))


if __name__ == '__main__':
    main()
