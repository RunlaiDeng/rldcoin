#!/usr/bin/env python3
"""Recompute a named source set; does not attest binary honesty or approve upgrades."""
import argparse
import hashlib
import json
from pathlib import Path
import stat

FORMAT='RLD-EARTH-IMPLEMENTATION-SOURCE'
ROOTS=('Cargo.toml','Cargo.lock','rust-toolchain.toml','crates','vectors','spec','docs/spec')

def capture(root):
    files=[]
    def walk(path):
        mode=path.lstat().st_mode
        if stat.S_ISLNK(mode):raise ValueError('symlink in implementation source')
        if stat.S_ISDIR(mode):
            for child in path.iterdir():
                name=child.name
                if '\\' in name or any(ord(c)<32 or 127<=ord(c)<=159 for c in name):raise ValueError('unsafe source name')
                if name.startswith('.') or name in ('target','node_modules','__pycache__') or name.endswith('.pyc'):continue
                walk(child)
        elif stat.S_ISREG(mode):
            if len(files)>=8192 or path.stat().st_size>128*1024*1024:raise ValueError('source limit exceeded')
            files.append(path)
        else:raise ValueError('non-regular implementation source')
    for name in ROOTS:walk(root/name)
    files.sort(key=lambda p:p.relative_to(root).as_posix())
    total=0;entries=[];digest=hashlib.sha256(FORMAT.encode()+b'\0'+len(files).to_bytes(4,'big'))
    for path in files:
        name=path.relative_to(root).as_posix();encoded=name.encode('utf-8');size=0;file_hash=hashlib.sha256()
        if len(encoded)>4096:raise ValueError('source path too long')
        with path.open('rb') as f:
            while chunk:=f.read(65536):
                size+=len(chunk);total+=len(chunk)
                if size>128*1024*1024 or total>512*1024*1024:raise ValueError('source byte ceiling')
                file_hash.update(chunk)
        raw=file_hash.digest();digest.update(len(encoded).to_bytes(4,'big')+encoded+size.to_bytes(8,'big')+raw)
        entries.append(dict(path=name,size_bytes=size,sha256=raw.hex()))
    return dict(format=FORMAT,commitment=digest.hexdigest(),file_count=len(files),total_bytes=total,files=entries)

def unique(pairs):
    result={}
    for k,v in pairs:
        if k in result:raise ValueError('duplicate manifest field')
        result[k]=v
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--manifest',type=Path,required=True,help='build-embedded inventory from rld-genesis implementation-source')
    parser.add_argument('--expected-commitment',required=True,help='separately selected source commitment; not a trust boolean')
    args=parser.parse_args()
    if not stat.S_ISREG(args.manifest.lstat().st_mode) or args.manifest.stat().st_size>4*1024*1024:raise ValueError('invalid manifest file')
    embedded=json.loads(args.manifest.read_bytes(),object_pairs_hook=unique)
    actual=capture(args.root)
    if embedded!=actual or actual['commitment']!=args.expected_commitment:raise ValueError('source or expected commitment differs')
    print(json.dumps({k:v for k,v in actual.items() if k!='files'} | dict(result='MATCH',binary_attested=False,upgrade_authorized=False)))
if __name__=='__main__':main()
