"""Independent retained Python spool syscall oracle, never a native fallback."""
import os
import re
import stat
from pathlib import Path
import interstellar_mesh as mesh
import interstellar_transfer as evidence
import interstellar_spool_codec_reference as spool_codec
from interstellar_storage_reference import sync_retained
require=mesh.require
SPOOL_PENDING=mesh.SPOOL_PENDING

def spool_inventory(root, adapter=None):
    files, total, entries = [], 0, 0
    for path in root.iterdir():
        entries += 1
        require(entries <= mesh.MAX_SPOOL_FILES, 'contact file capacity reached; preserve spool')
        pending = SPOOL_PENDING.fullmatch(path.name)
        if pending:
            reservation = int(pending[2])
            require(reservation <= mesh.MAX_BATCH, 'pending contact reservation exceeds bound')
            try:
                info = path.lstat()
            except FileNotFoundError:
                # Only this exact pending namespace can disappear when its
                # publisher finishes cleanup. Still charge its reservation
                # for this observation; no input or custody is inferred.
                info = None
            if info is not None:
                require(stat.S_ISREG(info.st_mode) and info.st_size <= reservation,
                        'unsafe or oversized pending contact spool file')
            size = reservation
        else:
            require(re.fullmatch(r'[0-9a-f]{64}\.json', path.name) and path.is_file() and not path.is_symlink(),
                    'unsafe contact spool file')
            size = path.stat().st_size
            if adapter == spool_codec.FORMAT:
                # Header length grants no authentication. Invalid or understated
                # streams refuse on complete decode; retain without receipt.
                with path.open('rb') as handle:
                    header = handle.read(spool_codec.HEADER_SIZE)
                size = max(size, spool_codec.expanded_size(header, encoded_size=size, limit=mesh.MAX_BATCH))
        total += size
        require(total <= mesh.MAX_SPOOL_BYTES, 'contact byte capacity reached; preserve spool')
        if not pending:
            files.append(path)
    return sorted(files), total, entries


def spool_files(root, adapter=None):
    files, total, _ = spool_inventory(root, adapter)
    return files, total


def _sync_spool_directory(root):
    descriptor = os.open(root, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _retain_same_spool(target, data, adapter):
    retained = evidence.read_file(target, mesh.MAX_BATCH)
    if adapter == spool_codec.FORMAT:
        retained = spool_codec.decode(retained, limit=mesh.MAX_BATCH)
    require(retained == data, 'exchange file collision')
    sync_retained(target)


def publish_spool(target, encoded, data, adapter=None):
    """Publish complete durable bytes without replacement; preserve any residue.

    The temporary and public link both count against the original bounds.
    Failures never acknowledge publication or delete an interrupted temporary.
    Old readers refuse the pending namespace; use fresh candidate directories.
    """
    require(re.fullmatch(r'[0-9a-f]{64}\.json', target.name), 'unsafe contact spool target')
    require(type(encoded) is bytes and type(data) is bytes
            and 0 < len(encoded) <= mesh.MAX_BATCH and 0 < len(data) <= mesh.MAX_BATCH,
            'exchange bytes exceed bound')
    _, total, entries = spool_inventory(target.parent, adapter)
    if target.exists() or target.is_symlink():
        _retain_same_spool(target, data, adapter)
        return
    reservation = max(len(data), len(encoded))
    require(entries + 2 <= mesh.MAX_SPOOL_FILES and total + 2 * reservation <= mesh.MAX_SPOOL_BYTES,
            'contact capacity reached; retain queued evidence')
    temporary = target.parent / (f'.rld-spool-pending-v1-{target.stem}-{reservation}-'
                                 + os.urandom(16).hex() + '.tmp')
    # Existing write_new fsyncs complete temporary bytes and their directory.
    # It remains unchanged for all other evidence and state callers.
    evidence.write_new(temporary, encoded)
    try:
        os.link(temporary, target, follow_symlinks=False)
    except FileExistsError:
        _retain_same_spool(target, data, adapter)
    else:
        # The inode was already fsynced. The recipient can consume the public
        # link now; do not reopen a name it may have durably consumed.
        _sync_spool_directory(target.parent)
    temporary.unlink()
    _sync_spool_directory(target.parent)
