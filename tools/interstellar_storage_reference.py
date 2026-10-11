"""Independent Python syscall oracle; never a production native-failure fallback."""
import os
import interstellar_transfer as evidence
from interstellar_mesh import MAX_STATE, MAX_MESSAGES, MAX_PACKET_BATCH, require

def sync_retained(path):
    """Reaffirm unchanged custody without rewriting the complete archive."""
    descriptor=os.open(path,os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    descriptor=os.open(path.parent,os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

def sync_retained_many(paths):
    """Same-operation custody: every distinct file, then each parent directory.

    No result survives the call. Failure prevents receive acknowledgment and
    publication; shared frames still require their own complete authentication.
    """
    # Preserve dependency-before-wrapper order while coalescing repeated paths.
    paths = list(dict.fromkeys(paths))
    require(len(paths) <= 2 * (MAX_MESSAGES + MAX_PACKET_BATCH),
            'retained custody sync capacity exceeded')
    parents = set()
    for path in paths:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        parents.add(path.parent)
    for parent in sorted(parents):
        descriptor = os.open(parent, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

def archive_write(path, raw):
    temporary=path.parent/('.archive-write-'+os.urandom(32).hex())
    try:
        evidence.write_new(temporary,raw)
        try:
            os.link(temporary,path)
        except FileExistsError:
            require(evidence.read_file(path,MAX_STATE)==raw,'existing archive differs')
        sync_retained(path)
    finally:
        # This is disposable staging; original active custody is unchanged
        # until the separately durable archive and index transaction succeed.
        temporary.unlink(missing_ok=True)
        descriptor=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
