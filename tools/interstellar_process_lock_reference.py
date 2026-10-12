"""Explicit independent original Python directory/flock syscall oracle."""
import fcntl
import os
from pathlib import Path
from interstellar_file_reference import ensure_dir
NAMES=dict(Mesh='.lock',Startup='.startup.lock',Service='.regional-contact-service.lock')
def safe_directory(path):
    path=Path(path)
    if not path.is_absolute():raise ValueError('directory must be absolute')
    if any(p.is_symlink() for p in [path,*path.parents]):raise ValueError('symlink directory refused')
    ensure_dir(path);return path
class Lock:
    @classmethod
    def acquire(cls,path,role,nonblocking=False):
        result=cls();result.fd=os.open(safe_directory(path)/NAMES[role],os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        try:fcntl.flock(result.fd,fcntl.LOCK_EX|(fcntl.LOCK_NB if nonblocking else 0))
        except BaseException:result.close();raise
        return result
    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None
    def __enter__(self):return self
    def __exit__(self,*_):self.close()
