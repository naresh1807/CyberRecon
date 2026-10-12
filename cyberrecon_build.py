"""Build-only source-archive normalization; never imported by the application."""
import gzip
import os
from pathlib import Path
import tarfile
import tempfile

from setuptools.command.sdist import sdist


def normalize_archive(path, epoch):
    """Canonical metadata, stable ordering and gzip header for a fixed source epoch."""
    if type(epoch) is not int or not 0 <= epoch <= 4294967295:
        raise ValueError("SOURCE_DATE_EPOCH must be an unsigned 32-bit timestamp")
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Source archive cannot be symlinked")
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".sdist-", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            with tarfile.open(path, "r:gz") as source, gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=epoch) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as target:
                    total = 0
                    for member in sorted(source.getmembers(), key=lambda item: item.name):
                        if (Path(member.name).is_absolute() or ".." in Path(member.name).parts
                                or not (member.isfile() or member.isdir()) or member.size > 64 * 1024 * 1024):
                            raise ValueError("Unsafe source archive member")
                        total += member.size
                        if total > 256 * 1024 * 1024:
                            raise ValueError("Source archive exceeds size bound")
                        member.uid = member.gid = 0
                        member.uname = member.gname = ""
                        member.mtime = epoch
                        member.mode = 0o755 if member.isdir() or member.mode & 0o111 else 0o644
                        member.pax_headers = {}
                        payload = source.extractfile(member) if member.isfile() else None
                        try:
                            target.addfile(member, payload)
                        finally:
                            if payload:
                                payload.close()
            stream.flush()
            os.fsync(stream.fileno())
            temporary.chmod(0o644)
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()


class ReproducibleSdist(sdist):
    def make_distribution(self):
        value = os.environ.get("SOURCE_DATE_EPOCH")
        if value is not None and (not value.isascii() or not value.isdigit() or not 0 <= int(value) <= 4294967295):
            raise ValueError("SOURCE_DATE_EPOCH must be an unsigned 32-bit timestamp")
        super().make_distribution()
        if value is not None:
            for path in self.archive_files:
                if str(path).endswith(".tar.gz"):
                    normalize_archive(path, int(value))
