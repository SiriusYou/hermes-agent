"""Env-gated raw callback frame capture for F6.1 live evidence.

Default-off: when ``YOUPET_WECOM_FRAME_CAPTURE_DIR`` is absent the hook is a
no-op and the adapter behaves exactly as before. When the variable is set,
inbound websocket frames whose parsed ``cmd`` is in ``CALLBACK_COMMANDS`` are
written verbatim (raw ``msg.data`` bytes, never a re-serialized payload) into
the capture directory. Heartbeats, subscribe/handshake traffic, outbound
``_send_json`` frames, and ordinary command responses are never written, so
the bot secret and outbound content cannot land on disk.

Safety properties (all fail-closed):

- The directory must be absolute, existing, a real directory (never a
  symlink), owned by the current user, owner-only, and writable. It is opened
  with ``O_NOFOLLOW | O_DIRECTORY`` and all file operations go through the
  bound file descriptor, so replacing or renaming the path after validation
  cannot redirect evidence (no TOCTOU between validation and write).
  Writability is proven at initialization by a create/fchmod/unlink probe
  through the bound fd, so a non-writable directory fails startup instead of
  dropping the first live callback.
- Frames are staged under a dot-prefixed name and published with
  ``os.link`` — a no-clobber primitive: a pre-existing final name fails the
  publish instead of being overwritten, and a staging name this invocation
  did not create is never unlinked.
- The final mode is pinned with ``fchmod(0o600)`` because the ``O_CREAT``
  mode is masked by the process umask.
- Single-frame size and total count are bounded; error logs carry reason
  labels only, never operator paths or frame content.

Capture requires POSIX dirfd/ownership primitives; on platforms without
them (e.g. Windows) a requested capture is rejected as
``platform-unsupported``.
"""

import errno
import logging
import os
import stat
import uuid
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

ENV_VAR = "YOUPET_WECOM_FRAME_CAPTURE_DIR"
DEFAULT_MAX_FRAME_BYTES = 256 * 1024
DEFAULT_MAX_FRAMES = 500


def _current_uid() -> int:
    """Process uid via getattr (os.getuid does not exist on Windows)."""
    return getattr(os, "getuid")()


def _capture_platform_supported() -> bool:
    """Frame capture needs POSIX ownership checks and dirfd-bound writes."""
    return (
        callable(getattr(os, "getuid", None))
        and hasattr(os, "fstat")
        and hasattr(os, "fchmod")
        and hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_DIRECTORY")
        and os.open in os.supports_dir_fd
        and os.rename in os.supports_dir_fd
        and os.unlink in os.supports_dir_fd
        and os.link in os.supports_dir_fd
    )


class FrameCapture:
    """Bounded, fail-closed raw-frame writer for F6.1 evidence runs only."""

    def __init__(
        self,
        *,
        max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
        max_frames: int = DEFAULT_MAX_FRAMES,
    ) -> None:
        self._max_frame_bytes = max_frame_bytes
        self._max_frames = max_frames
        self._dir_fd: Optional[int] = None
        self._count = 0
        self._limit_logged = False
        # Requested means the operator set the variable at all; a requested
        # capture that cannot initialize must block the run, not silently pass.
        self._requested = ENV_VAR in os.environ
        if not self._requested:
            return
        raw_dir = os.getenv(ENV_VAR, "").strip()
        if not raw_dir:
            self._reject("dir-empty")
            return
        self._dir_fd = self._open_dir(Path(raw_dir))

    @property
    def requested(self) -> bool:
        return self._requested

    @property
    def enabled(self) -> bool:
        return self._dir_fd is not None

    @property
    def captured_count(self) -> int:
        return self._count

    def close(self) -> None:
        if self._dir_fd is not None:
            try:
                os.close(self._dir_fd)
            except OSError:
                pass
            self._dir_fd = None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    @staticmethod
    def _reject(reason: str) -> None:
        logger.error("WeCom frame capture disabled: %s", reason)

    def _open_dir(self, path: Path) -> Optional[int]:
        """Open and validate the capture directory, returning an inode-bound fd."""
        if not path.is_absolute():
            self._reject("dir-not-absolute")
            return None
        if not _capture_platform_supported():
            self._reject("platform-unsupported")
            return None
        try:
            dir_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except FileNotFoundError:
            self._reject("dir-missing")
            return None
        except NotADirectoryError:
            # macOS raises ENOTDIR for O_NOFOLLOW|O_DIRECTORY on a
            # symlink-to-dir. lstat here only picks the diagnostic label;
            # enforcement is the O_NOFOLLOW open plus the bound fd.
            try:
                is_link = stat.S_ISLNK(os.lstat(path).st_mode)
            except OSError:
                is_link = False
            self._reject("dir-symlink" if is_link else "dir-not-directory")
            return None
        except OSError as exc:
            self._reject("dir-symlink" if exc.errno == errno.ELOOP else "dir-unopenable")
            return None
        try:
            st = os.fstat(dir_fd)
        except OSError:
            os.close(dir_fd)
            self._reject("dir-stat-failed")
            return None
        if not stat.S_ISDIR(st.st_mode):
            os.close(dir_fd)
            self._reject("dir-not-directory")
            return None
        if st.st_uid != _current_uid():
            os.close(dir_fd)
            self._reject("dir-not-owned")
            return None
        if st.st_mode & 0o077:
            os.close(dir_fd)
            self._reject("dir-not-owner-only")
            return None
        if not self._probe_writable(dir_fd):
            os.close(dir_fd)
            self._reject("dir-not-writable")
            return None
        return dir_fd

    @staticmethod
    def _probe_writable(dir_fd: int) -> bool:
        """Prove create/fchmod/close/unlink through the bound fd before going live.

        Returns True only when every step succeeds; any failure (including
        the final unlink) keeps capture disabled so the connect-time gate
        rejects the configuration instead of discovering it on live traffic.
        """
        probe = f".write-probe-{uuid.uuid4().hex[:8]}"
        fd: Optional[int] = None
        created = False
        try:
            fd = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=dir_fd)
            created = True
            os.fchmod(fd, 0o600)
            os.close(fd)
            fd = None
            os.unlink(probe, dir_fd=dir_fd)
            return True
        except OSError:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if created:
                # Best-effort residue cleanup; the probe still reports failure
                # because a residue-free directory could not be proven.
                try:
                    os.unlink(probe, dir_fd=dir_fd)
                except OSError:
                    pass
            return False

    def capture(self, raw: Any) -> bool:
        """Write one raw frame verbatim; returns True only on complete publish."""
        if self._dir_fd is None:
            return False
        if isinstance(raw, str):
            data = raw.encode("utf-8")
        elif isinstance(raw, (bytes, bytearray)):
            data = bytes(raw)
        else:
            logger.error("WeCom frame capture skipped: frame-unsupported-type")
            return False
        if len(data) > self._max_frame_bytes:
            logger.warning(
                "WeCom frame capture skipped: frame-oversize (%d bytes)", len(data)
            )
            return False
        if self._count >= self._max_frames:
            if not self._limit_logged:
                logger.warning("WeCom frame capture stopped: capture-limit-reached")
                self._limit_logged = True
            return False

        # Neutral names: sequence + random suffix, never user/group/message IDs.
        name = f"frame-{self._count + 1:04d}-{uuid.uuid4().hex[:8]}.json"
        staging = f".{name}.tmp"
        fd: Optional[int] = None
        staging_created = False
        try:
            fd = os.open(
                staging,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=self._dir_fd,
            )
            staging_created = True
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short write to capture file")
                view = view[written:]
            # O_CREAT mode is umask-masked; pin the final mode explicitly.
            os.fchmod(fd, 0o600)
            os.close(fd)
            fd = None
        except OSError as exc:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            # Only remove a staging file this invocation created; a
            # pre-existing staging name is not ours to delete.
            if staging_created:
                self._unlink_staging(staging)
            # Exception type name only; strerror can embed the path.
            logger.error(
                "WeCom frame capture write failed: frame-write-error (%s)",
                type(exc).__name__,
            )
            return False

        # Publish with a no-clobber primitive: os.link fails EEXIST instead of
        # silently replacing an earlier frame the way POSIX rename would.
        try:
            os.link(
                staging,
                name,
                src_dir_fd=self._dir_fd,
                dst_dir_fd=self._dir_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            self._unlink_staging(staging)
            logger.error("WeCom frame capture publish failed: frame-publish-exists")
            return False
        except OSError as exc:
            self._unlink_staging(staging)
            logger.error(
                "WeCom frame capture publish failed: frame-publish-error (%s)",
                type(exc).__name__,
            )
            return False
        # Best-effort removal of our own staging link; the evidence is the
        # published final name and is already durable.
        self._unlink_staging(staging)
        self._count += 1
        return True

    def _unlink_staging(self, staging: str) -> None:
        try:
            os.unlink(staging, dir_fd=self._dir_fd)
        except OSError:
            logger.error("WeCom frame capture cleanup failed: staging-unlink-failed")
