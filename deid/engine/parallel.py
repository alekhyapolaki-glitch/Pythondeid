"""Masking of value batches, optionally spread over worker processes for big tables.

Masking is CPU bound (HMAC / Feistel rounds in Python), so large tables benefit
from ``execution.workers``.  Workers rebuild the exact same maskers from the
domain definitions and key, so results are identical to in-process masking.
"""

from __future__ import annotations

import hashlib
from collections import deque
from concurrent.futures import ProcessPoolExecutor
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from ..masking import BaseMasker, KeyRing, MaskerError, build_maskers, column_masker

# (hash, masked or None, error or None, canonical digest or None)
Result = Tuple[bytes, Optional[str], Optional[str], Optional[bytes]]

_WORKER: Dict[str, Any] = {}


class _Domain:
    def __init__(self, name, type_, params):
        self.name, self.type, self.params = name, type_, params


def _init_worker(domain_specs, keyring) -> None:
    _WORKER["keyring"] = keyring
    _WORKER["maskers"] = build_maskers([_Domain(*d) for d in domain_specs], keyring)
    _WORKER["columns"] = {}


def _worker_masker(domain: str, overrides: Tuple[Tuple[str, Any], ...]) -> BaseMasker:
    key = (domain, overrides)
    m = _WORKER["columns"].get(key)
    if m is None:
        m = column_masker(_WORKER["maskers"][domain], _WORKER["keyring"], dict(overrides))
        _WORKER["columns"][key] = m
    return m


def mask_rows(masker: BaseMasker, rows: Sequence[Tuple[Any, ...]], want_digest: bool) -> List[Result]:
    """rows: (hash, value) or (hash, value, entity)."""
    out: List[Result] = []
    for row in rows:
        h, value = row[0], row[1]
        entity = row[2] if len(row) > 2 else None
        try:
            masked = masker.mask(value, entity)
        except MaskerError as exc:
            out.append((bytes(h), None, str(exc), None))
            continue
        digest = hashlib.sha256(masker.canonical(value).encode("utf-8")).digest()[:16] if want_digest else None
        out.append((bytes(h), masked, None, digest))
    return out


def _worker_mask(domain, overrides, rows, want_digest) -> List[Result]:
    return mask_rows(_worker_masker(domain, overrides), rows, want_digest)


class MaskingPool:
    def __init__(self, workers: int, domains, keyring: KeyRing):
        self.workers = workers
        self._executor = None
        self._specs = [(d.name, d.type, dict(d.params)) for d in domains]
        self._keyring = keyring

    def _ensure(self):
        if self._executor is None:
            self._executor = ProcessPoolExecutor(self.workers, initializer=_init_worker,
                                                 initargs=(self._specs, self._keyring))
        return self._executor

    def map(self, masker: BaseMasker, overrides: Dict[str, Any], batches: Iterable[Sequence[Tuple[Any, ...]]],
            want_digest: bool, parallel: bool) -> Iterator[Tuple[Sequence[Tuple[Any, ...]], List[Result]]]:
        """Yields (input batch, results) in input order."""
        if not parallel or self.workers <= 1:
            for b in batches:
                yield b, mask_rows(masker, b, want_digest)
            return
        ex = self._ensure()
        ov = tuple(sorted(overrides.items()))
        pending: deque = deque()
        for b in batches:
            pending.append((b, ex.submit(_worker_mask, masker.domain, ov, [tuple(r) for r in b], want_digest)))
            if len(pending) >= self.workers * 2:
                batch, fut = pending.popleft()
                yield batch, fut.result()
        while pending:
            batch, fut = pending.popleft()
            yield batch, fut.result()

    def close(self) -> None:
        if self._executor is not None:
            self._executor.shutdown(wait=True)
            self._executor = None
