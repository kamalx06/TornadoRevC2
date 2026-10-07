"""ECDSA signing for beacon task dispatch.

The server holds one keypair per handler run (`handler.signer`). Every
task is signed before dispatch; the agent embeds the public key at
build time and refuses to execute anything whose signature fails.

The same key signs the agent's own bootstrap metadata (identity), so a
man-in-the-middle that substitutes a beacon cannot redirect tasks.
"""

from __future__ import annotations

import base64
import json
from typing import Optional


class TaskSigner:
    """Wraps the handler's ECDSA signer for the beacon wire format."""

    def __init__(self, handler_signer):
        self.signer = handler_signer
        if self.signer is not None:
            self.public_pem = self.signer.public_pem
        else:
            self.public_pem = ''

    @property
    def enabled(self) -> bool:
        return self.signer is not None

    def sign_task(self, task_wire: dict) -> str:
        """Return base64 signature over the canonical task JSON.

        The task dict is serialized with sorted keys and no whitespace
        so the agent can reproduce the exact bytes when verifying.
        """
        if not self.enabled:
            return ''
        # ensure_ascii=False is required: Go's encoding/json emits raw
        # UTF-8 for non-ASCII content, while Python's json.dumps escapes
        # to \uXXXX by default. The two encodings must be byte-identical
        # for the signature to verify on the agent side.
        payload = json.dumps(task_wire, sort_keys=True,
                             separators=(',', ':'),
                             ensure_ascii=False).encode('utf-8')
        sig = self.signer.sign(payload)
        return base64.b64encode(sig).decode('ascii')

    def verify_payload(self, payload: bytes, signature_b64: str) -> bool:
        """Used by tests; agents verify with their embedded pubkey."""
        if not self.enabled:
            return True
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import hashes
            sig = base64.b64decode(signature_b64)
            self.signer.private.public_key().verify(
                sig, payload, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False