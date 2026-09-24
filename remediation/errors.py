"""稳定可区分的拒绝原因错误码与领域异常。"""
from __future__ import annotations

from enum import Enum


class RejectReason(str, Enum):
    MALFORMED_EVENT = "MALFORMED_EVENT"
    MISSING_FIELD = "MISSING_FIELD"
    NO_MATCHING_POLICY = "NO_MATCHING_POLICY"
    POLICY_CONFLICT = "POLICY_CONFLICT"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    FORBIDDEN = "FORBIDDEN"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    APPROVAL_REVOKED = "APPROVAL_REVOKED"
    INVALID_TRANSITION = "INVALID_TRANSITION"
    EXECUTION_NOT_FOUND = "EXECUTION_NOT_FOUND"
    ILLEGAL_STATE = "ILLEGAL_STATE"
    CONFIG_INVALID = "CONFIG_INVALID"


class DomainError(Exception):
    def __init__(self, reason: RejectReason, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


class PolicyError(DomainError):
    pass


class AuthzError(DomainError):
    pass


class StateError(DomainError):
    pass
