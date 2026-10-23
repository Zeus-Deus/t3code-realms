"""Stable error codes shared by the CLI and private worker RPC."""
import signal
import socket
import subprocess
from .lifecycle import (RealmError, OwnershipError, NotFoundError, NotRunningError,
                        SetupRequired, BusyError)


class CodedError(RealmError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def coded_error(code, message):
    return CodedError(code, message)


def error_code(exc):
    if isinstance(exc, CodedError):
        return exc.code
    if isinstance(exc, OwnershipError):
        return 'ownership'
    if isinstance(exc, NotFoundError):
        return 'not_found'
    if isinstance(exc, NotRunningError):
        return 'not_running'
    if isinstance(exc, SetupRequired):
        return 'setup_required'
    if isinstance(exc, BusyError):
        return 'busy'
    if isinstance(exc, (TimeoutError, socket.timeout, subprocess.TimeoutExpired)):
        return 'timeout'
    if isinstance(exc, (ValueError, TypeError, KeyError)):
        return 'invalid_input'
    return 'failed'


def signal_number(value):
    names = {name: int(getattr(signal, 'SIG' + name))
             for name in ('INT', 'TERM', 'HUP', 'WINCH', 'QUIT', 'KILL')}
    if isinstance(value, str):
        value = names.get(value.removeprefix('SIG').upper(), value)
    if type(value) is not int or value not in names.values():
        raise ValueError('unsupported signal')
    return value
