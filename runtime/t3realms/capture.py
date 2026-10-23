"""Private captures written through an exclusively created asset descriptor."""
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import uuid
from .config import effective_home, private_directory, finite_number
from .lifecycle import OwnershipError, RealmError


def capture_options(format='png', quality=None, scale=1):
    if format not in ('png', 'jpeg'):
        raise ValueError('format must be png or jpeg')
    if quality is not None and (type(quality) is not int or not 1 <= quality <= 100):
        raise ValueError('quality must be an integer from 1 to 100')
    if quality is not None and format != 'jpeg':
        raise ValueError('quality applies only to jpeg')
    if not finite_number(scale) or not 0.1 <= scale <= 1:
        raise ValueError('scale must be between 0.1 and 1')
    return {'format': format, 'quality': quality, 'scale': scale}


def asset_path(home, relative):
    home = effective_home(home)
    assets = private_directory(home / 'assets')
    if not isinstance(relative, str):
        raise ValueError('asset path must be a string')
    path = Path(relative)
    if not path.is_absolute():
        path = home / path
    if not path.is_relative_to(assets) or path == assets or '..' in path.parts:
        raise OwnershipError('capture path must stay within home/assets')
    if path.parent != assets or path.is_symlink() or path.resolve() != path:
        raise OwnershipError('capture path must not contain symlinks')
    return path


def dimensions(data, format):
    if format == 'png':
        if len(data) < 24 or data[:8] != b'\x89PNG\r\n\x1a\n' or data[12:16] != b'IHDR':
            raise RealmError('capture did not return a PNG')
        return struct.unpack('>II', data[16:24])
    if not data.startswith(b'\xff\xd8'):
        raise RealmError('capture did not return a JPEG')
    offset = 2
    sof = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
    while offset + 4 <= len(data):
        if data[offset] != 0xFF:
            break
        while offset < len(data) and data[offset] == 0xFF:
            offset += 1
        if offset >= len(data):
            break
        marker = data[offset]
        offset += 1
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            continue
        if marker in (0xDA, 0xD9) or offset + 2 > len(data):
            break
        size = int.from_bytes(data[offset:offset + 2])
        if size < 2 or offset + size > len(data):
            break
        if marker in sof and size >= 8:
            height, width = struct.unpack('>HH', data[offset + 3:offset + 7])
            return width, height
        offset += size
    raise RealmError('JPEG dimensions unavailable')


def capture(record, env, *, format='png', quality=None, scale=1):
    options = capture_options(format, quality, scale)
    suffix = 'png' if format == 'png' else 'jpg'
    path = asset_path(record['home'], 'assets/shot-' + uuid.uuid4().hex + '.' + suffix)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        command = ['grim', '-o', 'HEADLESS-1', '-t', options['format'], '-s', str(scale)]
        if quality is not None:
            command += ['-q', str(quality)]
        command.append('-')
        with os.fdopen(descriptor, 'wb') as output:
            subprocess.run(command, env=env, stdout=output, stderr=subprocess.PIPE,
                           check=True, timeout=10)
            output.flush()
            os.fsync(output.fileno())
        data = path.read_bytes()
        width, height = dimensions(data, format)
        if width <= 0 or height <= 0:
            raise RealmError('capture dimensions are invalid')
        return {'path': str(path.relative_to(record['home'])),
                'mimeType': 'image/png' if format == 'png' else 'image/jpeg',
                'width': width, 'height': height, 'bytes': len(data),
                'sha256': hashlib.sha256(data).hexdigest()}
    except BaseException:
        path.unlink(missing_ok=True)
        raise
