"""Native bounded lossless carriage; decode before all ordinary authentication.

One RFC1950 stream preserves the complete original signed bytes and the original
encoded/expanded bounds. The Python codec remains an explicit test oracle only.
"""
from interstellar_spool_codec_native import encode, decode, expanded_size

FORMAT = 'RLD-CONTACT-SPOOL-ZLIB-V1'
MAGIC = (FORMAT + '\0').encode('ascii')
HEADER_SIZE = len(MAGIC) + 8 + 32
