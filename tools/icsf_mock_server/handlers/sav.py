"""
handlers/sav.py — CSFPSAV: Set Attribute Value (service tag 11).

Request (from icsf_set_attribute() in icsf.c):

    SAVInput ::= Attributes   -- same encoding as icsf_ber_put_attribute_list()

    The attribute list is the *direct contents* of the context-constructed TLV
    (no wrapping SEQUENCE around the list items — the outer SEQUENCE is the
    context TLV itself).

Response:

    SAVOutput ::= NULL   -- no service-specific output; just check rc/reason.

The handle identifies the object to update (token_name + sequence + type).
"""

import logging
from ber_codec import (
    encode_response, encode_sequence,
    decode_attribute_list,
    parse_handle
)

logger = logging.getLogger(__name__)

ICSF_TAG_CSFPSAV = 11

RC_SUCCESS        = 0
RC_ERROR          = 8
RSN_OBJ_NOT_FOUND = 3025


def handle_sav(store, request):
    """
    Process a CSFPSAV request.

    Parameters
    ----------
    store   : TokenStore
    request : ICSFRequest

    Returns
    -------
    bytes — raw BER responseValue
    """
    token_name, sequence, obj_type = parse_handle(request.handle)

    if not token_name or sequence == 0:
        logger.error('SAV: invalid handle (token=%r seq=%d)', token_name, sequence)
        return encode_response(
            request.handle, RC_ERROR, 3001, ICSF_TAG_CSFPSAV, b'')

    # service_data is the raw BER contents of the context-constructed TLV.
    # icsf_set_attribute() calls icsf_ber_put_attribute_list() which writes a
    # SEQUENCE OF SEQUENCE directly; we need to wrap it in a SEQUENCE tag so
    # decode_attribute_list() can parse it.
    attrs = []
    try:
        wrapped = encode_sequence(request.service_data)
        attrs = decode_attribute_list(wrapped)
    except Exception as exc:
        logger.warning('SAV: could not decode attribute list: %s', exc)

    if not store.get_object(token_name, sequence):
        logger.warning('SAV: object not found token=%r seq=%d', token_name, sequence)
        return encode_response(
            request.handle, RC_ERROR, RSN_OBJ_NOT_FOUND, ICSF_TAG_CSFPSAV, b'')

    logger.info('SAV: token=%r seq=%d setting %d attributes',
                token_name, sequence, len(attrs))

    store.set_object_attrs(token_name, sequence, attrs)

    # SAVOutput is NULL — no service data
    return encode_response(request.handle, RC_SUCCESS, 0, ICSF_TAG_CSFPSAV, b'')
