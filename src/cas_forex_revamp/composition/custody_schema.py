"""Closed, locally pinned subset for the six published custody schemas.

No remote resolution, schema extension, coercion, floats or ignored keywords.
This is not a general Draft 2020-12 implementation.
"""
from hashlib import sha256
import json
import re
from ..contracts import ContractError

PINS = {
    'common.schema.json': '772f16ad58d21ca6cb68f005863bda34b41a6908de1331ee000252aef41af21b',
    'custody-counterparts-v1.schema.json': '7973a281dbd1e6b187a8dcaf2247d85eee21737d0d9100e6ad1373443a58e855',
    'custody-independent-keys-v1.schema.json': 'fff0787a3e3125b2e75eb1c3e72bd8e01a314fd785763662acd20261022b3c33',
    'custody-predicate-catalogue-v1.schema.json': '471ee8386369c4e54ae7a94c8ce7d8f6c480ca3c3ca8b66a1a5caf341357a14a',
    'custody-schedules-v1.schema.json': 'bec61cbf273ae0d9f236a99fc783232ea81c3d74539d4d396fc2a6a4dfe44857',
    'custody-trajectories-v1.schema.json': 'a72738be1eb5ad53bcb8face1e7dfdbb249f87edecd8c4c9e79565b4cfb8a7ec'}
KEYWORDS = {'$schema', '$id', '$defs', '$ref', 'type', 'properties', 'required',
    'additionalProperties', 'propertyNames', 'minProperties', 'items', 'minItems',
    'maxItems', 'uniqueItems', 'minLength', 'maxLength', 'pattern', 'minimum',
    'maximum', 'const', 'enum', 'anyOf', 'oneOf'}


def load_json(raw):
    if type(raw) is not bytes or len(raw) > 4194304:
        raise ContractError('bounded raw custody JSON required')
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ContractError('duplicate custody JSON member')
            out[key] = value
        return out
    def bad(_):
        raise ContractError('floats and nonfinite custody JSON numbers are unsupported')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_float=bad, parse_constant=bad)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ContractError('invalid bounded custody JSON') from exc


def equal(left, right):
    return type(left) is type(right) and left == right


class CustodySchemas:
    def __init__(self, directory):
        self.documents, self.registry = {}, {}
        for name, pin in PINS.items():
            raw = (directory/name).read_bytes()
            if sha256(raw).hexdigest() != pin:
                raise ContractError('public custody schema pin differs')
            value = load_json(raw)
            self.documents[name] = value
            self.registry[value['$id']] = value
        for value in self.documents.values():
            self._inspect(value, ())

    def _resolve(self, ref):
        base, _, fragment = ref.partition('#')
        if base not in self.registry or (fragment and not fragment.startswith('/')):
            raise ContractError('unknown/nonlocal custody schema reference')
        target = self.registry[base]
        for part in fragment.split('/')[1:]:
            target = target[part.replace('~1', '/').replace('~0', '~')]
        return target

    def _inspect(self, schema, stack):
        if type(schema) is not dict or set(schema)-KEYWORDS or len(stack) > 64:
            raise ContractError('unsupported custody schema semantics')
        if '$ref' in schema:
            ref = schema['$ref']
            if ref in stack:
                raise ContractError('cyclic custody schema reference')
            self._inspect(self._resolve(ref), stack+(ref,))
        for name in ('$defs', 'properties'):
            for child in schema.get(name, {}).values():
                self._inspect(child, stack)
        for name in ('additionalProperties', 'propertyNames', 'items'):
            if type(schema.get(name)) is dict:
                self._inspect(schema[name], stack)
        for name in ('anyOf', 'oneOf'):
            for child in schema.get(name, []):
                self._inspect(child, stack)

    def validate(self, name, payload):
        self._validate(self.documents[name], payload, 0)
        return True

    def _validate(self, schema, value, depth):
        def need(ok):
            if not ok:
                raise ContractError('custody document does not match its pinned schema')
        need(depth <= 96)
        if '$ref' in schema:
            self._validate(self._resolve(schema['$ref']), value, depth+1)
        for choice in ('anyOf', 'oneOf'):
            if choice in schema:
                hits = 0
                for child in schema[choice]:
                    try:
                        self._validate(child, value, depth+1)
                        hits += 1
                    except ContractError:
                        pass
                need(hits == 1 if choice == 'oneOf' else hits >= 1)
        types = {'object': dict, 'array': list, 'string': str, 'integer': int,
                 'boolean': bool, 'null': type(None)}
        if 'type' in schema:
            need(type(value) is types[schema['type']])
        if 'const' in schema:
            need(equal(value, schema['const']))
        if 'enum' in schema:
            need(any(equal(value, x) for x in schema['enum']))
        if type(value) is dict:
            need(set(schema.get('required', [])) <= set(value))
            need(len(value) >= schema.get('minProperties', 0))
            for key, item in value.items():
                if 'propertyNames' in schema:
                    self._validate(schema['propertyNames'], key, depth+1)
                child = schema.get('properties', {}).get(key)
                if child is None:
                    child = schema.get('additionalProperties', True)
                need(child is not False)
                if child is not True:
                    self._validate(child, item, depth+1)
        if type(value) is list:
            need(schema.get('minItems', 0) <= len(value) <= schema.get('maxItems', 10000))
            if schema.get('uniqueItems'):
                need(len({json.dumps(x, sort_keys=True, separators=(',', ':')) for x in value}) == len(value))
            for item in value:
                self._validate(schema.get('items', {}), item, depth+1)
        if type(value) is str:
            need(schema.get('minLength', 0) <= len(value) <= schema.get('maxLength', 16384))
            need(len(value.encode()) <= 65536)
            if 'pattern' in schema:
                need(re.search(schema['pattern'], value) is not None)
        if type(value) is int:
            need(schema.get('minimum', -2147483648) <= value <= schema.get('maximum', 2147483647))
