# kernel_types.py
#
# This module provides classes and functions to parse the JSON output
# from the dwarf2json tool (https://github.com/volatilityfoundation/dwarf2json),
# specifically its Intermediate Symbol File (ISF) format.
# It uses ujson for faster parsing if available, implements lazy loading for types,
# supports .json.xz compressed files, uses __slots__ for memory efficiency,
# caches compiled struct formatters, allows symbol lookup by address,
# offers flexible type input for create_instance, supports writing to fields,
# and provides a to_bytes() method for instances.

try:
    import ujson as json
    _JSON_LIB_USED = "ujson"
except ImportError:
    import json
    _JSON_LIB_USED = "json"

import base64
import struct  # For unpacking data from buffers
import argparse  # For command-line argument parsing
import sys  # For exiting script
import lzma  # For handling .xz compressed files
import os  # For path operations
from typing import List, Dict, Any, Optional, Union


class SourceMetadata:
    """Represents source file metadata within the ISF."""
    __slots__ = 'kind', 'name', 'hash_type', 'hash_value'

    def __init__(self, data: Dict[str, Any]):
        self.kind: Optional[str] = data.get("kind")
        self.name: Optional[str] = data.get("name")
        self.hash_type: Optional[str] = data.get("hash_type")
        self.hash_value: Optional[str] = data.get("hash_value")

    def __repr__(self) -> str:
        return f"<SourceMetadata Name='{self.name}' Kind='{self.kind}'>"


class UnixMetadata:
    """Represents Unix-specific (Linux/Mac) metadata within the ISF."""
    __slots__ = 'symbols', 'types'

    def __init__(self, data: Dict[str, Any]):
        self.symbols: List[SourceMetadata] = [
            SourceMetadata(s_data) for s_data in data.get("symbols", []) if s_data
        ]
        self.types: List[SourceMetadata] = [
            SourceMetadata(t_data) for t_data in data.get("types", []) if t_data
        ]

    def __repr__(self) -> str:
        return f"<UnixMetadata Symbols={len(self.symbols)} Types={len(self.types)}>"


class VtypeMetadata:
    """Represents the top-level metadata in the ISF."""
    __slots__ = 'linux', 'mac', 'producer', 'format_version'

    def __init__(self, data: Dict[str, Any]):
        self.linux: Optional[UnixMetadata] = UnixMetadata(
            data["linux"]) if data.get("linux") else None
        self.mac: Optional[UnixMetadata] = UnixMetadata(
            data["mac"]) if data.get("mac") else None
        self.producer: Dict[str, str] = data.get("producer", {})
        self.format_version: Optional[str] = data.get("format")

    def __repr__(self) -> str:
        return f"<VtypeMetadata Format='{self.format_version}' Producer='{self.producer.get('name')}'>"


class VtypeBaseType:
    """Represents a base type definition in the ISF (e.g., int, char)."""
    __slots__ = 'name', 'size', 'signed', 'kind', 'endian', '_compiled_struct'

    def __init__(self, name: str, data: Dict[str, Any]):
        self.name: str = name
        self.size: Optional[int] = data.get("size")
        self.signed: Optional[bool] = data.get("signed")
        self.kind: Optional[str] = data.get("kind")
        self.endian: Optional[str] = data.get("endian")
        self._compiled_struct: Optional[struct.Struct] = None

    def get_compiled_struct(self) -> Optional[struct.Struct]:
        if hasattr(self, '_compiled_struct') and self._compiled_struct is not None:
            if self.size == 0 and self._compiled_struct is None:
                return None
            if self.size != 0:
                return self._compiled_struct
        elif self.size == 0:
            self._compiled_struct = None
            return None

        if self.size is None or self.kind is None or self.endian is None:
            return None
        if self.size == 0 and self.kind == "void":
            self._compiled_struct = None
            return None

        endian_char = '<' if self.endian == 'little' else '>'
        fmt_char: Optional[str] = None

        if self.kind == "int" or self.kind == "pointer":
            if self.size == 1:
                fmt_char = 'b' if self.signed else 'B'
            elif self.size == 2:
                fmt_char = 'h' if self.signed else 'H'
            elif self.size == 4:
                fmt_char = 'i' if self.signed else 'I'
            elif self.size == 8:
                fmt_char = 'q' if self.signed else 'Q'
        elif self.kind == "char":
            if self.size == 1:
                fmt_char = 'b' if self.signed else 'B'
        elif self.kind == "bool":
            if self.size == 1:
                fmt_char = '?'
        elif self.kind == "float":
            if self.size == 4:
                fmt_char = 'f'
            elif self.size == 8:
                fmt_char = 'd'

        if fmt_char:
            try:
                self._compiled_struct = struct.Struct(endian_char + fmt_char)
            except struct.error:
                self._compiled_struct = None
        else:
            self._compiled_struct = None

        return self._compiled_struct

    def __repr__(self) -> str:
        return f"<VtypeBaseType Name='{self.name}' Kind='{self.kind}' Size={self.size} Signed={self.signed}>"


class VtypeStructField:
    """Represents a field within a user-defined struct or union."""
    __slots__ = 'name', 'type_info', 'offset', 'anonymous'

    def __init__(self, name: str, data: Dict[str, Any]):
        self.name: str = name
        self.type_info: Dict[str, Any] = data.get("type", {})
        self.offset: Optional[int] = data.get("offset")
        self.anonymous: Optional[bool] = data.get("anonymous", False)

    def __repr__(self) -> str:
        type_kind = self.type_info.get('kind', 'unknown')
        type_name_val = self.type_info.get('name', '')
        name_part = f" TypeName='{type_name_val}'" if type_name_val else ""
        return f"<VtypeStructField Name='{self.name}' Offset={self.offset} TypeKind='{type_kind}'{name_part}>"


class VtypeUserType:
    """Represents a user-defined type (struct or union) in the ISF."""
    __slots__ = 'name', 'size', 'fields', 'kind'

    def __init__(self, name: str, data: Dict[str, Any]):
        self.name: str = name
        self.size: Optional[int] = data.get("size")
        self.fields: Dict[str, VtypeStructField] = {
            f_name: VtypeStructField(f_name, f_data) for f_name, f_data in data.get("fields", {}).items() if f_data
        }
        self.kind: Optional[str] = data.get("kind")

    def __repr__(self) -> str:
        return f"<VtypeUserType Name='{self.name}' Kind='{self.kind}' Size={self.size} Fields={len(self.fields)}>"


class VtypeEnum:
    """Represents an enumeration type in the ISF."""
    __slots__ = 'name', 'size', 'base', 'constants', '_val_to_name'

    def __init__(self, name: str, data: Dict[str, Any]):
        self.name: str = name
        self.size: Optional[int] = data.get("size")
        self.base: Optional[str] = data.get("base")
        self.constants: Dict[str, int] = data.get("constants", {})
        self._val_to_name: Optional[Dict[int, str]] = None

    def get_name_for_value(self, value: int) -> Optional[str]:
        if self._val_to_name is None:
            self._val_to_name = {v: k for k, v in self.constants.items()}
        return self._val_to_name.get(value)

    def __repr__(self) -> str:
        return f"<VtypeEnum Name='{self.name}' Size={self.size} Base='{self.base}' Constants={len(self.constants)}>"


class VtypeSymbol:
    """Represents a symbol (variable or function) in the ISF."""
    __slots__ = 'name', 'type_info', 'address', 'constant_data'

    def __init__(self, name: str, data: Dict[str, Any]):
        self.name: str = name
        self.type_info: Optional[Dict[str, Any]] = data.get("type")
        self.address: Optional[int] = data.get("address")
        self.constant_data: Optional[str] = data.get("constant_data")

    def get_decoded_constant_data(self) -> Optional[bytes]:
        if self.constant_data:
            try:
                return base64.b64decode(self.constant_data)
            except Exception:
                return None
        return None

    def __repr__(self) -> str:
        type_kind = self.type_info.get(
            'kind', 'N/A') if self.type_info else 'N/A'
        return f"<VtypeSymbol Name='{self.name}' Address={self.address:#x if self.address is not None else 'N/A'} TypeKind='{type_kind}'>"


class BoundTypeInstance:
    """Represents an instance of a DWARF type bound to a memory buffer (bytearray for writability)."""

    def __init__(self, type_name: str, type_def: Union[VtypeUserType, VtypeBaseType, VtypeEnum],
                 buffer: bytearray, vtype_accessor: 'VtypeJson',
                 instance_offset_in_buffer: int = 0):
        # Internal check, create_instance should ensure this.
        # Should have been handled by VtypeJson.create_instance
        if not isinstance(buffer, bytearray):
            raise TypeError(
                "Internal Error: BoundTypeInstance expects a bytearray.")
        self._instance_type_name = type_name
        self._instance_type_def = type_def
        self._instance_buffer = buffer
        self._instance_vtype_accessor = vtype_accessor
        self._instance_offset = instance_offset_in_buffer
        self._instance_cache = {}

    def _read_data(self, field_type_info: Dict[str, Any], field_offset_in_struct: int, field_name_for_error: str) -> Any:
        kind = field_type_info.get("kind")
        name = field_type_info.get("name")
        absolute_field_offset = self._instance_offset + field_offset_in_struct

        if kind == "base":
            if name is None:
                raise ValueError(
                    f"Base type for field '{field_name_for_error}' has no name.")
            base_type_def = self._instance_vtype_accessor.get_base_type(name)
            if base_type_def is None:
                raise ValueError(
                    f"Base type '{name}' not found for field '{field_name_for_error}'.")

            compiled_struct_obj = base_type_def.get_compiled_struct()
            if base_type_def.size == 0:
                return None
            if compiled_struct_obj is None:
                raise ValueError(
                    f"Cannot get compiled struct for base type '{name}' (size: {base_type_def.size}).")

            try:
                return compiled_struct_obj.unpack_from(self._instance_buffer, absolute_field_offset)[0]
            except struct.error as e:
                raise struct.error(
                    f"Error unpacking base type '{name}' for field '{field_name_for_error}' at offset {absolute_field_offset} (buffer len {len(self._instance_buffer)}): {e}")

        elif kind == "pointer":
            ptr_base_type = self._instance_vtype_accessor.get_base_type(
                "pointer")
            if ptr_base_type is None:
                raise ValueError("Base type 'pointer' definition not found.")

            compiled_struct_obj = ptr_base_type.get_compiled_struct()
            if compiled_struct_obj is None:
                raise ValueError(
                    "Cannot get compiled struct for 'pointer' base type.")
            try:
                address = compiled_struct_obj.unpack_from(
                    self._instance_buffer, absolute_field_offset)[0]
                return Ptr(address, field_type_info.get("subtype"), self._instance_vtype_accessor)
            except struct.error as e:
                raise struct.error(
                    f"Error unpacking pointer for field '{field_name_for_error}' at offset {absolute_field_offset}: {e}")

        elif kind == "array":
            count = field_type_info.get("count", 0)
            subtype_info = field_type_info.get("subtype")
            if subtype_info is None:
                raise ValueError(
                    f"Array field '{field_name_for_error}' has no subtype.")
            elements = []
            current_element_struct_offset = field_offset_in_struct
            for i in range(count):
                try:
                    element = self._read_data(
                        subtype_info, current_element_struct_offset, f"{field_name_for_error}[{i}]")
                    elements.append(element)
                except (ValueError, struct.error) as e:
                    elements.append(
                        f"<Error reading element {i} of {field_name_for_error}: {e}>")
                element_size = self._instance_vtype_accessor.get_type_size(
                    subtype_info)
                if element_size is None:
                    if i < count - 1:
                        elements.append(
                            f"<Error: Cannot get subtype size for '{field_name_for_error}', array incomplete.>")
                    break
                current_element_struct_offset += element_size
            return elements

        elif kind == "struct" or kind == "union":
            if name is None:
                raise ValueError(
                    f"User type for field '{field_name_for_error}' has no name.")
            user_type_def = self._instance_vtype_accessor.get_user_type(name)
            if user_type_def is None:
                raise ValueError(
                    f"User type '{name}' not found for field '{field_name_for_error}'.")
            return BoundTypeInstance(name, user_type_def, self._instance_buffer, self._instance_vtype_accessor, absolute_field_offset)

        elif kind == "enum":
            if name is None:
                raise ValueError(
                    f"Enum type for field '{field_name_for_error}' has no name.")
            enum_def = self._instance_vtype_accessor.get_enum(name)
            if enum_def is None:
                raise ValueError(
                    f"Enum type '{name}' not found for field '{field_name_for_error}'.")
            if enum_def.base is None:
                raise ValueError(f"Enum '{name}' has no base type.")
            base_type_def = self._instance_vtype_accessor.get_base_type(
                enum_def.base)
            if base_type_def is None:
                raise ValueError(
                    f"Base type '{enum_def.base}' for enum '{name}' not found.")

            compiled_struct_obj = base_type_def.get_compiled_struct()
            if compiled_struct_obj is None:
                raise ValueError(
                    f"Cannot get compiled struct for enum base type '{enum_def.base}'.")

            int_val = compiled_struct_obj.unpack_from(
                self._instance_buffer, absolute_field_offset)[0]
            return EnumInstance(enum_def, int_val)

        elif kind == "bitfield":
            bit_length = field_type_info.get("bit_length")
            bit_position = field_type_info.get("bit_position")
            underlying_type_info = field_type_info.get("type")
            if None in [bit_length, bit_position, underlying_type_info]:
                raise ValueError(
                    f"Bitfield '{field_name_for_error}' missing properties.")
            underlying_base_name = underlying_type_info.get("name")
            if underlying_base_name is None:
                raise ValueError(
                    f"Bitfield '{field_name_for_error}' underlying type has no name.")
            underlying_base_def = self._instance_vtype_accessor.get_base_type(
                underlying_base_name)
            if underlying_base_def is None or underlying_base_def.size is None:
                raise ValueError(
                    f"Cannot get underlying type definition or size for bitfield '{field_name_for_error}'.")

            compiled_struct_obj = underlying_base_def.get_compiled_struct()
            if compiled_struct_obj is None:
                raise ValueError(
                    f"Cannot get compiled struct for bitfield '{field_name_for_error}' underlying type.")

            storage_unit_val = compiled_struct_obj.unpack_from(
                self._instance_buffer, absolute_field_offset)[0]
            mask = (1 << bit_length) - 1
            return (storage_unit_val >> bit_position) & mask

        elif kind == "function":
            return f"<FunctionType: {field_type_info.get('name', 'anon_func')}>"
        elif kind == "void" and field_type_info.get("name") == "void":
            return None
        else:
            raise ValueError(
                f"Unsupported/invalid type kind '{kind}' for field '{field_name_for_error}'.")

    def _write_data(self, field_type_info: Dict[str, Any], field_offset_in_struct: int,
                    value_to_write: Any, field_name_for_error: str):
        kind = field_type_info.get("kind")
        name = field_type_info.get("name")
        absolute_field_offset = self._instance_offset + field_offset_in_struct

        if kind == "base":
            if name is None:
                raise ValueError(
                    f"Base type for field '{field_name_for_error}' has no name.")
            base_type_def = self._instance_vtype_accessor.get_base_type(name)
            if base_type_def is None:
                raise ValueError(
                    f"Base type '{name}' not found for field '{field_name_for_error}'.")

            compiled_struct_obj = base_type_def.get_compiled_struct()
            if base_type_def.size == 0:
                if value_to_write is not None:
                    raise ValueError(
                        f"Cannot write value to void type field '{field_name_for_error}'.")
                return
            if compiled_struct_obj is None:
                raise ValueError(
                    f"Cannot get compiled struct for base type '{name}' (size: {base_type_def.size}) to write field '{field_name_for_error}'.")
            try:
                compiled_struct_obj.pack_into(
                    self._instance_buffer, absolute_field_offset, value_to_write)
            except struct.error as e:
                raise struct.error(
                    f"Error packing base type '{name}' for field '{field_name_for_error}' at offset {absolute_field_offset} with value '{value_to_write}': {e}")

        elif kind == "pointer":
            ptr_base_type = self._instance_vtype_accessor.get_base_type(
                "pointer")
            if ptr_base_type is None:
                raise ValueError(
                    "Base type 'pointer' definition not found for writing.")

            compiled_struct_obj = ptr_base_type.get_compiled_struct()
            if compiled_struct_obj is None:
                raise ValueError(
                    "Cannot get compiled struct for 'pointer' base type for writing.")

            address_to_write: int
            if isinstance(value_to_write, Ptr):
                address_to_write = value_to_write.address
            elif isinstance(value_to_write, int):
                address_to_write = value_to_write
            else:
                raise TypeError(
                    f"Cannot write type '{type(value_to_write)}' to pointer field '{field_name_for_error}'. Expected Ptr or int.")
            try:
                compiled_struct_obj.pack_into(
                    self._instance_buffer, absolute_field_offset, address_to_write)
            except struct.error as e:
                raise struct.error(
                    f"Error packing pointer for field '{field_name_for_error}' at offset {absolute_field_offset} with address {address_to_write:#x}: {e}")

        elif kind == "enum":
            if name is None:
                raise ValueError(
                    f"Enum type for field '{field_name_for_error}' has no name.")
            enum_def = self._instance_vtype_accessor.get_enum(name)
            if enum_def is None:
                raise ValueError(
                    f"Enum type '{name}' not found for field '{field_name_for_error}'.")
            if enum_def.base is None:
                raise ValueError(
                    f"Enum '{name}' has no base type defined for writing.")
            base_type_def = self._instance_vtype_accessor.get_base_type(
                enum_def.base)
            if base_type_def is None:
                raise ValueError(
                    f"Base type '{enum_def.base}' for enum '{name}' not found for writing.")

            compiled_struct_obj = base_type_def.get_compiled_struct()
            if compiled_struct_obj is None:
                raise ValueError(
                    f"Cannot get compiled struct for enum base type '{enum_def.base}' for writing.")

            int_val_to_write: int
            if isinstance(value_to_write, EnumInstance):
                int_val_to_write = value_to_write.value
            elif isinstance(value_to_write, int):
                int_val_to_write = value_to_write
            elif isinstance(value_to_write, str):
                found_val = enum_def.constants.get(value_to_write)
                if found_val is None:
                    raise ValueError(
                        f"Enum constant name '{value_to_write}' not found in enum '{name}'.")
                int_val_to_write = found_val
            else:
                raise TypeError(
                    f"Cannot write type '{type(value_to_write)}' to enum field '{field_name_for_error}'. Expected EnumInstance, int, or str.")
            try:
                compiled_struct_obj.pack_into(
                    self._instance_buffer, absolute_field_offset, int_val_to_write)
            except struct.error as e:
                raise struct.error(
                    f"Error packing enum '{name}' for field '{field_name_for_error}' at offset {absolute_field_offset} with value {int_val_to_write}: {e}")

        elif kind == "bitfield":
            bit_length = field_type_info.get("bit_length")
            bit_position = field_type_info.get("bit_position")
            underlying_type_info = field_type_info.get("type")
            if None in [bit_length, bit_position, underlying_type_info]:
                raise ValueError(
                    f"Bitfield '{field_name_for_error}' missing properties for writing.")

            underlying_base_name = underlying_type_info.get("name")
            if underlying_base_name is None:
                raise ValueError(
                    f"Bitfield '{field_name_for_error}' underlying type has no name for writing.")
            underlying_base_def = self._instance_vtype_accessor.get_base_type(
                underlying_base_name)
            if underlying_base_def is None or underlying_base_def.size is None:
                raise ValueError(
                    f"Cannot get underlying type definition or size for bitfield '{field_name_for_error}' for writing.")

            compiled_struct_obj = underlying_base_def.get_compiled_struct()
            if compiled_struct_obj is None:
                raise ValueError(
                    f"Cannot get compiled struct for bitfield '{field_name_for_error}' underlying type for writing.")

            current_storage_val = compiled_struct_obj.unpack_from(
                self._instance_buffer, absolute_field_offset)[0]

            if not isinstance(value_to_write, int):
                raise TypeError(
                    f"Value for bitfield '{field_name_for_error}' must be an integer, got {type(value_to_write)}.")

            mask = (1 << bit_length) - 1
            value_to_set = value_to_write & mask

            new_storage_val = (current_storage_val & ~(
                mask << bit_position)) | (value_to_set << bit_position)

            try:
                compiled_struct_obj.pack_into(
                    self._instance_buffer, absolute_field_offset, new_storage_val)
            except struct.error as e:
                raise struct.error(
                    f"Error packing bitfield '{field_name_for_error}' at offset {absolute_field_offset} with new storage value {new_storage_val}: {e}")

        elif kind == "array" or kind == "struct" or kind == "union":
            raise NotImplementedError(
                f"Direct assignment to field '{field_name_for_error}' of type '{kind}' is not supported. Modify elements or nested fields individually.")

        else:
            raise TypeError(
                f"Cannot write to field '{field_name_for_error}' of unhandled type kind '{kind}'.")

    def __getattr__(self, name: str) -> Any:
        if name.startswith('_instance_'):
            return super().__getattribute__(name)
        if name in self._instance_cache:
            return self._instance_cache[name]
        if not isinstance(self._instance_type_def, VtypeUserType):
            raise AttributeError(
                f"Type '{self._instance_type_name}' is not struct/union, no field '{name}'.")
        field_def = self._instance_type_def.fields.get(name)
        if field_def is None:
            raise AttributeError(
                f"'{self._instance_type_name}' has no attribute '{name}'")
        if field_def.offset is None:
            raise ValueError(
                f"Field '{name}' in '{self._instance_type_name}' has no offset.")
        try:
            value = self._read_data(
                field_def.type_info, field_def.offset, name)
            if field_def.type_info.get("kind") in ["struct", "union", "array"]:
                self._instance_cache[name] = value
            return value
        except (struct.error, ValueError) as e:
            raise AttributeError(f"Error processing field '{name}': {e}")

    def __setattr__(self, name: str, value: Any):
        if name.startswith('_instance_'):
            super().__setattr__(name, value)
            return

        if not isinstance(self._instance_type_def, VtypeUserType):
            raise AttributeError(
                f"Cannot set attribute '{name}' on non-struct/union type '{self._instance_type_name}'.")

        field_def = self._instance_type_def.fields.get(name)
        if field_def is None:
            super().__setattr__(name, value)
            return

        if field_def.offset is None:
            raise ValueError(
                f"Field '{name}' in '{self._instance_type_name}' has no offset, cannot write.")

        try:
            self._write_data(field_def.type_info,
                             field_def.offset, value, name)
            if name in self._instance_cache:
                del self._instance_cache[name]
        except (struct.error, ValueError, TypeError, NotImplementedError) as e:
            raise AttributeError(f"Error setting field '{name}': {e}")

    def to_bytes(self) -> bytes:
        """
        Returns a 'bytes' object representing the portion of the underlying
        buffer that corresponds to this specific instance.
        """
        if not isinstance(self._instance_type_def, VtypeUserType):
            raise TypeError(
                f"to_bytes() is primarily for struct/union instances. Type is {self._instance_type_name}")

        size = self._instance_type_def.size
        if size is None:
            raise ValueError(
                f"Cannot determine size for type '{self._instance_type_name}' to get bytes.")

        start = self._instance_offset
        end = start + size
        return bytes(self._instance_buffer[start:end])

    @property
    def offset(self) -> int:
        """Returns the offset of this instance within the buffer."""
        return self._instance_offset

    def __repr__(self) -> str:
        return f"<BoundTypeInstance Type='{self._instance_type_name}' AtOffset={self._instance_offset}>"

    def __dir__(self):
        attrs = list(super().__dir__())
        if isinstance(self._instance_type_def, VtypeUserType):
            attrs.extend(self._instance_type_def.fields.keys())
        return sorted(list(set(a for a in attrs if a != '_instance_cache')))


class Ptr:
    """Represents a pointer, holding an address and its target type information."""
    __slots__ = 'address', '_subtype_info', '_vtype_accessor'

    def __init__(self, address: int, subtype_info: Optional[Dict[str, Any]], vtype_accessor: 'VtypeJson'):
        self.address = address
        self._subtype_info = subtype_info
        self._vtype_accessor = vtype_accessor

    def __repr__(self) -> str:
        subtype_str = "void"
        if self._subtype_info:
            kind, name = self._subtype_info.get(
                "kind"), self._subtype_info.get("name")
            subtype_str = name if name else (kind if kind else "unknown")
        return f"<Ptr ToType='{subtype_str}' Address={self.address:#x}>"

    @property
    def points_to_type_info(
        self) -> Optional[Dict[str, Any]]: return self._subtype_info

    @property
    def points_to_type_name(self) -> str:
        if not self._subtype_info:
            return "void"
        name, kind = self._subtype_info.get(
            "name"), self._subtype_info.get("kind")
        if name:
            return name
        return "void" if kind == "base" and not name else (kind if kind else "unknown")


class EnumInstance:
    """Represents an instance of an enum, holding its definition and integer value."""
    __slots__ = '_enum_def', 'value'

    def __init__(self, enum_def: VtypeEnum, value: int):
        self._enum_def = enum_def
        self.value = value

    @property
    def name(
        self) -> Optional[str]: return self._enum_def.get_name_for_value(self.value)

    def __repr__(self) -> str:
        name_part = f"{self._enum_def.name}.{self.name}" if self.name else f"{self._enum_def.name} (value)"
        return f"<EnumInstance {name_part} ({self.value})>"

    def __int__(self) -> int: return self.value

    def __eq__(self, other):
        if isinstance(other, EnumInstance):
            return self.value == other.value and self._enum_def.name == other._enum_def.name
        if isinstance(other, int):
            return self.value == other
        if isinstance(other, str):
            return self.name == other
        return False


class VtypeJson:
    """Top-level container for ISF JSON, enabling lazy loading of type definitions."""

    def __init__(self, data: Dict[str, Any]):
        self.metadata: VtypeMetadata = VtypeMetadata(data.get("metadata", {}))
        self._raw_base_types: Dict[str, Any] = data.get("base_types", {})
        self._parsed_base_types_cache: Dict[str, VtypeBaseType] = {}
        self._raw_user_types: Dict[str, Any] = data.get("user_types", {})
        self._parsed_user_types_cache: Dict[str, VtypeUserType] = {}
        self._raw_enums: Dict[str, Any] = data.get("enums", {})
        self._parsed_enums_cache: Dict[str, VtypeEnum] = {}
        self._raw_symbols: Dict[str, Any] = data.get("symbols", {})
        self._parsed_symbols_cache: Dict[str, VtypeSymbol] = {}
        self._address_to_symbol_list_cache: Optional[Dict[int,
                                                          List[VtypeSymbol]]] = None

    def get_base_type(self, name: str) -> Optional[VtypeBaseType]:
        if name in self._parsed_base_types_cache:
            return self._parsed_base_types_cache[name]
        raw_data = self._raw_base_types.get(name)
        if raw_data is None:
            return None
        obj = VtypeBaseType(name, raw_data)
        self._parsed_base_types_cache[name] = obj
        return obj

    def get_user_type(self, name: str) -> Optional[VtypeUserType]:
        if name in self._parsed_user_types_cache:
            return self._parsed_user_types_cache[name]
        raw_data = self._raw_user_types.get(name)
        if raw_data is None:
            return None
        obj = VtypeUserType(name, raw_data)
        self._parsed_user_types_cache[name] = obj
        return obj

    def get_enum(self, name: str) -> Optional[VtypeEnum]:
        if name in self._parsed_enums_cache:
            return self._parsed_enums_cache[name]
        raw_data = self._raw_enums.get(name)
        if raw_data is None:
            return None
        obj = VtypeEnum(name, raw_data)
        self._parsed_enums_cache[name] = obj
        return obj

    def get_symbol(self, name: str) -> Optional[VtypeSymbol]:
        if name in self._parsed_symbols_cache:
            return self._parsed_symbols_cache[name]
        raw_data = self._raw_symbols.get(name)
        if raw_data is None:
            return None
        obj = VtypeSymbol(name, raw_data)
        self._parsed_symbols_cache[name] = obj
        return obj

    def get_symbols_by_address(self, target_address: int) -> List[VtypeSymbol]:
        if self._address_to_symbol_list_cache is None:
            self._address_to_symbol_list_cache = {}
            for symbol_name in self._raw_symbols.keys():
                symbol_obj = self.get_symbol(symbol_name)
                if symbol_obj and symbol_obj.address is not None:
                    self._address_to_symbol_list_cache.setdefault(
                        symbol_obj.address, []).append(symbol_obj)

        return self._address_to_symbol_list_cache.get(target_address, [])

    def get_type_size(self, type_info: Dict[str, Any]) -> Optional[int]:
        kind, name = type_info.get("kind"), type_info.get("name")
        if kind == "base":
            base_def = self.get_base_type(name) if name else None
            return base_def.size if base_def else None
        if kind == "pointer":
            ptr_base_def = self.get_base_type("pointer")
            return ptr_base_def.size if ptr_base_def else None
        if kind in ["struct", "union"]:
            user_def = self.get_user_type(name) if name else None
            return user_def.size if user_def else None
        if kind == "enum":
            enum_def = self.get_enum(name) if name else None
            if not enum_def or not enum_def.base:
                return None
            base_type_for_enum = self.get_base_type(enum_def.base)
            return base_type_for_enum.size if base_type_for_enum else None
        if kind == "array":
            count, subtype_info = type_info.get(
                "count"), type_info.get("subtype")
            if None in [count, subtype_info]:
                return None
            element_size = self.get_type_size(subtype_info)
            return count * element_size if element_size is not None else None
        if kind == "bitfield":
            underlying_type_info = type_info.get("type")
            return self.get_type_size(underlying_type_info) if underlying_type_info else None
        return None

    def create_instance(self, type_input: Union[str, VtypeUserType],
                        # Accept bytes or bytearray
                        buffer: Union[bytes, bytearray],
                        instance_offset_in_buffer: int = 0) -> BoundTypeInstance:
        user_type_def: Optional[VtypeUserType] = None
        type_name_for_instance: str

        processed_buffer: bytearray
        if isinstance(buffer, bytes):
            processed_buffer = bytearray(buffer)
        elif isinstance(buffer, bytearray):
            processed_buffer = buffer
        else:
            raise TypeError(
                "Input buffer for create_instance must be bytes or bytearray.")

        if isinstance(type_input, str):
            user_type_def = self.get_user_type(type_input)
            type_name_for_instance = type_input
        elif isinstance(type_input, VtypeUserType):
            user_type_def = type_input
            type_name_for_instance = user_type_def.name
        else:
            raise TypeError(
                f"type_input must be a string (type name) or VtypeUserType object, got {type(type_input)}")

        if user_type_def:
            effective_len = len(processed_buffer) - instance_offset_in_buffer
            if user_type_def.size is not None and user_type_def.size > effective_len:
                raise ValueError(
                    f"Buffer too small for '{type_name_for_instance}' at offset {instance_offset_in_buffer}. Need {user_type_def.size}, got {effective_len}.")
            return BoundTypeInstance(type_name_for_instance, user_type_def, processed_buffer, self, instance_offset_in_buffer)

        if isinstance(type_input, str):
            if self.get_base_type(type_input):
                raise NotImplementedError(
                    f"Direct instance creation for base type '{type_input}' not primary use case. Use for struct/union types.")
            if self.get_enum(type_input):
                raise NotImplementedError(
                    f"Direct instance creation for enum type '{type_input}' not primary use case. Use for struct/union types.")

        raise ValueError(
            f"User type definition for '{type_input if isinstance(type_input, str) else type_input.name}' not found or not a VtypeUserType.")

    def __repr__(self) -> str:
        return (f"<VtypeJson RawBaseTypes={len(self._raw_base_types)} RawUserTypes={len(self._raw_user_types)} "
                f"RawEnums={len(self._raw_enums)} RawSymbols={len(self._raw_symbols)} (Lazy Loaded)>")


def load_isf_json(json_input: Union[str, object]) -> VtypeJson:
    global _JSON_LIB_USED
    raw_data: Any
    input_is_path_str = isinstance(json_input, str)
    if input_is_path_str:
        path_str = str(json_input)
        is_xz = path_str.endswith(".xz")
        try:
            if is_xz:
                with lzma.open(path_str, 'rt', encoding='utf-8') as f:
                    raw_data = json.load(f)
            else:
                with open(path_str, 'r', encoding='utf-8') as f:
                    raw_data = json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(
                f"The ISF JSON file was not found: {path_str}")
        except (IOError, OSError) as e:
            raise ValueError(
                f"Could not open or read file '{path_str}'. Error: {e}") from e
        except json.JSONDecodeError as e:
            raise ValueError(
                f"Error decoding JSON from file {path_str} (using {_JSON_LIB_USED}).") from e
        except lzma.LZMAError as e:
            raise ValueError(f"Error decompressing XZ file {path_str}.") from e
    elif hasattr(json_input, 'read'):
        try:
            raw_data = json.load(json_input)
        except json.JSONDecodeError as e:
            raise ValueError(
                f"Error decoding JSON from file-like object (using {_JSON_LIB_USED}).") from e
    else:
        raise TypeError(
            f"Input must be a JSON string (path or content), or a file-like object. Got {type(json_input)}.")
    if not isinstance(raw_data, dict):
        raise ValueError(
            "ISF JSON root must be an object, not a list or other type.")
    return VtypeJson(raw_data)


if __name__ == '__main__':
    cli_parser = argparse.ArgumentParser(
        description="Load and parse a dwarf2json ISF (Intermediate Symbol File) JSON or JSON.XZ.",
        epilog=f"This script uses the '{_JSON_LIB_USED}' library for JSON parsing."
    )
    cli_parser.add_argument(
        "json_file_path",
        type=str,
        help="Path to the ISF JSON or JSON.XZ file to be loaded."
    )
    cli_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print more detailed information about the loaded data."
    )
    cli_parser.add_argument(
        "--find-symbol-at",
        type=lambda x: int(x, 0),
        metavar="ADDRESS",
        help="Find and print symbols at the given address (e.g., 0xffffffff81000000)."
    )
    cli_parser.add_argument(
        "--test-write",
        action="store_true",
        help="Run a small test of writing to a field if 'my_struct' is defined (for dev purposes)."
    )
    cli_parser.add_argument(
        "--test-to-bytes",
        action="store_true",
        help="Run a small test of the to_bytes() method if 'my_struct' is defined (for dev purposes)."
    )

    args = cli_parser.parse_args()
    print(
        f"Attempting to load ISF file: {args.json_file_path} (using {_JSON_LIB_USED})")

    try:
        isf_data: VtypeJson = load_isf_json(args.json_file_path)
        print("\nSuccessfully loaded ISF JSON.")
        print(f"  ISF Representation: {isf_data}")

        if args.find_symbol_at is not None:
            print(
                f"\n--- Finding symbols at address {args.find_symbol_at:#x} ---")
            symbols_at_addr = isf_data.get_symbols_by_address(
                args.find_symbol_at)
            if symbols_at_addr:
                print(
                    f"  Found {len(symbols_at_addr)} symbol(s) at {args.find_symbol_at:#x}:")
                for sym_obj in symbols_at_addr:
                    print(f"    - {sym_obj}")
            else:
                print(
                    f"  No symbols found at address {args.find_symbol_at:#x}.")
            if isf_data._address_to_symbol_list_cache is not None:
                print(
                    f"  Address-to-symbol cache is now populated with {len(isf_data._address_to_symbol_list_cache)} entries.")

        if args.verbose:
            print("\n--- Verbose Information ---")
            print(
                f"  Metadata Producer: {isf_data.metadata.producer.get('name', 'N/A')}, Version: {isf_data.metadata.producer.get('version', 'N/A')}")
            print(f"  ISF Format Version: {isf_data.metadata.format_version}")
            print(
                f"  Number of raw base types defined: {len(isf_data._raw_base_types)}")
            print(
                f"  Number of raw user types defined: {len(isf_data._raw_user_types)}")
            print(f"  Number of raw enums defined: {len(isf_data._raw_enums)}")
            print(
                f"  Number of raw symbols defined: {len(isf_data._raw_symbols)}")
            # ... (rest of verbose printing) ...

        if args.test_write or args.test_to_bytes:
            print("\n--- Testing Field Write and/or To Bytes Functionality ---")
            # Assumes 'my_struct' exists for test
            my_struct_def = isf_data.get_user_type("my_struct")
            if my_struct_def and my_struct_def.size is not None:
                # Use bytes for initial data, create_instance will convert to bytearray
                initial_bytes_data = bytearray(my_struct_def.size)
                struct.pack_into("<i", initial_bytes_data, 0, 100)      # id
                # status_flags=1, type_flag=0
                struct.pack_into("<B", initial_bytes_data, 4, 0b00000001)
                # ... (initialize other fields if necessary for a complete test)

                # Pass the bytearray to create_instance
                instance = isf_data.create_instance(
                    "my_struct", initial_bytes_data)

                if args.test_write:
                    print(f"  Initial id: {instance.id}")
                    instance.id = 999
                    # Check original bytearray
                    print(
                        f"  Modified id: {instance.id} (Buffer check: {struct.unpack_from('<i', initial_bytes_data, 0)[0]})")
                    # ... (more write tests as before) ...

                if args.test_to_bytes:
                    instance_bytes = instance.to_bytes()
                    print(
                        f"  instance.to_bytes() (hex): {instance_bytes.hex()}")
                    # Verify the slice is correct
                    expected_bytes = bytes(
                        initial_bytes_data[instance._instance_offset: instance._instance_offset + my_struct_def.size])
                    if instance_bytes == expected_bytes:
                        print(
                            "  to_bytes() content matches expected slice of the buffer.")
                    else:
                        print("  ERROR: to_bytes() content MISMATCH!")
                        print(f"    Expected (hex): {expected_bytes.hex()}")
            else:
                print(
                    "  Skipping write/to_bytes test: 'my_struct' not found or has no size in the loaded ISF.")

    except FileNotFoundError as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"\nError loading or parsing ISF file: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
