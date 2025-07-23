"""
DWARF2JSON ISF Loader and Type Binding Utilities
================================================

This module provides classes and functions to parse the JSON output
from the dwarf2json tool (https://github.com/volatilityfoundation/dwarf2json),
specifically its Intermediate Symbol File (ISF) format.

Key Features:
-------------
- Fast parsing with ujson if available
- Lazy loading and caching of types, enums, and symbols
- .json.xz compressed file support
- Memory-efficient type objects using __slots__
- Symbol lookup by address
- Flexible type input for create_instance (including base/enum types)
- Field and value writing, including array element assignment
- to_bytes() method for serializing instances
- Generic get_type() method for resolving type names

How to Use:
-----------
1. Load an ISF file (JSON or JSON.XZ):

    from wrappers.ctypes_wrap import load_isf_json
    isf = load_isf_json("vmlinux.isf.json.xz")

2. Access type definitions:

    my_struct_def = isf.get_user_type("my_struct")
    int_def = isf.get_base_type("int")
    enum_def = isf.get_enum("my_enum")

3. Create an instance of a type bound to a buffer:

    buf = bytearray(my_struct_def.size)
    instance = isf.create_instance("my_struct", buf)
    print(instance.field1)
    instance.field1 = 42
    print(instance.to_bytes())

4. Work with arrays and enums:

    arr = instance.array_field
    arr[0] = 123
    print(arr[0])
    print(instance.enum_field.name)

5. Lookup symbols by address:

    syms = isf.get_symbols_by_address(0xffffffffdeadbeef)
    for sym in syms:
        print(sym.name, sym.address)

6. Create and manipulate base/enum type instances:

    int_buf = bytearray(int_def.size)
    int_instance = isf.create_instance("int", int_buf)
    int_instance._value = 123
    print(int_instance._value)

Command Line Usage:
-------------------
    python -m wrappers.ctypes_wrap vmlinux.isf.json.xz [options]

Options:
    --find-symbol-at ADDRESS   Find symbols at a given address
    --get-type TYPE_NAME       Test the generic get_type method
    --test-write               Test writing to struct fields
    --test-to-bytes            Test to_bytes() on an instance
    --test-array-write         Test writing to array elements
    --test-base-enum-instance  Test creating base/enum type instances
    -v, --verbose              Print detailed info

See the __main__ section for more CLI details and test examples.

Main Classes and Functions:
---------------------------
- load_isf_json(path_or_file): Load and parse an ISF file, returning a VtypeJson accessor.
- VtypeJson: Main accessor for types, enums, symbols, and instance creation.
- BoundTypeInstance: Represents a struct/union/base/enum instance bound to a buffer.
- BoundArrayView: View for array fields, supporting element access and assignment.
- EnumInstance: Wrapper for enum values, supporting name and value access.

"""

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
        self.kind: Optional[str] = data.get("kind")  # "struct" or "union"

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
        addr = f"{self.address:#x}" if self.address is not None else 'N/A'
        return f"<VtypeSymbol Name='{self.name}' Address={addr} TypeKind='{type_kind}'>"


class BoundArrayView:
    """A view into an array field of a BoundTypeInstance, allowing get/set of elements."""
    __slots__ = '_parent_instance', '_array_field_name', '_array_subtype_info', '_array_count', '_element_size', '_array_start_offset_in_parent'

    def __init__(self, parent_instance: 'BoundTypeInstance', array_field_name: str,
                 array_type_info: Dict[str, Any], array_start_offset_in_parent: int):
        self._parent_instance = parent_instance
        self._array_field_name = array_field_name  # For error messages
        self._array_subtype_info = array_type_info.get("subtype")
        if self._array_subtype_info is None:
            raise ValueError(
                f"Array field '{array_field_name}' has no subtype information. type_info={array_type_info}")
        self._array_count = array_type_info.get("count", 0)

        # Pre-calculate element size for efficiency
        self._element_size = parent_instance._instance_vtype_accessor.get_type_size(
            self._array_subtype_info)
        if self._element_size is None:
            raise ValueError(
                f"Cannot determine element size for array '{array_field_name}'.\n"
                f"  Parent struct: {getattr(parent_instance, '_instance_type_name', None)}\n"
                f"  Array type_info: {array_type_info}\n"
                f"  Subtype info: {self._array_subtype_info}\n"
                f"  get_type_size(subtype_info) returned None.\n"
                f"  Check that the subtype is defined in the ISF and has a valid size.")

        self._array_start_offset_in_parent = array_start_offset_in_parent

    def _get_element_offset_in_parent_struct(self, index: int) -> int:
        if not 0 <= index < self._array_count:
            raise IndexError(
                f"Array index {index} out of bounds for array '{self._array_field_name}' of size {self._array_count}.")
        # type: ignore
        return self._array_start_offset_in_parent + (index * self._element_size)

    def __getitem__(self, index: int) -> Any:
        element_offset = self._get_element_offset_in_parent_struct(index)
        # _read_data expects offset relative to parent struct start
        return self._parent_instance._read_data(
            self._array_subtype_info,
            element_offset,
            f"{self._array_field_name}[{index}]"
        )

    def __setitem__(self, index: int, value: Any):
        element_offset = self._get_element_offset_in_parent_struct(index)
        # _write_data expects offset relative to parent struct start
        self._parent_instance._write_data(
            self._array_subtype_info,
            element_offset,
            value,
            f"{self._array_field_name}[{index}]"
        )
        # Invalidate parent's cache for this array field, as its content (via this view) has changed.
        if self._array_field_name in self._parent_instance._instance_cache:
            del self._parent_instance._instance_cache[self._array_field_name]

    def __len__(self) -> int:
        return self._array_count

    def __iter__(self):
        for i in range(self._array_count):
            yield self[i]

    def __repr__(self) -> str:
        # Displaying all elements can be verbose for large arrays
        # Consider showing first few and count, or just type and count
        preview_count = min(self._array_count, 3)
        items_preview = [repr(self[i]) for i in range(preview_count)]
        if self._array_count > preview_count:
            items_preview.append("...")
        return f"<BoundArrayView Field='{self._array_field_name}' Count={self._array_count} Items=[{', '.join(items_preview)}]>"


class BoundTypeInstance:
    """Represents an instance of a DWARF type bound to a memory buffer (bytearray for writability)."""

    def __init__(self, type_name: str, type_def: Union[VtypeUserType, VtypeBaseType, VtypeEnum],
                 buffer: bytearray, vtype_accessor: 'VtypeJson',
                 instance_offset_in_buffer: int = 0):
        if not isinstance(buffer, bytearray):
            raise TypeError(
                "Internal Error: BoundTypeInstance expects a bytearray.")
        self._instance_type_name = type_name
        self._instance_type_def = type_def
        self._instance_buffer = buffer
        self._instance_vtype_accessor = vtype_accessor
        self._instance_offset = instance_offset_in_buffer
        self._instance_cache = {}

    @property
    def _value(self) -> Any:
        if isinstance(self._instance_type_def, VtypeUserType):
            raise AttributeError(
                f"'{self._instance_type_name}' is a struct/union and does not have a direct '._value' attribute. Access its fields instead.")
        if isinstance(self._instance_type_def, VtypeBaseType):
            base_type_def = self._instance_type_def
            compiled_struct_obj = base_type_def.get_compiled_struct()
            if base_type_def.size == 0:
                return None
            if compiled_struct_obj is None:
                raise ValueError(
                    f"Cannot get compiled struct for base type '{base_type_def.name}'")
            try:
                return compiled_struct_obj.unpack_from(self._instance_buffer, self._instance_offset)[0]
            except struct.error as e:
                raise struct.error(
                    f"Error unpacking value for base type '{base_type_def.name}': {e}")
        elif isinstance(self._instance_type_def, VtypeEnum):
            enum_def = self._instance_type_def
            if enum_def.base is None:
                raise ValueError(f"Enum '{enum_def.name}' has no base type.")
            base_type_def = self._instance_vtype_accessor.get_base_type(
                enum_def.base)
            if base_type_def is None:
                raise ValueError(
                    f"Base type '{enum_def.base}' for enum '{enum_def.name}' not found.")
            compiled_struct_obj = base_type_def.get_compiled_struct()
            if compiled_struct_obj is None:
                raise ValueError(
                    f"Cannot get compiled struct for enum base type '{enum_def.base}'.")
            try:
                int_val = compiled_struct_obj.unpack_from(
                    self._instance_buffer, self._instance_offset)[0]
                return EnumInstance(enum_def, int_val)
            except struct.error as e:
                raise struct.error(
                    f"Error unpacking value for enum '{enum_def.name}': {e}")
        else:
            raise TypeError(
                f"'._value' property not applicable to internal type: {type(self._instance_type_def).__name__}")

    @_value.setter
    def _value(self, new_value: Any):
        if isinstance(self._instance_type_def, VtypeUserType):
            raise AttributeError(
                f"Cannot set '._value' on a struct/union '{self._instance_type_name}'. Set its fields instead.")
        if isinstance(self._instance_type_def, VtypeBaseType):
            base_type_def = self._instance_type_def
            compiled_struct_obj = base_type_def.get_compiled_struct()
            if base_type_def.size == 0:
                if new_value is not None:
                    raise ValueError("Cannot assign value to void type.")
                return
            if compiled_struct_obj is None:
                raise ValueError(
                    f"Cannot get compiled struct for base type '{base_type_def.name}' to write value.")
            # Handle negative values for unsigned types
            if base_type_def.signed is False and isinstance(new_value, int) and new_value < 0:
                new_value = new_value % (1 << (base_type_def.size * 8))
            try:
                compiled_struct_obj.pack_into(
                    self._instance_buffer, self._instance_offset, new_value)
            except struct.error as e:
                raise struct.error(
                    f"Error packing value for base type '{base_type_def.name}': {e}")
        elif isinstance(self._instance_type_def, VtypeEnum):
            enum_def = self._instance_type_def
            if enum_def.base is None:
                raise ValueError(
                    f"Enum '{enum_def.name}' has no base type for writing.")
            base_type_def = self._instance_vtype_accessor.get_base_type(
                enum_def.base)
            if base_type_def is None:
                raise ValueError(
                    f"Base type '{enum_def.base}' for enum '{enum_def.name}' not found for writing.")
            compiled_struct_obj = base_type_def.get_compiled_struct()
            if compiled_struct_obj is None:
                raise ValueError(
                    f"Cannot get compiled struct for enum base type '{enum_def.base}' for writing.")
            int_val_to_write: int
            if isinstance(new_value, EnumInstance):
                int_val_to_write = new_value._value
            elif isinstance(new_value, int):
                int_val_to_write = new_value
            elif isinstance(new_value, str):
                found_val = enum_def.constants.get(new_value)
                if found_val is None:
                    raise ValueError(
                        f"Enum constant name '{new_value}' not found in enum '{enum_def.name}'.")
                int_val_to_write = found_val
            else:
                raise TypeError(
                    f"Cannot write type '{type(new_value)}' to enum instance. Expected EnumInstance, int, or str.")
            try:
                compiled_struct_obj.pack_into(
                    self._instance_buffer, self._instance_offset, int_val_to_write)
            except struct.error as e:
                raise struct.error(
                    f"Error packing value for enum '{enum_def.name}': {e}")
        else:
            raise TypeError(
                f"'._value' property setter not applicable to internal type: {type(self._instance_type_def).__name__}")
        if '_value' in self._instance_cache:
            del self._instance_cache['_value']

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
                    f"Cannot get compiled struct for base type '{name}'.")
            try:
                return compiled_struct_obj.unpack_from(self._instance_buffer, absolute_field_offset)[0]
            except struct.error as e:
                raise struct.error(
                    f"Error unpacking base type '{name}' for field '{field_name_for_error}': {e}")

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
                    f"Error unpacking pointer for field '{field_name_for_error}': {e}")

        elif kind == "array":
            # Return a BoundArrayView instance instead of a Python list
            return BoundArrayView(self, field_name_for_error, field_type_info, field_offset_in_struct)

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
                    f"Cannot get compiled struct for base type '{name}' to write field '{field_name_for_error}'.")
            # Handle negative values for unsigned types
            if base_type_def.signed is False and isinstance(value_to_write, int) and value_to_write < 0:
                value_to_write = value_to_write % (1 << (base_type_def.size * 8))
            try:
                compiled_struct_obj.pack_into(
                    self._instance_buffer, absolute_field_offset, value_to_write)
            except struct.error as e:
                raise struct.error(
                    f"Error packing base type '{name}' for field '{field_name_for_error}': {e}")

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
                    f"Error packing pointer for field '{field_name_for_error}': {e}")

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
                int_val_to_write = value_to_write._value
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
                    f"Error packing enum '{name}' for field '{field_name_for_error}': {e}")

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
                    f"Error packing bitfield '{field_name_for_error}': {e}")

        elif kind == "array" or kind == "struct" or kind == "union":
            raise NotImplementedError(
                f"Direct assignment to field '{field_name_for_error}' of type '{kind}' is not supported. Modify elements or nested fields individually.")
        else:
            raise TypeError(
                f"Cannot write to field '{field_name_for_error}' of unhandled type kind '{kind}'.")

    def __getattr__(self, name: str) -> Any:
        if name.startswith('_instance_'):
            return super().__getattribute__(name)

        if isinstance(self._instance_type_def, VtypeUserType):
            if name in self._instance_cache:
                return self._instance_cache[name]
            field_def = self._instance_type_def.fields.get(name)
            if field_def is None:
                raise AttributeError(
                    f"'{self._instance_type_name}' (struct/union) has no attribute '{name}'")
            if field_def.offset is None:
                raise ValueError(
                    f"Field '{name}' in '{self._instance_type_name}' has no offset.")
            try:
                val = self._read_data(
                    field_def.type_info, field_def.offset, name)
                # Cache the BoundArrayView if an array is accessed
                if field_def.type_info.get("kind") in ["struct", "union", "array"]:
                    self._instance_cache[name] = val
                return val
            except (struct.error, ValueError) as e:
                raise AttributeError(f"Error processing field '{name}': {e}")

        raise AttributeError(
            f"Type '{self._instance_type_name}' (kind: {self._instance_type_def.__class__.__name__}) has no attribute '{name}'. Use '._value' for base/enum types.")

    def __setattr__(self, name: str, new_value: Any):
        if name.startswith('_instance_'):
            super().__setattr__(name, new_value)
            return

        if isinstance(self._instance_type_def, VtypeUserType):
            field_def = self._instance_type_def.fields.get(name)
            if field_def is None:
                super().__setattr__(name, new_value)
                return
            if field_def.offset is None:
                raise ValueError(
                    f"Field '{name}' in '{self._instance_type_name}' has no offset, cannot write.")
            try:
                # If setting an array field, the user should be using the BoundArrayView's __setitem__
                # This __setattr__ is for regular fields.
                if field_def.type_info.get("kind") == "array":
                    raise NotImplementedError(
                        f"Direct assignment to array field '{name}' is not supported. Access elements like '{name}[index] = value'.")

                self._write_data(field_def.type_info,
                                 field_def.offset, new_value, name)
                if name in self._instance_cache:
                    del self._instance_cache[name]
                return
            except (struct.error, ValueError, TypeError, NotImplementedError) as e:
                raise AttributeError(f"Error setting field '{name}': {e}")

        raise AttributeError(
            f"Cannot set attribute '{name}' on type '{self._instance_type_name}' (kind: {self._instance_type_def.__class__.__name__}). Use '._value' for base/enum types.")

    def to_bytes(self) -> bytes:
        size = self._instance_type_def.size
        if size is None:
            raise ValueError(
                f"Cannot determine size for type '{self._instance_type_name}' (kind: {self._instance_type_def.__class__.__name__}) to get bytes.")
        if size == 0:
            return b''
        start = self._instance_offset
        end = start + size
        return bytes(self._instance_buffer[start:end])

    @property
    def offset(self) -> int:
        """Returns the offset of this instance within the buffer."""
        return self._instance_offset

    def __repr__(self) -> str:
        return f"<BoundTypeInstance Type='{self._instance_type_name}' Kind='{self._instance_type_def.__class__.__name__}' AtOffset={self._instance_offset}>"

    def __dir__(self):
        attrs = list(super().__dir__())
        if isinstance(self._instance_type_def, VtypeUserType):
            attrs.extend(self._instance_type_def.fields.keys())
        if isinstance(self._instance_type_def, (VtypeBaseType, VtypeEnum)):
            attrs.append('_value')
        return sorted(list(set(a for a in attrs if a != '_instance_cache')))


class Ptr:
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
    __slots__ = '_enum_def', '_value'

    def __init__(self, enum_def: VtypeEnum, value: int):
        self._enum_def = enum_def
        self._value = value

    @property
    def name(
        self) -> Optional[str]: return self._enum_def.get_name_for_value(self._value)

    def __repr__(self) -> str:
        name_part = f"{self._enum_def.name}.{self.name}" if self.name else f"{self._enum_def.name} (value)"
        return f"<EnumInstance {name_part} ({self._value})>"

    def __int__(self) -> int: return self._value

    def __eq__(self, other):
        if isinstance(other, EnumInstance):
            return self._value == other._value and self._enum_def.name == other._enum_def.name
        if isinstance(other, int):
            return self._value == other
        if isinstance(other, str):
            return self.name == other
        return False


class VtypeJson:
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

    def shift_symbol_addresses(self, delta: int):
        """
        Shift all symbol addresses by the given delta. Updates both raw symbol data and cached VtypeSymbol objects.
        """
        # Update raw symbol data
        for sym_name, sym_data in self._raw_symbols.items():
            if sym_data is not None and "address" in sym_data and sym_data["address"] not in [None, 0]:
                sym_data["address"] += delta
        # Update cached VtypeSymbol objects
        for sym_obj in self._parsed_symbols_cache.values():
            if sym_obj.address not in [None, 0]:
                sym_obj.address += delta
        # Invalidate address-to-symbol cache
        self._address_to_symbol_list_cache = None

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

    def get_type(self, name: str) -> Optional[Union[VtypeUserType, VtypeBaseType, VtypeEnum]]:
        original_name = name
        name_lower = name.lower()

        if name_lower.startswith("struct "):
            type_name_to_find = original_name[len("struct "):].strip()
            return self.get_user_type(type_name_to_find)
        elif name_lower.startswith("union "):
            type_name_to_find = original_name[len("union "):].strip()
            user_type = self.get_user_type(type_name_to_find)
            if user_type and user_type.kind == "union":
                return user_type
            return None
        elif name_lower.startswith("enum "):
            type_name_to_find = original_name[len("enum "):].strip()
            return self.get_enum(type_name_to_find)

        found_type = self.get_user_type(original_name)
        if found_type:
            return found_type
        found_type = self.get_enum(original_name)
        if found_type:
            return found_type
        found_type = self.get_base_type(original_name)
        if found_type:
            return found_type
        return None

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

    def create_instance(self, type_input: Union[str, VtypeUserType, VtypeBaseType, VtypeEnum],
                        buffer: Union[bytes, bytearray],
                        instance_offset_in_buffer: int = 0) -> BoundTypeInstance:

        type_def: Optional[Union[VtypeUserType,
                                 VtypeBaseType, VtypeEnum]] = None
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
            type_name_for_instance = type_input
            type_def = self.get_type(type_input)
        elif isinstance(type_input, (VtypeUserType, VtypeBaseType, VtypeEnum)):
            type_def = type_input
            type_name_for_instance = type_def.name
        else:
            raise TypeError(
                f"type_input must be a string (type name) or a VtypeUserType/BaseType/Enum object, got {type(type_input)}")

        if type_def:
            if not hasattr(type_def, 'size') or type_def.size is None:
                if not (hasattr(type_def, 'kind') and getattr(type_def, 'kind') == 'void' and type_def.size == 0):
                    raise ValueError(
                        f"Type definition for '{type_name_for_instance}' (kind: {type_def.__class__.__name__}) lacks a valid size attribute.")

            if type_def.size is not None:
                effective_len = len(processed_buffer) - \
                    instance_offset_in_buffer
                if type_def.size > effective_len:
                    raise ValueError(
                        f"Buffer too small for '{type_name_for_instance}' at offset {instance_offset_in_buffer}. Need {type_def.size}, got {effective_len}.")
            return BoundTypeInstance(type_name_for_instance, type_def, processed_buffer, self, instance_offset_in_buffer)

        raise ValueError(
            f"Type definition for '{type_input if isinstance(type_input, str) else type_input.name}' not found.")

    def __repr__(self) -> str:
        return (f"<VtypeJson RawBaseTypes={len(self._raw_base_types)} RawUserTypes={len(self._raw_user_types)} "
                f"RawEnums={len(self._raw_enums)} RawSymbols={len(self._raw_symbols)} (Lazy Loaded)>")


class VtypeJsonGroup:
    """
    Container for multiple related VtypeJson objects, loaded from a list of file paths or file-like objects.
    Methods are dispatched in order to each VtypeJson until a result is found.
    """
    def __init__(self, file_list: list):
        self._file_order = list(file_list)
        self.vtypejsons = {}
        for f in self._file_order:
            self.vtypejsons[f] = load_isf_json(f)

    @property
    def paths(self):
        return list(self._file_order)

    def get_vtypejson(self, path):
        return self.vtypejsons[path]

    def get_base_type(self, name: str):
        for f in self._file_order:
            res = self.vtypejsons[f].get_base_type(name)
            if res is not None:
                return res
        return None

    def get_user_type(self, name: str):
        for f in self._file_order:
            res = self.vtypejsons[f].get_user_type(name)
            if res is not None:
                return res
        return None

    def get_enum(self, name: str):
        for f in self._file_order:
            res = self.vtypejsons[f].get_enum(name)
            if res is not None:
                return res
        return None

    def get_symbol(self, name: str):
        for f in self._file_order:
            res = self.vtypejsons[f].get_symbol(name)
            if hasattr(res, 'address') and res.address in [None, 0]:
                continue
            return res

    def get_type(self, name: str):
        for f in self._file_order:
            res = self.vtypejsons[f].get_type(name)
            if res is not None:
                return res
        return None

    def get_symbols_by_address(self, target_address: int):
        results = []
        for f in self._file_order:
            results.extend(self.vtypejsons[f].get_symbols_by_address(target_address))
        return results

    def get_type_size(self, type_info: dict):
        for f in self._file_order:
            res = self.vtypejsons[f].get_type_size(type_info)
            if res is not None:
                return res
        return None

    def create_instance(self, type_input, buffer, instance_offset_in_buffer=0):
        for f in self._file_order:
            try:
                return self.vtypejsons[f].create_instance(type_input, buffer, instance_offset_in_buffer)
            except ValueError:
                continue
        raise ValueError(f"Type definition for '{type_input if isinstance(type_input, str) else getattr(type_input, 'name', type(type_input))}' not found in any VtypeJson.")

    def shift_symbol_addresses(self, delta: int, path: str = None):
        """
        Shift symbol addresses for all or a specific VtypeJson in the group.
        If path is None, shift all; else shift only the VtypeJson for the given path.
        """
        if path is None:
            for f in self._file_order:
                self.vtypejsons[f].shift_symbol_addresses(delta)
        else:
            self.vtypejsons[path].shift_symbol_addresses(delta)

    def __repr__(self):
        return f"<VtypeJsonGroup: {len(self.vtypejsons)} VtypeJsons>"


def load_isf_json(json_input: Union[str, object]) -> VtypeJson:
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
    cli_parser.add_argument("json_file_path", type=str,
                            help="Path to the ISF JSON or JSON.XZ file.")
    cli_parser.add_argument(
        "-v", "--verbose", action="store_true", help="Print detailed info.")
    cli_parser.add_argument("--find-symbol-at", type=lambda x: int(x, 0),
                            metavar="ADDRESS", help="Find symbols at address.")
    cli_parser.add_argument(
        "--test-write", action="store_true", help="Run field write test.")
    cli_parser.add_argument(
        "--test-to-bytes", action="store_true", help="Run to_bytes() test.")
    cli_parser.add_argument("--test-base-enum-instance", action="store_true",
                            help="Test creating instances of base/enum types.")
    cli_parser.add_argument(
        "--get-type", type=str, help="Test the generic get_type method with the provided type name.")
    cli_parser.add_argument(
        "--test-array-write", action="store_true", help="Test writing to array elements.")

    args = cli_parser.parse_args()
    print(
        f"Attempting to load ISF file: {args.json_file_path} (using {_JSON_LIB_USED})")

    try:
        isf_data: VtypeJson = load_isf_json(args.json_file_path)
        print("\nSuccessfully loaded ISF JSON.")
        print(f"  ISF Representation: {isf_data}")

        if args.get_type:
            print(f"\n--- Testing get_type('{args.get_type}') ---")
            found_type_obj = isf_data.get_type(args.get_type)
            if found_type_obj:
                print(f"  Found type: {found_type_obj}")
                print(f"  Type class: {found_type_obj.__class__.__name__}")
            else:
                print(f"  Type '{args.get_type}' not found.")

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

        if args.test_write or args.test_to_bytes or args.test_array_write:
            print(
                "\n--- Testing Field Write, To Bytes, and/or Array Write Functionality ---")
            # This test assumes 'my_struct' and 'portal_ffi_call' are defined as in previous examples or in your ISF.
            # Adjust struct name and fields as necessary.
            struct_to_test = "my_struct"  # or "portal_ffi_call" if that's in your ISF
            struct_def = isf_data.get_user_type(struct_to_test)

            if struct_def and struct_def.size is not None:
                buffer_data = bytearray(struct_def.size)

                # Initialize buffer for "my_struct" (example)
                if struct_to_test == "my_struct":
                    struct.pack_into("<i", buffer_data, 0, 100)  # id
                    # status_flags=1, type_flag=0
                    struct.pack_into("<B", buffer_data, 4, 0b00000001)
                    # ... (initialize other fields of my_struct if needed)

                instance = isf_data.create_instance(
                    struct_to_test, buffer_data)

                if args.test_write:
                    print(f"  Testing writes for '{struct_to_test}':")
                    if "id" in struct_def.fields:
                        print(f"    Initial id: {instance.id}")
                        instance.id = 999
                        print(
                            f"    Modified id: {instance.id} (Buffer check: {struct.unpack_from('<i', buffer_data, 0)[0]})")
                    # ... (more write tests as before) ...

                if args.test_array_write and "args" in struct_def.fields:  # Test for portal_ffi_call like structure
                    print(
                        f"  Testing array writes for '{struct_to_test}.args':")
                    # Assuming 'args' is an array field, e.g., of unsigned long (pointer size)
                    # This requires 'args' field to exist and be an array.
                    args_array_view = instance.args
                    print(
                        f"    Initial args_array_view[0] (if applicable): {args_array_view[0] if len(args_array_view) > 0 else 'N/A'}")
                    if len(args_array_view) > 0:
                        args_array_view[0] = 0xAAAAAAAAAAAAAAAA
                        print(
                            "    Set args_array_view[0] = 0xAAAAAAAAAAAAAAAA")
                        print(
                            f"    New args_array_view[0]: {args_array_view[0]}")
                    if len(args_array_view) > 1:
                        args_array_view[1] = 0xBBBBBBBBBBBBBBBB
                        print(
                            "    Set args_array_view[1] = 0xBBBBBBBBBBBBBBBB")
                        print(
                            f"    New args_array_view[1]: {args_array_view[1]}")

                    # Verify directly from buffer if possible (assuming 'args' field offset and element size)
                    args_field_def = struct_def.fields.get("args")
                    if args_field_def and args_field_def.offset is not None:
                        subtype_info = args_field_def.type_info.get("subtype")
                        if subtype_info:
                            element_size = isf_data.get_type_size(subtype_info)
                            if element_size:
                                if len(args_array_view) > 0:
                                    val0 = struct.unpack_from(
                                        f"<{isf_data.get_base_type(subtype_info.get('name')).get_compiled_struct().format[-1]}", buffer_data, instance._instance_offset + args_field_def.offset)[0]
                                    print(
                                        f"    Buffer check args[0]: {val0:#x}")
                                if len(args_array_view) > 1:
                                    val1 = struct.unpack_from(
                                        f"<{isf_data.get_base_type(subtype_info.get('name')).get_compiled_struct().format[-1]}", buffer_data, instance._instance_offset + args_field_def.offset + element_size)[0]
                                    print(
                                        f"    Buffer check args[1]: {val1:#x}")

                if args.test_to_bytes:
                    instance_bytes = instance.to_bytes()
                    print(
                        f"  instance.to_bytes() (hex) for '{struct_to_test}': {instance_bytes.hex()}")
            else:
                print(
                    f"  Skipping write/to_bytes/array_write test: '{struct_to_test}' not found or has no size.")

        if args.test_base_enum_instance:
            # ... (base/enum instance test as before) ...
            print("\n--- Testing Base/Enum Instance Creation ---")
            int_def = isf_data.get_base_type("int")
            if int_def and int_def.size is not None:
                int_buffer = bytearray(int_def.size)
                struct.pack_into("<i", int_buffer, 0, 12345)
                int_instance = isf_data.create_instance("int", int_buffer)
                print(f"  Created int_instance: {int_instance}")
                print(f"  int_instance._value: {int_instance._value}")
                int_instance._value = 54321
                print(f"  Modified int_instance._value: {int_instance._value}")
                print(
                    f"  int_instance.to_bytes() (hex): {int_instance.to_bytes().hex()}")
            else:
                print("  Skipping 'int' instance test: 'int' not found or has no size.")

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

if __name__ == '__main__':
    cli_parser = argparse.ArgumentParser(
        description="Load and parse a dwarf2json ISF (Intermediate Symbol File) JSON or JSON.XZ.",
        epilog=f"This script uses the '{_JSON_LIB_USED}' library for JSON parsing."
    )
    cli_parser.add_argument("json_file_path", type=str,
                            help="Path to the ISF JSON or JSON.XZ file.")
    cli_parser.add_argument(
        "-v", "--verbose", action="store_true", help="Print detailed info.")
    cli_parser.add_argument("--find-symbol-at", type=lambda x: int(x, 0),
                            metavar="ADDRESS", help="Find symbols at address.")
    cli_parser.add_argument(
        "--test-write", action="store_true", help="Run field write test.")
    cli_parser.add_argument(
        "--test-to-bytes", action="store_true", help="Run to_bytes() test.")
    cli_parser.add_argument("--test-base-enum-instance", action="store_true",
                            help="Test creating instances of base/enum types.")
    cli_parser.add_argument(
        "--get-type", type=str, help="Test the generic get_type method with the provided type name.")
    cli_parser.add_argument(
        "--test-array-write", action="store_true", help="Test writing to array elements.")

    args = cli_parser.parse_args()
    print(
        f"Attempting to load ISF file: {args.json_file_path} (using {_JSON_LIB_USED})")

    try:
        isf_data: VtypeJson = load_isf_json(args.json_file_path)
        print("\nSuccessfully loaded ISF JSON.")
        print(f"  ISF Representation: {isf_data}")

        if args.get_type:
            print(f"\n--- Testing get_type('{args.get_type}') ---")
            found_type_obj = isf_data.get_type(args.get_type)
            if found_type_obj:
                print(f"  Found type: {found_type_obj}")
                print(f"  Type class: {found_type_obj.__class__.__name__}")
            else:
                print(f"  Type '{args.get_type}' not found.")

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

        if args.test_write or args.test_to_bytes or args.test_array_write:
            print(
                "\n--- Testing Field Write, To Bytes, and/or Array Write Functionality ---")
            # This test assumes 'my_struct' and 'portal_ffi_call' are defined as in previous examples or in your ISF.
            # Adjust struct name and fields as necessary.
            struct_to_test = "my_struct"  # or "portal_ffi_call" if that's in your ISF
            struct_def = isf_data.get_user_type(struct_to_test)

            if struct_def and struct_def.size is not None:
                buffer_data = bytearray(struct_def.size)

                # Initialize buffer for "my_struct" (example)
                if struct_to_test == "my_struct":
                    struct.pack_into("<i", buffer_data, 0, 100)  # id
                    # status_flags=1, type_flag=0
                    struct.pack_into("<B", buffer_data, 4, 0b00000001)
                    # ... (initialize other fields of my_struct if needed)

                instance = isf_data.create_instance(
                    struct_to_test, buffer_data)

                if args.test_write:
                    print(f"  Testing writes for '{struct_to_test}':")
                    if "id" in struct_def.fields:
                        print(f"    Initial id: {instance.id}")
                        instance.id = 999
                        print(
                            f"    Modified id: {instance.id} (Buffer check: {struct.unpack_from('<i', buffer_data, 0)[0]})")
                    # ... (more write tests as before) ...

                if args.test_array_write and "args" in struct_def.fields:  # Test for portal_ffi_call like structure
                    print(
                        f"  Testing array writes for '{struct_to_test}.args':")
                    # Assuming 'args' is an array field, e.g., of unsigned long (pointer size)
                    # This requires 'args' field to exist and be an array.
                    args_array_view = instance.args
                    print(
                        f"    Initial args_array_view[0] (if applicable): {args_array_view[0] if len(args_array_view) > 0 else 'N/A'}")
                    if len(args_array_view) > 0:
                        args_array_view[0] = 0xAAAAAAAAAAAAAAAA
                        print(
                            "    Set args_array_view[0] = 0xAAAAAAAAAAAAAAAA")
                        print(
                            f"    New args_array_view[0]: {args_array_view[0]}")
                    if len(args_array_view) > 1:
                        args_array_view[1] = 0xBBBBBBBBBBBBBBBB
                        print(
                            "    Set args_array_view[1] = 0xBBBBBBBBBBBBBBBB")
                        print(
                            f"    New args_array_view[1]: {args_array_view[1]}")

                    # Verify directly from buffer if possible (assuming 'args' field offset and element size)
                    args_field_def = struct_def.fields.get("args")
                    if args_field_def and args_field_def.offset is not None:
                        subtype_info = args_field_def.type_info.get("subtype")
                        if subtype_info:
                            element_size = isf_data.get_type_size(subtype_info)
                            if element_size:
                                if len(args_array_view) > 0:
                                    val0 = struct.unpack_from(
                                        f"<{isf_data.get_base_type(subtype_info.get('name')).get_compiled_struct().format[-1]}", buffer_data, instance._instance_offset + args_field_def.offset)[0]
                                    print(
                                        f"    Buffer check args[0]: {val0:#x}")
                                if len(args_array_view) > 1:
                                    val1 = struct.unpack_from(
                                        f"<{isf_data.get_base_type(subtype_info.get('name')).get_compiled_struct().format[-1]}", buffer_data, instance._instance_offset + args_field_def.offset + element_size)[0]
                                    print(
                                        f"    Buffer check args[1]: {val1:#x}")

                if args.test_to_bytes:
                    instance_bytes = instance.to_bytes()
                    print(
                        f"  instance.to_bytes() (hex) for '{struct_to_test}': {instance_bytes.hex()}")
            else:
                print(
                    f"  Skipping write/to_bytes/array_write test: '{struct_to_test}' not found or has no size.")

        if args.test_base_enum_instance:
            # ... (base/enum instance test as before) ...
            print("\n--- Testing Base/Enum Instance Creation ---")
            int_def = isf_data.get_base_type("int")
            if int_def and int_def.size is not None:
                int_buffer = bytearray(int_def.size)
                struct.pack_into("<i", int_buffer, 0, 12345)
                int_instance = isf_data.create_instance("int", int_buffer)
                print(f"  Created int_instance: {int_instance}")
                print(f"  int_instance._value: {int_instance._value}")
                int_instance._value = 54321
                print(f"  Modified int_instance._value: {int_instance._value}")
                print(
                    f"  int_instance.to_bytes() (hex): {int_instance.to_bytes().hex()}")
            else:
                print("  Skipping 'int' instance test: 'int' not found or has no size.")

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
