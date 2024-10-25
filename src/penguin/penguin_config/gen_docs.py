import typing
from typing import Any, Literal, Optional, Union
from types import NoneType
import argparse
import dataclasses
from pydantic_core import PydanticUndefined, PydanticUndefinedType
import yaml

import structure


def gen_docs_yaml_dump(x):
    """
    Convert `x` to YAML for use in generated docs.
    We can't use `yaml.dump(x)` alone for this, becuase it appends "\n...\n".
    """

    s = yaml.dump(x)
    term = "\n...\n"
    s = s[: -len(term)] if s.endswith(term) else s
    return s.strip()


def gen_docs_literal_arg(a):
    s = gen_docs_yaml_dump(a)
    if isinstance(a, str):
        s = f'"{s}"'
    s = f"`{s}`"
    return s


def gen_docs_type_name(t):
    """Convert the Python type `t` to a string for use in generated docs."""

    og = typing.get_origin(t)
    args = typing.get_args(t)

    if t == structure.Star:
        return '"*"'
    elif og is Union:
        return " or ".join(map(gen_docs_type_name, args))
    elif og is Literal:
        return " or ".join([gen_docs_literal_arg(a) for a in args])
    elif og in (list, tuple):
        return "list of " + gen_docs_type_name(args[0])
    elif t is int:
        return "integer"
    elif t is str:
        return "string"
    elif t is bool:
        return "boolean"
    elif t is NoneType:
        return "null"
    else:
        raise ValueError(f"unknown type {t}")


def gen_docs_field(path, docs_field, include_type=True):
    """Generate docs for a single field of the config"""

    assert (
        docs_field.title is not None
    ), f"config option {path} has no title: {docs_field}"
    heading_hashes = "#" * (len(path) + 1)
    include_docs = docs_field.default is not PydanticUndefined
    path_prefix = f"`{'.'.join(path)}` " if path else ""
    out = ""
    out += f"{heading_hashes} {path_prefix}{docs_field.title}\n"
    if include_type or include_docs:
        out += "\n"
        out += "|||\n"
        out += "|-|-|\n"
    if include_type:
        out += f"|__Type__|{gen_docs_type_name(docs_field.type_)}|\n"
    if include_docs:
        out += f"|__Default__|`{gen_docs_yaml_dump(docs_field.default)}`|\n"
    out += "\n"
    if docs_field.description is not None:
        out += docs_field.description + "\n"
    out += "\n"
    for e in docs_field.examples:
        out += "```yaml\n"
        out += gen_docs_yaml_dump(e) + "\n"
        out += "```\n"
        out += "\n"
    return out


@dataclasses.dataclass(frozen=True)
class DocsField:
    """Information about a field of the config, for generating docs"""

    type_: type
    title: Optional[str]
    description: Optional[str]
    default: Union[PydanticUndefinedType, Any]
    examples: tuple[Any]

    def from_type(type_: type) -> "DocsField":
        """Create a `DocsField` from a Python type, which should probably inherit `BaseModel` or `RootModel`"""

        # Change Optional[Optional[... Optional[T] ...]] to T
        while (
            typing.get_origin(type_) is Union
            and len(typing.get_args(type_)) == 2
            and typing.get_args(type_)[1] is NoneType
        ):
            type_ = typing.get_args(type_)[0]

        if hasattr(type_, "model_config"):
            # Inherits BaseModel or RootModel
            title = type_.model_config["title"]
            description = type_.__doc__
            try:
                default = type_.model_config["default"]
            except KeyError:
                default = PydanticUndefined
            try:
                examples = type_.model_config["json_schema_extra"]["examples"]
            except (KeyError, TypeError):
                examples = []
        else:
            # Doesn't inherit BaseModel or RootModel, so make all values empty
            title = description = None
            default = PydanticUndefined
            examples = []
        return DocsField(type_, title, description, default, examples)

    def from_field(field) -> "DocsField":
        """Create a `DocsField` from a Pydantic `Field`"""

        return DocsField(
            field.annotation,
            field.title,
            field.description,
            field.default,
            field.examples or [],
        ).merge(DocsField.from_type(field.annotation))

    def merge(self, other: "DocsField") -> "DocsField":
        """Create a `DocsField` by combining two `DocsField`s, using the second to fill in gaps in the first"""
        return DocsField(
            self.type_,
            self.title or other.title,
            self.description or other.description,
            other.default if self.default is PydanticUndefined else self.default,
            self.examples + other.examples,
        )


def gen_docs(path=[], docs_field=DocsField.from_type(structure.Main)):
    """Generate docs for config format starting from the field at the given path"""

    type_ = docs_field.type_
    type_origin = typing.get_origin(type_)
    type_args = typing.get_args(type_)

    # The first type argument that inherits `BaseModel`.
    # For example, if the type is `Optional[Env]`, this is `Env`
    first_model_arg = next(
        (a for a in type_args if hasattr(a, "model_fields")),
        None,
    )

    is_model = hasattr(type_, "model_fields")  # Type inherits `BaseModel`
    is_root_model = (
        is_model and "root" in type_.model_fields
    )  # Type inherits `RootModel`
    out = ""

    if is_root_model:
        # The type inherits `RootModel`. It is a newtype or a union.

        info = type_.model_fields["root"]
        discrim_key = info.discriminator
        ann = info.annotation
        og = typing.get_origin(ann)
        args = typing.get_args(ann)

        if isinstance(discrim_key, str):
            # The type is a tagged union
            assert og is Union

            # Generate docs for the union itself
            out += gen_docs_field(path=path, docs_field=docs_field, include_type=False)

            # Generate docs for each variant
            for variant in args:
                [discrim_val] = typing.get_args(
                    variant.model_fields[discrim_key].annotation
                )
                out += gen_docs(
                    path=path + [f"<{discrim_key}={discrim_val}>"],
                    docs_field=DocsField.from_type(variant),
                )
        else:
            # The type is a newtype.
            # Collect its metadata and try again with the underlying type.
            out += gen_docs(
                path=path,
                docs_field=DocsField.from_field(info).merge(docs_field),
            )
    elif is_model:
        # The type inherits `BaseModel` but not `RootModel`

        out += gen_docs_field(path=path, docs_field=docs_field, include_type=False)
        for name, info in type_.model_fields.items():
            out += gen_docs(
                path=path + [name],
                docs_field=DocsField.from_field(info),
            )
    elif type_origin is dict:
        # The type is `dict[T, U]`.

        # Generate docs for the dictionary itself
        out += gen_docs_field(path=path, docs_field=docs_field, include_type=False)

        # Generate docs for the value type
        key_type, val_type = typing.get_args(type_)
        key_type_str = gen_docs_type_name(key_type)
        out += gen_docs(
            path=path + [f"<{key_type_str}>"],
            docs_field=DocsField.from_type(val_type),
        )
    elif type_origin is Union and first_model_arg is not None:
        # The type is `Optional[T]`. Try again with just `T`.
        out += gen_docs(
            path=path,
            docs_field=DocsField.from_type(first_model_arg),
        )
    else:
        # The type does not inherit from `BaseModel` and it doesn't have an argument that does.
        # It is probably a primative type, like `str` or `bool`.
        # There is no more recursion to do for this field, so just generate docs for it.
        out += gen_docs_field(path, docs_field)

    return out


def main():
    p = argparse.ArgumentParser()
    sp = p.add_subparsers(required=True)

    sp.add_parser(
        "schema",
        help="Write JSON schema for config to stdout",
    ).set_defaults(func=lambda: print(yaml.dump(structure.Main.model_json_schema(), indent=2)))

    sp.add_parser(
        "docs",
        help="Write generated config docs to stdout",
    ).set_defaults(func=lambda: print(gen_docs()))

    p.parse_args().func()


if __name__ == "__main__":
    main()
