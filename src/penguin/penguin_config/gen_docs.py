import typing
from typing import Any, Literal, Optional, Union
from types import NoneType
import argparse
import dataclasses
from pydantic_core import PydanticUndefined, PydanticUndefinedType
import yaml

try:
    from penguin.penguin_config import structure
except ImportError:
    import structure


def type_has_simple_name(ty):
    """
    Determine whether a type is a regular Python type and not a Pydantic model class.
    """
    try:
        gen_docs_type_name(ty)
        return True
    except ValueError:
        return False


def gen_docs_yaml_dump(x):
    """
    Convert x to YAML for use in generated docs.

    We can't use yaml.dump(x) alone for this, because it appends "\n...\n".

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
    elif og in (list, tuple) or t in (list, tuple):
        return "list of " + gen_docs_type_name(args[0]) if args else "list"
    elif og is dict or t is dict:
        if len(args) >= 2:
            return f"mapping from {gen_docs_type_name(args[0])} to {gen_docs_type_name(args[1])}"
        return "mapping"
    elif t is Any:
        return "any"
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
    heading_hashes = "#" * min(len(path) + 1, 6)
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
    if docs_field.merge_behavior is not None:
        out += f"|__Patch merge behavior__|{docs_field.merge_behavior}|\n"
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


def gen_docs_compact_field_table(fields):
    """
    For fields that do not have any nested structure and only simple types,
    generate a compact table to make the docs easier to read.
    """

    has_examples = any(field.examples for field in fields.values())
    out = f"|Field|Type|Default|Title|{'Examples|' if has_examples else ''}\n"
    out += f"|-|-|-|-|{'-|' if has_examples else ''}\n"
    for name, field in fields.items():
        field = DocsField.from_field(field)
        # Ensure there is no extra information for this field that doesn't fit in the compact table
        assert not field.merge_behavior and not field.description, (name, field)
        type_name = gen_docs_type_name(field.type_)
        default = "" if field.default is PydanticUndefined else "`" + gen_docs_yaml_dump(field.default) + "`"
        examples = ", ".join(f"`{gen_docs_yaml_dump(example)}`" for example in field.examples)
        out += f"|`{name}`|{type_name}|{default}|{field.title}|{examples + '|' if has_examples else ''}\n"
    return out


@dataclasses.dataclass(frozen=True)
class DocsField:
    """Information about a field of the config, for generating docs"""

    type_: type
    merge_behavior: Optional[str]
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
            try:
                merge_behavior = type_.merge_behavior()
            except AttributeError:
                merge_behavior = None
            title = type_.model_config.get("title")
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
            merge_behavior = title = description = None
            default = PydanticUndefined
            examples = []
        return DocsField(type_, merge_behavior, title, description, default, examples)

    def from_field(field) -> "DocsField":
        """Create a `DocsField` from a Pydantic `Field`"""

        return DocsField(
            field.annotation,
            None,
            field.title,
            field.description,
            field.default,
            field.examples or [],
        ).merge(DocsField.from_type(field.annotation))

    def merge(self, other: "DocsField") -> "DocsField":
        """
        Create a DocsField by combining two DocsFields, using the second to fill in gaps in the first.
        """
        return DocsField(
            self.type_,
            self.merge_behavior or other.merge_behavior,
            self.title or other.title,
            self.description or other.description,
            other.default if self.default is PydanticUndefined else self.default,
            (
                self.examples
                if self.examples == other.examples
                else self.examples + other.examples
            ),
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

        # Render high-level info before specific sub-fields
        out += gen_docs_field(path=path, docs_field=docs_field, include_type=False)

        all_fields_compact = all(
            type_has_simple_name(field.annotation) and not field.description
            for field in type_.model_fields.values()
        )
        if all_fields_compact:
            # We can render this as one compact table since there is no recursive structure here
            out += gen_docs_compact_field_table(type_.model_fields)
        else:
            # Recursively render docs for each field
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
            docs_field=DocsField.from_type(first_model_arg).merge(docs_field),
        )
    else:
        # The type does not inherit from `BaseModel` and it doesn't have an argument that does.
        # It is probably a primative type, like `str` or `bool`.
        # There is no more recursion to do for this field, so just generate docs for it.
        out += gen_docs_field(path, docs_field)

    return out


def _advance_section(type_, seg):
    """
    Move one user-facing step into the schema by `seg`, transparently skipping
    non-consuming wrappers (Optional, RootModel newtypes, and dict values).

    Returns the resolved sub-type, or None if `seg` doesn't resolve.
    """
    while True:
        # Collapse Optional[... T ...] to T
        while (
            typing.get_origin(type_) is Union
            and len(typing.get_args(type_)) == 2
            and typing.get_args(type_)[1] is NoneType
        ):
            type_ = typing.get_args(type_)[0]

        if hasattr(type_, "model_fields") and "root" in type_.model_fields:
            info = type_.model_fields["root"]
            ann = info.annotation
            if info.discriminator and typing.get_origin(ann) is Union:
                # Tagged union: `seg` should name a discriminator value.
                for variant in typing.get_args(ann):
                    disc = variant.model_fields.get(info.discriminator)
                    vals = typing.get_args(disc.annotation) if disc else ()
                    if vals and vals[0] == seg:
                        return variant
                return None
            type_ = ann  # newtype: unwrap and retry the same segment
            continue

        if hasattr(type_, "model_fields"):
            field = type_.model_fields.get(seg)
            return field.annotation if field is not None else None

        if typing.get_origin(type_) is dict:
            type_ = typing.get_args(type_)[1]  # descend into the value type
            continue

        return None


def resolve_section(dotted):
    """
    Resolve a dotted config-section path (e.g. "core", "pseudofiles.read",
    "pseudofiles.read.const_buf") to the type at that location, or None.
    """
    type_ = structure.Main
    for seg in [s for s in dotted.split(".") if s]:
        type_ = _advance_section(type_, seg)
        if type_ is None:
            return None
    return type_


def gen_plugin_args_docs(name, args_model, deprecation_note=True):
    """
    Render a plugin's declared ``Args`` model as a markdown section.

    ``args_model`` is a ``PluginArgs`` subclass; we render one row per field with
    its type, default, required-ness, and description. Set ``deprecation_note``
    to False to omit the per-plugin first-class-syntax note (the aggregate
    reference states it once instead).
    """
    out = [f"# Plugin `{name}` arguments", ""]
    fields = args_model.model_fields
    if not fields:
        out.append("This plugin declares an `Args` schema with no fields.")
        return "\n".join(out) + "\n"
    out.append("|Argument|Type|Default|Required|Description|")
    out.append("|-|-|-|-|-|")
    for fname, info in fields.items():
        try:
            type_name = gen_docs_type_name(info.annotation)
        except Exception:
            type_name = getattr(info.annotation, "__name__", str(info.annotation))
        required = info.is_required()
        default = "" if required else "`" + gen_docs_yaml_dump(info.default) + "`"
        desc = info.description or ""
        out.append(f"|`{fname}`|{type_name}|{default}|{'yes' if required else ''}|{desc}|")
    out.append("")
    out.append("Configure under `plugins:`:")
    out.append("```yaml")
    out.append(f"plugins:\n  {name}:\n    # args...")
    out.append("```")
    if deprecation_note:
        out.append("")
        out.append(
            f"> The first-class top-level form (`{name}:` at the config root) is "
            "**deprecated**: it still loads but logs a warning and may be removed."
        )
    return "\n".join(out) + "\n"


def gen_all_plugin_args_docs(plugin_path=None, manager=None, panda=None):
    """
    Render a single markdown reference for every plugin that declares an ``Args``
    schema under ``plugin_path`` (default: the schema's ``core.plugin_path``).

    Completeness depends on the runtime: many plugins only import with a live
    ``plugins`` manager bound (e.g. kernel-FFI enums). Pass ``manager``/``panda``
    (the live singletons, as the docgen plugin does) for full coverage; without
    them this is best-effort and runtime-dependent plugins are skipped.
    """
    from penguin.plugin_manager import discover_declaring_plugins

    if plugin_path is None:
        plugin_path = structure.Core.model_fields["plugin_path"].default

    found, skipped = discover_declaring_plugins(plugin_path, manager=manager, panda=panda)

    out = [
        "# Plugin arguments",
        "",
        "Plugins that declare an `Args` schema validate their arguments and "
        "document them here. Configure them under the top-level `plugins:` "
        "section, keyed by the plugin name. This page is generated from the "
        "plugins' declared `Args`; run `penguin schema <plugin>` for the same "
        "information at the CLI.",
        "",
        "> The first-class top-level form (writing `<plugin>:` at the config "
        "root instead of under `plugins:`) is **deprecated**: it still loads "
        "but logs a warning and may be removed.",
        "",
    ]
    if not found:
        out.append("_No plugins declaring an `Args` schema were discovered "
                   f"under `{plugin_path}`._")
        return "\n".join(out) + "\n"

    out.append("**Plugins:** " + ", ".join(f"[`{n}`](#plugin-{n}-arguments)"
                                           for n, _ in found))
    out.append("")
    for name, model in found:
        out.append(gen_plugin_args_docs(name, model, deprecation_note=False))
    if skipped:
        out.append("")
        out.append(f"<!-- {len(skipped)} plugin file(s) could not be imported "
                   "for introspection and were skipped. -->")
    return "\n".join(out) + "\n"


def list_sections():
    """Return [(name, title)] for the top-level config sections."""
    out = []
    for name, info in structure.Main.model_fields.items():
        df = DocsField.from_field(info)
        out.append((name, df.title or name))
    return out


def main():
    p = argparse.ArgumentParser()
    sp = p.add_subparsers(required=True)

    sp.add_parser(
        "schema",
        help="Write JSON schema for config to stdout",
    ).set_defaults(func=lambda: print(yaml.dump(structure.Patch.model_json_schema(), indent=2)))

    sp.add_parser(
        "docs",
        help="Write generated config docs to stdout",
    ).set_defaults(func=lambda: print(gen_docs()))

    pa = sp.add_parser(
        "plugin-docs",
        help="Write generated plugin-arguments docs to stdout "
             "(run inside the penguin container for full coverage)",
    )
    pa.add_argument("--plugin-path", default=None,
                    help="Plugin search path (default: core.plugin_path)")
    pa.set_defaults(func=lambda: print(gen_all_plugin_args_docs(args.plugin_path)))

    args = p.parse_args()
    args.func()


if __name__ == "__main__":
    main()
