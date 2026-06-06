"""
Human-friendly rendering of Pydantic ValidationErrors for Penguin configs.

`structure.Main(**config)` raises a `pydantic.ValidationError` whose default
string form is a wall of text with URLs and no indication of which config/patch
file is at fault. `format_validation_error` turns it into a short, located,
optionally-colorized report that names the offending option, the file that set
it (via the patch `origin_map`), what was wrong, and the allowed values.
"""

import difflib
import os
import sys
import typing
from types import NoneType
from typing import Union

from . import structure

# Keys that we never want to suggest as "did you mean" or treat as descendable.
_UNION_TAG_KEYS = ("type", "model")


def _supports_color(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


class _Palette:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def _wrap(self, code, text):
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def loc(self, t):
        return self._wrap("1;31", t)  # bold red

    def file(self, t):
        return self._wrap("2", t)  # dim

    def allowed(self, t):
        return self._wrap("33", t)  # yellow

    def ok(self, t):
        return self._wrap("32", t)  # green


def _unwrap_optional(type_):
    """Collapse Optional[Optional[... T ...]] to T (mirrors gen_docs)."""
    while (
        typing.get_origin(type_) is Union
        and len(typing.get_args(type_)) == 2
        and typing.get_args(type_)[1] is NoneType
    ):
        type_ = typing.get_args(type_)[0]
    return type_


def _resolve_model_at_path(loc, root=None):
    """
    Walk ``root`` (default ``structure.Main``) along ``loc`` (a tuple of pydantic
    error-location segments) and return the BaseModel class at that location, or
    None if it can't be resolved (best effort, used only for "did you mean").
    """
    type_ = root if root is not None else structure.Main
    for seg in loc:
        type_ = _unwrap_optional(type_)
        # RootModel newtypes / tagged unions wrap their content under "root".
        if hasattr(type_, "model_fields") and "root" in type_.model_fields:
            info = type_.model_fields["root"]
            ann = info.annotation
            if info.discriminator and typing.get_origin(ann) is Union:
                # Tagged union: seg should be a discriminator tag value.
                match = None
                for variant in typing.get_args(ann):
                    disc = variant.model_fields.get(info.discriminator)
                    if disc is None:
                        continue
                    vals = typing.get_args(disc.annotation)
                    if vals and vals[0] == seg:
                        match = variant
                        break
                if match is None:
                    return None
                type_ = match
                continue
            type_ = _unwrap_optional(ann)
            # Re-process this same segment against the unwrapped type.

        type_ = _unwrap_optional(type_)
        if hasattr(type_, "model_fields"):
            field = type_.model_fields.get(seg)
            if field is None:
                return None
            type_ = field.annotation
        elif typing.get_origin(type_) is dict:
            # dict[K, V]: a path segment is a key; descend into V.
            type_ = typing.get_args(type_)[1]
        else:
            return None
    type_ = _unwrap_optional(type_)
    return type_ if hasattr(type_, "model_fields") else None


def _field_names(model):
    try:
        return [k for k in model.model_fields.keys() if k != "root"]
    except AttributeError:
        return []


def _did_you_mean(key, candidates):
    matches = difflib.get_close_matches(str(key), candidates, n=1)
    return matches[0] if matches else None


def _describe(err, pal, root=None):
    """Return a one-line description of a single pydantic error dict."""
    etype = err["type"]
    ctx = err.get("ctx", {})
    loc = err["loc"]
    last = loc[-1] if loc else ""

    if etype == "literal_error":
        return f"invalid value; allowed: {pal.allowed(ctx.get('expected', '?'))}"
    if etype in ("union_tag_invalid", "union_tag_not_found"):
        disc = ctx.get("discriminator", "type")
        tag = ctx.get("tag")
        allowed = ctx.get("expected_tags", "?")
        if tag is not None:
            return f"unknown {disc} {tag!r}; allowed: {pal.allowed(allowed)}"
        return f"missing {disc}; allowed: {pal.allowed(allowed)}"
    if etype == "extra_forbidden":
        parent = _resolve_model_at_path(loc[:-1], root=root)
        msg = f"unknown option {str(last)!r}"
        if parent is not None:
            suggestion = _did_you_mean(last, _field_names(parent))
            if suggestion:
                msg += f" (did you mean {pal.allowed(suggestion)}?)"
        return msg
    if etype == "missing":
        return f"required option {str(last)!r} is missing"
    return err.get("msg", etype)


def format_validation_error(
    exc, *, config_path=None, origin_map=None, root_model=None,
    header="Config validation failed:",
):
    """
    Render a pydantic ``ValidationError`` into a friendly multi-line report.

    ``config_path`` is the main config file (used as a fallback source).
    ``origin_map`` is the {dotted.path: source_file} map produced by
    ``patch_config`` during load, used to name which file set each option.
    ``root_model`` is the model the error paths are relative to (defaults to
    ``structure.Main``); pass a plugin's ``Args`` model for plugin-arg errors.
    """
    pal = _Palette(_supports_color(sys.stderr))
    origin_map = origin_map or {}

    lines = [header]
    for err in exc.errors(include_url=False):
        loc = err["loc"]
        dotted = ".".join(str(p) for p in loc)
        # The origin map keys are dotted paths without union-tag segments;
        # drop tag segments (type/model values) when looking up the source.
        origin_key = ".".join(
            str(p) for p in loc if p not in _UNION_TAG_KEYS
        )
        source = origin_map.get(origin_key) or origin_map.get(dotted)
        if source and source != "base_config":
            source = os.path.basename(source)
        elif source == "base_config" and config_path:
            source = os.path.basename(config_path)
        elif config_path:
            source = os.path.basename(config_path)

        head = pal.loc(dotted) if dotted else pal.loc("<root>")
        where = f" [{pal.file(source)}]" if source else ""
        lines.append(f"  - {head}{where}: {_describe(err, pal, root=root_model)}")
    return "\n".join(lines)
