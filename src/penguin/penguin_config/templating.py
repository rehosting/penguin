"""
Jinja2 "meta variable" templating for Penguin configs.

Lets a config or patch reference values like ``{{ arch }}`` / ``{{ core.arch }}``,
any other ``core.*`` scalar, user-defined ``vars:``, and ``{{ kernel_version }}``
so that changing one value (e.g. ``core.arch``) flows everywhere it is used.

Substitution runs per-file on the parsed YAML dict, before patch merging:
each file resolves against the main config's ``core``/``arch`` plus its own and
the main config's ``vars``. ``kernel_version`` is special — the real kernel path
is only resolved late, so first-pass rendering replaces ``{{ kernel_version }}``
with a sentinel that ``resolve_kernel_version`` substitutes once it is known.

Configs that contain no ``{{ }}``/``{% %}`` are returned untouched.
"""

import jinja2

# First-pass placeholder for the late-bound kernel_version variable.
KERNEL_VERSION_SENTINEL = "\x00IGLOO_KERNEL_VERSION\x00"


class TemplateError(Exception):
    """Raised when a config template references an undefined var or is malformed."""


def _env():
    return jinja2.Environment(
        undefined=jinja2.StrictUndefined,
        autoescape=False,
        keep_trailing_newline=True,
    )


def _looks_templated(s):
    return "{{" in s or "{%" in s or "{#" in s


def _render_str(s, ctx, env, where):
    if not _looks_templated(s):
        return s
    try:
        return env.from_string(s).render(**ctx)
    except jinja2.UndefinedError as e:
        defined = sorted(k for k in ctx if not k.startswith("_"))
        raise TemplateError(
            f"undefined template variable in {where}: {e}; defined vars: {defined}"
        )
    except jinja2.TemplateSyntaxError as e:
        raise TemplateError(f"template syntax error in {where}: {e}")


def substitute(obj, ctx, env=None, where="config"):
    """Recursively render every string leaf of ``obj`` with the Jinja context."""
    env = env or _env()
    if isinstance(obj, str):
        return _render_str(obj, ctx, env, where)
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            nk = _render_str(k, ctx, env, where) if isinstance(k, str) else k
            out[nk] = substitute(v, ctx, env, where)
        return out
    if isinstance(obj, list):
        return [substitute(v, ctx, env, where) for v in obj]
    return obj


def build_context(raw_config, extra=None, env=None, where="vars"):
    """
    Build the Jinja context for a config/patch dict.

    Exposes ``arch``, ``core`` (so ``{{ core.mem }}`` works), the late-bound
    ``kernel_version`` sentinel, anything in ``extra`` (e.g. the main config's
    context when rendering a patch), and the file's own ``vars:`` (which may
    themselves reference earlier vars / arch).
    """
    env = env or _env()
    ctx = {"kernel_version": KERNEL_VERSION_SENTINEL}
    if extra:
        ctx.update(extra)
    core = raw_config.get("core") if isinstance(raw_config, dict) else None
    if isinstance(core, dict):
        ctx["core"] = dict(core)
        if core.get("arch"):
            ctx["arch"] = core["arch"]
    user_vars = raw_config.get("vars") if isinstance(raw_config, dict) else None
    if isinstance(user_vars, dict):
        for k, v in user_vars.items():
            ctx[k] = substitute(v, ctx, env, where)
    return ctx


def render_config(raw_config, extra=None, env=None, where="config"):
    """
    Render a raw config/patch dict in place-equivalent fashion, returning the
    rendered dict and the context used (so callers can reuse it for patches).
    """
    env = env or _env()
    ctx = build_context(raw_config, extra=extra, env=env)
    return substitute(raw_config, ctx, env, where), ctx


def resolve_kernel_version(obj, kernel_version):
    """Second pass: replace the kernel_version sentinel with the resolved value."""
    kv = str(kernel_version) if kernel_version is not None else ""
    if isinstance(obj, str):
        return obj.replace(KERNEL_VERSION_SENTINEL, kv)
    if isinstance(obj, dict):
        return {
            (k.replace(KERNEL_VERSION_SENTINEL, kv) if isinstance(k, str) else k):
                resolve_kernel_version(v, kv)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [resolve_kernel_version(v, kv) for v in obj]
    return obj
