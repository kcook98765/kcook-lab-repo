"""Render reviewed OpenCode v1 integration into a new private staging directory.

This does not install profiles, authenticate, invoke OpenCode, or change services.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import re


TEMPLATES = Path(__file__).resolve().parents[2] / 'integrations/opencode'


def render(text, bindings):
    # Replace once: a supplied path must never become another template variable.
    return re.sub(r'\$\{([A-Z_]+)\}', lambda m: bindings[m[1]], text)


def merge(base, overlay):
    result = copy.deepcopy(base)
    for key, value in overlay.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge(result[key], value)
        elif key == 'paths' and isinstance(result.get(key), list):
            result[key] += [p for p in value if p not in result[key]]
        else:
            result[key] = copy.deepcopy(value)
    return result


def load_profile(path):
    if path is None:
        return {}
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError('A base profile must be a JSON object')
    return value


def bindings_for(home, development, source, distribution, toolkit):
    paths = [home, development, source, distribution, toolkit]
    if any(not p.is_absolute() or p != p.resolve() for p in paths):
        raise ValueError('Roots must be absolute canonical paths without symlinks')
    if home == Path('/') or development in (Path('/'), home):
        raise ValueError('Use a specific development root, not the home or filesystem root')
    roots = [source, distribution, toolkit]
    if any(p in (Path('/'), home, development) or p in home.parents
           or p in development.parents for p in roots):
        raise ValueError('Checkout roots cannot contain the home or development root')
    if any(a == b or a in b.parents or b in a.parents
           for i, a in enumerate(roots) for b in roots[i + 1:]):
        raise ValueError('Source, distribution and Toolkit roots must be separate')
    if any(re.search(r'[\x00-\x1f*?\[\]{}$]', str(p)) for p in paths):
        raise ValueError('Roots cannot contain control characters or permission/template wildcards')
    return dict(zip(['USER_HOME', 'DEVELOPMENT_ROOT', 'SOURCE_ROOT',
                     'DISTRIBUTION_ROOT', 'TOOLKIT_ROOT'], map(str, paths)),
                USER_HOME_RELATIVE=home.as_posix().lstrip('/'))


def stage(output, bindings, profiles):
    rendered = {}
    for name in ('global', 'source', 'distribution'):
        # Substitute parsed JSON strings rather than raw JSON: paths may contain quotes.
        template = json.loads((TEMPLATES / f'{name}.template.json').read_text())

        def expand(value):
            if isinstance(value, str):
                return render(value, bindings)
            if isinstance(value, dict):
                return {render(k, bindings): expand(v) for k, v in value.items()}
            if isinstance(value, list):
                return [expand(v) for v in value]
            return value

        rendered[f'{name}-profile.json'] = (
            json.dumps(merge(profiles.get(name, {}), expand(template)), indent=2) + '\n')
    for path in (TEMPLATES / 'local-templates').rglob('*'):
        if path.is_file():
            relative = path.relative_to(TEMPLATES / 'local-templates')
            rendered[f'distribution-local/.opencode/{relative}'] = render(path.read_text(), bindings)
    rendered['source-instructions.md'] = render(
        (TEMPLATES / 'source-instructions.template.md').read_text(), bindings)
    if any(p.is_symlink() for p in (output, *output.parents)):
        raise ValueError('Staging paths cannot use symlinks')
    # This is deliberately never an in-place installer. Existing output is an error.
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    for relative, text in rendered.items():
        path = output / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with path.open('x') as stream:
            os.chmod(path, 0o600)
            stream.write(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('home', 'development', 'source', 'distribution', 'toolkit'):
        parser.add_argument(f'--{name}-root', type=Path, required=True)
    for name in ('global', 'source', 'distribution'):
        parser.add_argument(f'--{name}-base', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    bindings = bindings_for(args.home_root, args.development_root, args.source_root,
                            args.distribution_root, args.toolkit_root)
    stage(args.output, bindings, {
        name: load_profile(getattr(args, f'{name}_base'))
        for name in ('global', 'source', 'distribution')})
    print('Integration staged; installed profiles and services were not changed.')


if __name__ == '__main__':
    main()
