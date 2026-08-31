"""Loads rule and exception definitions from the rules/ directory.

The loading contract matters as much as the parsing: **one bad rule must never
take the tool down or silently disable detection**. A rule that fails to parse is
skipped, recorded with the file, rule id and a human-readable reason, and
reported on /api/rules. Everything else keeps working.

That is the opposite of failing fast, and it is deliberate. This runs unattended
as a security service; refusing to start because of a typo in one of thirty rules
would turn a small mistake into a total monitoring outage.
"""

from __future__ import annotations

import os

import yaml  # type: ignore

from core.ruleengine import GlobalException, Rule, RuleError  # type: ignore


def _load_yaml_documents(path: str) -> tuple[list, str | None]:
    """Parse one YAML file, returning (documents, error)."""
    try:
        with open(path, 'r', encoding='utf-8') as handle:
            loaded = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        return [], f'YAML syntax error: {exc}'
    except OSError as exc:
        return [], f'could not read file: {exc}'

    if loaded is None:
        return [], None
    if isinstance(loaded, dict):
        # Accept either a bare list of rules or a mapping with a 'rules' key.
        for key in ('rules', 'exceptions'):
            if key in loaded:
                items = loaded.get(key) or []
                if not isinstance(items, list):
                    return [], f"'{key}' must be a list"
                return items, None
        return [loaded], None
    if isinstance(loaded, list):
        return loaded, None
    return [], f'expected a list or mapping at the top level, got {type(loaded).__name__}'


def load_rules(rules_dir: str) -> tuple[list[Rule], list[GlobalException], list[dict]]:
    """Load every rule and exception under `rules_dir`.

    Files named exceptions*.yaml hold allowlist entries; everything else holds
    rules. Returns (rules, exceptions, errors).
    """
    rules: list[Rule] = []
    exceptions: list[GlobalException] = []
    errors: list[dict] = []

    if not os.path.isdir(rules_dir):
        errors.append({'file': rules_dir, 'rule': None,
                       'error': 'rules directory does not exist'})
        return rules, exceptions, errors

    seen_ids: dict[str, str] = {}

    for filename in sorted(os.listdir(rules_dir)):
        if not filename.lower().endswith(('.yaml', '.yml')):
            continue
        path = os.path.join(rules_dir, filename)
        documents, error = _load_yaml_documents(path)
        if error:
            errors.append({'file': filename, 'rule': None, 'error': error})
            continue

        is_exception_file = filename.lower().startswith('exception')

        for index, spec in enumerate(documents):
            label = None
            try:
                if is_exception_file:
                    exceptions.append(GlobalException(spec, origin=filename))
                else:
                    label = spec.get('id') if isinstance(spec, dict) else None
                    rule = Rule(spec, origin=filename)
                    if rule.id in seen_ids:
                        raise RuleError(
                            f"duplicate rule id '{rule.id}' (already defined in "
                            f"{seen_ids[rule.id]})"
                        )
                    seen_ids[rule.id] = filename
                    rules.append(rule)
            except RuleError as exc:
                errors.append({'file': filename,
                               'rule': label or f'#{index}',
                               'error': str(exc)})
            except Exception as exc:
                errors.append({'file': filename,
                               'rule': label or f'#{index}',
                               'error': f'{type(exc).__name__}: {exc}'})

    return rules, exceptions, errors


def describe_load(rules, exceptions, errors) -> None:
    """Print a startup summary so problems are visible in the console too."""
    enabled = sum(1 for r in rules if r.enabled)
    techniques = {r.technique for r in rules if r.enabled and r.technique}
    print(f'[*] Detection rules: {enabled} enabled / {len(rules)} loaded, '
          f'{len(techniques)} ATT&CK techniques, {len(exceptions)} exception(s)')
    for err in errors:
        target = f"{err['file']}:{err['rule']}" if err['rule'] else err['file']
        print(f'[!] Rule load error in {target}: {err["error"]}')
