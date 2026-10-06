"""GitHub Actions checks: outsider threat model, positive and negative cases (SPEC §12)."""

from __future__ import annotations

from pathlib import Path

import pytest

from secscope.analysis.config_checks import check_config

SHA = "8f4b7f84864484a7bf31766abe9204da3cbe65b3"


def rules(tmp_path: Path, workflow: str) -> set[str]:
    path = tmp_path / ".github" / "workflows" / "ci.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(workflow, encoding="utf-8")
    return {i.rule_id for i in check_config(tmp_path)}


INJECT_POSITIVE = [
    # issue title straight into a shell
    """on: issues
permissions: {contents: read}
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
""",
    # branch names are attacker-chosen
    """on: pull_request_target
permissions: {contents: read}
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ github.head_ref }}
""",
    # multi-line run block, workflow_run branch name
    """on:
  workflow_run:
    workflows: [build]
permissions: {contents: read}
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo building
          git checkout "${{ github.event.workflow_run.head_branch }}"
""",
    # commit author e-mail
    """on: issue_comment
permissions: {contents: read}
jobs:
  t:
    if: contains(fromJSON('["OWNER"]'), github.event.comment.author_association)
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.head_commit.author.email }}"
""",
]

INJECT_NEGATIVE = [
    # push needs write access: outside the threat model
    """on: push
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.head_commit.message }}"
""",
    # pull_request runs with the fork's read-only token
    """on: pull_request
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
""",
    # numeric id is not injectable; env: indirection is the fix
    """on: issue_comment
permissions: {contents: read}
jobs:
  t:
    if: github.event.comment.author_association == 'MEMBER'
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ github.event.issue.number }}
      - env:
          BODY: ${{ github.event.comment.body }}
        run: echo "$BODY"
""",
]


@pytest.mark.parametrize("workflow", INJECT_POSITIVE)
def test_expression_injection_found(tmp_path: Path, workflow: str) -> None:
    assert "CONF-CI-INJECT-001" in rules(tmp_path, workflow)


@pytest.mark.parametrize("workflow", INJECT_NEGATIVE)
def test_expression_injection_not_reported(tmp_path: Path, workflow: str) -> None:
    assert "CONF-CI-INJECT-001" not in rules(tmp_path, workflow)


def test_comment_command_without_authorisation(tmp_path: Path) -> None:
    unguarded = """on: issue_comment
permissions: {contents: read}
jobs:
  deploy:
    if: startsWith(github.event.comment.body, '/deploy')
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh
"""
    guarded = unguarded.replace(
        "    if: startsWith(github.event.comment.body, '/deploy')\n",
        "    if: >-\n      startsWith(github.event.comment.body, '/deploy') &&\n"
        "      github.event.comment.author_association == 'MEMBER'\n",
    )
    assert "CONF-CI-COMMENT-001" in rules(tmp_path / "a", unguarded)
    assert "CONF-CI-COMMENT-001" not in rules(tmp_path / "b", guarded)


@pytest.mark.parametrize(
    ("workflow", "expected"),
    [
        (
            "on: pull_request_target\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo hi\n",
            True,
        ),
        (
            "on: issues\npermissions: write-all\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo\n",
            True,
        ),
        (
            "on: pull_request_target\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: x\n"
            "    steps:\n      - run: echo hi\n",
            False,
        ),
        (
            "on: issues\njobs:\n  a:\n    runs-on: x\n    permissions:\n      issues: write\n"
            "    steps:\n      - run: echo\n",
            False,
        ),
        # internal triggers are outside the threat model
        ("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo hi\n", False),
    ],
)
def test_token_permissions(tmp_path: Path, workflow: str, expected: bool) -> None:
    assert ("CONF-CI-PERM-001" in rules(tmp_path, workflow)) is expected


@pytest.mark.parametrize(
    ("workflow", "expected"),
    [
        # secrets + third-party action on a tag
        (
            "on: push\njobs:\n  rel:\n    runs-on: x\n    steps:\n      - uses: some-org/publish@v2\n"
            "        with:\n          token: ${{ secrets.NPM_TOKEN }}\n",
            True,
        ),
        # same, pinned to a full SHA
        (
            f"on: push\njobs:\n  rel:\n    runs-on: x\n    steps:\n      - uses: some-org/publish@{SHA}\n"
            "        with:\n          token: ${{ secrets.NPM_TOKEN }}\n",
            False,
        ),
        # first-party actions on tags are fine
        (
            "on: push\njobs:\n  rel:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v4\n"
            "      - run: echo ${{ secrets.X }}\n",
            False,
        ),
        # unprivileged read-only CI is not a finding
        (
            "on: pull_request\njobs:\n  lint:\n    runs-on: x\n    steps:\n      - uses: some-org/lint@v1\n",
            False,
        ),
        # local actions are not third-party
        (
            "on: pull_request_target\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: x\n"
            "    steps:\n      - uses: ./.github/actions/setup\n",
            False,
        ),
    ],
)
def test_third_party_pinning(tmp_path: Path, workflow: str, expected: bool) -> None:
    assert ("CONF-CI-PIN-001" in rules(tmp_path, workflow)) is expected


def test_broken_yaml_falls_back_to_line_checks(tmp_path: Path) -> None:
    broken = (
        'jobs:\n  a:\n    steps:\n      - run: echo "${{ github.event.issue.title }}"\n   bad: [\n'
    )
    assert "CONF-CI-INJECT-001" in rules(tmp_path, broken)
