---
applyTo: "**"
---

# Pull Request Agent Instructions

## Branch rules
- Never commit directly to `main` — all changes go on a feature branch
- Branch names must be descriptive: `feat/<topic>`, `fix/<topic>`, `chore/<topic>`
- Open a PR to merge into `main`

## PR title format
Use the same convention as commit messages:
```
feat: short description of what was added
fix: short description of what was corrected
chore: tooling, CI, or non-functional changes
```

## PR description structure

### For simple changes (single-file edits, small fixes)
A short paragraph is sufficient:
- What changed and why
- Any issue it closes (`Closes #N`)

### For larger changes, use this template:
```
## Summary
One or two sentences describing the overall change.

## Changes
- Bullet list of specific files/components modified and what changed in each

## Motivation
Why this change is needed — reference the open issue if one exists (`Closes #N` or `Related to #N`).

## Security considerations
- Note any changes to how secrets, passwords, or vault data are handled
- Note any new file permission logic
- Note if bandit was run and the result (clean / findings addressed)

## Testing
- Confirm tests pass: `python -m pytest tests/ -v`
- Note any new tests added or fixtures changed
- If vault operations were changed, confirm they remain mocked in tests

## Breaking changes
- List any changes to CLI flags, JSON schema, or vault file format that affect existing users
- If none: "None"
```

## Referencing issues
- Always link related issues: `Closes #N` (auto-closes on merge) or `Related to #N`
- If the PR partially addresses an issue, say so explicitly

## Checklist before opening
- [ ] Branch is not `main`
- [ ] `python -m pytest tests/ -v` passes locally
- [ ] `bandit -r myvault.py -ll` is clean or findings are documented
- [ ] No plaintext passwords, vault contents, or key material added to any file
- [ ] New vault-handling code validates file permissions (600) before reading
- [ ] Commit(s) are GPG-signed (`git log --show-signature -1`)

## Using the gh CLI

Always use `--body-file` when creating or editing PRs and issues with multi-line descriptions. This applies to `gh pr create`, `gh pr edit`, and `gh issue create`.

### Writing the body file

**Always** write the body file using a dedicated file-creation tool (not the shell). Never use shell heredocs, `echo`, `printf`, or any other shell redirection to create the file. The terminal intercept used in this environment corrupts content written through the shell — backtick-wrapped paths, filenames containing dots, and other special characters will be garbled or duplicated in the final output.

Correct approach:
1. Use the file-creation tool to write the body to a temp file such as `/tmp/pr-body.txt`
2. Pass that file to the gh CLI

```bash
gh pr create --title "feat: description" --body-file /tmp/pr-body.txt --base main
gh pr edit 42 --body-file /tmp/pr-body.txt
gh issue create --title "Bug: description" --body-file /tmp/issue-body.txt
```

3. Delete the temp file after the gh command succeeds

**Never** do any of the following — all will produce corrupted output:
```bash
# WRONG: heredoc through the shell
cat > pr-body.txt << 'EOF'
...
EOF

# WRONG: inline body flag with multi-line content
gh pr create --body "## Summary
..."

# WRONG: echo/printf redirection
echo "## Summary" > pr-body.txt
```
