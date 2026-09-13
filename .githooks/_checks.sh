#!/bin/sh
# Shared content checks, sourced by pre-commit and pre-push.
#
# These exist because AGENTS.md section 6 asks contributors never to commit
# secrets, credentials, or real hostnames from their own network. That was a
# request; this makes it a mechanism. A push to a public repository cannot be
# taken back, and neither can a secret that reached its history.
#
# Two design rules, both learned the hard way:
#
#   * A guard with false positives gets disabled. Every pattern here is checked
#     against this repository's own tree, which legitimately contains a
#     private-key header in a form placeholder (ScanFormView.tsx) and a
#     discussion of PEM headers in the methodology doc. So the key check
#     requires a BEGIN *and* a matching END marker: prose and placeholders have
#     one, real key material has both.
#
#   * Scan the diff, not just the final tree. History is published too, so a
#     secret added in one commit and deleted in the next still leaks.

# The empty tree, used as the base when pushing a branch the remote has never
# seen. It makes "first push" and "incremental push" one code path.
CVEDECK_EMPTY_TREE=4b825dc642cb6eb9a060e54bf8d69288fbee4904

# Personal patterns live outside the repository on purpose: a tracked file
# naming the exact hosts that must never be published would publish them, which
# defeats the point. Absent is fine; the generic checks below still run.
CVEDECK_DENYLIST=".githooks/local-denylist"

cvedeck_say()  { printf '%s\n' "$*"; }
cvedeck_warn() { printf '  ! %s\n' "$*" >&2; }

cvedeck_banner() {
    printf '\n' >&2
    printf '  ============================================================\n' >&2
    printf '   %s REFUSED: %s\n' "${CVEDECK_ACTION:-PUSH}" "$1" >&2
    printf '  ============================================================\n' >&2
}

# This folder's role, from local git config. Local config is never pushed, so
# the role describes one checkout and says nothing to anyone who clones.
#
#   staging   a private working folder that must never publish
#   public    a clean room that only receives snapshots and publishes them
#   (unset)   an ordinary clone -- a contributor's, say -- with no role rules
cvedeck_role() {
    git config --get cvedeck.role 2>/dev/null || true
}

# ------------------------------------------------------- force-added ignores --
#
# A file can only be both tracked and matched by an ignore rule if someone ran
# `git add -f`. That is exactly the move that defeats an ignore rule, so refuse
# it -- for every ignore source at once (.gitignore, .git/info/exclude, the
# global excludes file), without this tracked script having to name a single
# file. Local working documents stay local without their names being published.
#
# $1 is a tree-ish to inspect, or empty for the index.
cvedeck_check_force_added() {
    if [ -z "$1" ]; then
        _ignored=$(git ls-files --cached --ignored --exclude-standard)
    else
        _ignored=$(git ls-tree -r --name-only "$1" |
            git check-ignore --no-index --stdin 2>/dev/null)
    fi
    [ -z "$_ignored" ] && return 0
    printf '%s\n' "$_ignored" | while IFS= read -r _f; do
        printf '    %s\n        tracked, but an ignore rule says it should not be\n' "$_f"
    done
    return 1
}

# ---------------------------------------------------------------- filenames --
#
# stdin: one path per line. Prints one line per offence. Returns 1 if any.
cvedeck_check_paths() {
    _found=0
    while IFS= read -r _p; do
        [ -n "$_p" ] || continue
        _base=${_p##*/}
        case "$_base" in
            # Templates are the documented way to ship configuration, and
            # .env.example is tracked deliberately.
            .env.example|.env.sample|.env.template)
                continue
                ;;
            .env|.env.*)
                printf '    %s\n        an environment file: these hold real credentials\n' "$_p"
                _found=1
                ;;
            *.db|*.sqlite|*.sqlite3)
                printf '    %s\n        a database: the scan databases hold real host data\n' "$_p"
                _found=1
                ;;
            *.pem|*.key|*.p12|*.pfx|*.kdbx|*.jks)
                printf '    %s\n        key or certificate material\n' "$_p"
                _found=1
                ;;
            id_rsa*|id_ed25519*|id_ecdsa*|id_dsa*)
                printf '    %s\n        an SSH private key\n' "$_p"
                _found=1
                ;;
        esac
    done
    return $_found
}

# ------------------------------------------------------------------ content --
#
# stdin: unified diff output. Only added lines are examined, because a line
# being removed is not a line being published.
cvedeck_check_added_lines() {
    _tmp=$(mktemp) || { cvedeck_warn "could not create a temp file; content scan skipped"; return 0; }
    # Keep added lines, drop the '+++ b/path' headers, strip the leading '+'.
    grep '^+' | grep -v '^+++' | sed 's/^+//' > "$_tmp"

    _found=0

    # Real key material carries both markers. A placeholder or a sentence about
    # PEM headers carries only the first.
    if grep -qE -- '-----BEGIN [A-Z ]*PRIVATE KEY-----' "$_tmp" &&
       grep -qE -- '-----END [A-Z ]*PRIVATE KEY-----' "$_tmp"; then
        printf '    a private key block (both BEGIN and END markers present)\n'
        _found=1
    fi

    # Provider token shapes. These are unambiguous: nothing legitimately looks
    # like one.
    if grep -qE -- 'AKIA[0-9A-Z]{16}' "$_tmp"; then
        printf '    an AWS access key id (AKIA...)\n'
        _found=1
    fi
    if grep -qE -- 'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|gho_[A-Za-z0-9]{36}' "$_tmp"; then
        printf '    a GitHub token\n'
        _found=1
    fi
    if grep -qE -- 'xox[baprs]-[A-Za-z0-9-]{10,}' "$_tmp"; then
        printf '    a Slack token\n'
        _found=1
    fi

    # Personal patterns, if the operator has any.
    if [ -f "$CVEDECK_DENYLIST" ]; then
        while IFS= read -r _pat; do
            case "$_pat" in '' | \#*) continue ;; esac
            if grep -qiE -- "$_pat" "$_tmp"; then
                _hit=$(grep -iE -o -- "$_pat" "$_tmp" | head -1)
                printf '    "%s"\n        matches a local denylist pattern: %s\n' "$_hit" "$_pat"
                _found=1
            fi
        done < "$CVEDECK_DENYLIST"
    fi

    rm -f "$_tmp"
    return $_found
}

# Report whether the personal denylist is in play, so its silent absence is
# never mistaken for a clean result.
cvedeck_denylist_status() {
    if [ -f "$CVEDECK_DENYLIST" ]; then
        printf '%s active (%s patterns)\n' "$CVEDECK_DENYLIST" \
            "$(grep -cvE '^\s*(#|$)' "$CVEDECK_DENYLIST" 2>/dev/null || echo 0)"
    else
        printf 'no %s -- generic checks only\n' "$CVEDECK_DENYLIST"
    fi
}
