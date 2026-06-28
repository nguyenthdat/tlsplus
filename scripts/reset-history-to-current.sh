#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Rewrite the current branch so the current HEAD becomes the only root commit.

This uses the safe git-filter-repo graft workflow:
  1. git replace --graft HEAD
  2. git filter-repo --force --refs <current-branch>

It DOES NOT push automatically. After reviewing the rewritten repository,
force-push the branch yourself and delete any obsolete remote tags/branches
that still point to the old history.

Usage:
  scripts/reset-history-to-current.sh --yes-i-understand-history-rewrite

Options:
  --branch <name>    Branch ref to rewrite. Defaults to the current branch.
  --remote <name>    Remote name to restore/print after filter-repo. Default: origin.
  -h, --help         Show this help.

Important:
  - Commit the exact version you want to keep before running this script.
  - Work from a fresh clone or make sure the generated bundle backup is safe.
  - Tell collaborators to re-clone after you force-push rewritten history.
EOF
}

confirm=false
branch=""
remote="origin"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes-i-understand-history-rewrite)
      confirm=true
      ;;
    --branch)
      branch="${2:-}"
      shift
      ;;
    --remote)
      remote="${2:-}"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [[ "${confirm}" != "true" ]]; then
  echo "Refusing to rewrite history without --yes-i-understand-history-rewrite" >&2
  usage >&2
  exit 2
fi

if ! git rev-parse --show-toplevel >/dev/null 2>&1; then
  echo "This script must run inside a Git repository." >&2
  exit 1
fi

if ! git filter-repo --help >/dev/null 2>&1; then
  echo "git-filter-repo is required. Install it first: python3 -m pip install git-filter-repo" >&2
  exit 1
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "${repo_root}"

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree is dirty. Commit/stash changes before rewriting history." >&2
  exit 1
fi

if [[ -z "${branch}" ]]; then
  branch="$(git symbolic-ref --quiet --short HEAD || true)"
fi

if [[ -z "${branch}" ]]; then
  echo "Could not determine current branch. Use --branch <name>." >&2
  exit 1
fi

local_branch_count="$(git for-each-ref --format='%(refname:short)' refs/heads | wc -l | tr -d ' ')"
if [[ "${local_branch_count}" != "1" ]]; then
  echo "Expected exactly one local branch before snapshot rewrite; found ${local_branch_count}." >&2
  echo "Delete/archive extra local branches first, otherwise old commits remain reachable." >&2
  exit 1
fi

tag_count="$(git tag --list | wc -l | tr -d ' ')"
if [[ "${tag_count}" != "0" ]]; then
  echo "Found ${tag_count} local tag(s). Delete/archive tags first, otherwise old commits remain reachable." >&2
  exit 1
fi

replace_count="$(git replace -l | wc -l | tr -d ' ')"
if [[ "${replace_count}" != "0" ]]; then
  echo "Existing git replace refs found. Resolve them before running this script." >&2
  exit 1
fi

old_head="$(git rev-parse HEAD)"
timestamp="$(date +%Y%m%d_%H%M%S)"
backup_dir="${TLSPLUS_HISTORY_BACKUP_DIR:-${repo_root}/../tlsplus-history-backups}"
mkdir -p "${backup_dir}"
safe_branch="${branch//\//-}"
backup_bundle="${backup_dir}/tlsplus-${safe_branch}-${old_head:0:12}-${timestamp}.bundle"
remote_url="$(git remote get-url "${remote}" 2>/dev/null || true)"

echo "Creating full backup bundle: ${backup_bundle}"
git bundle create "${backup_bundle}" --all

echo "Rewriting ${branch}: ${old_head} becomes a single root commit."
git replace --graft HEAD
git filter-repo --force --refs "${branch}"

if [[ -n "${remote_url}" ]]; then
  if git remote get-url "${remote}" >/dev/null 2>&1; then
    git remote set-url "${remote}" "${remote_url}"
  else
    git remote add "${remote}" "${remote_url}"
  fi
fi

git reflog expire --expire=now --all
git gc --prune=now --aggressive

new_head="$(git rev-parse HEAD)"
new_count="$(git rev-list --count HEAD)"

echo "Done."
echo "Old HEAD: ${old_head}"
echo "New HEAD: ${new_head}"
echo "Current branch commit count: ${new_count}"
echo "Backup bundle: ${backup_bundle}"
echo
echo "Review the repository, then publish with:"
echo "  git push --force-with-lease ${remote} ${branch}"
echo
echo "If GitHub still has old tags or branches, delete them too; any ref pointing to old commits keeps old history reachable."
