#!/usr/bin/env python3
"""Strip Co-Authored-By lines from all commit messages."""
import subprocess, re, sys, os

os.environ["GIT_COMMITTER_NAME"] = "Umang"
os.environ["GIT_COMMITTER_EMAIL"] = "umang@scint.dev"

# Get all commits oldest-first
result = subprocess.run(
    ["git", "log", "--format=%H", "--reverse"],
    capture_output=True, text=True
)
all_hashes = result.stdout.strip().split("\n")

# Find which ones have Co-Authored-By
to_fix = []
for h in all_hashes:
    msg = subprocess.run(
        ["git", "log", "-1", "--format=%B", h],
        capture_output=True, text=True
    ).stdout
    if "Co-Authored-By:" in msg:
        to_fix.append(h)

if not to_fix:
    print("No commits with Co-Authored-By found.")
    sys.exit(0)

print(f"Found {len(to_fix)} commits to fix.")

# Find the parent of the earliest commit to fix
parent = subprocess.run(
    ["git", "rev-parse", to_fix[0] + "^"],
    capture_output=True, text=True
).stdout.strip()

print(f"Rebasing from {parent[:8]}...")

# Set GIT_SEQUENCE_EDITOR to change pick -> edit for target commits
# Build sed command
sed_parts = []
for h in to_fix:
    short = h[:8]
    sed_parts.append(f"s/^pick {short}/edit {short}/")

sed_cmd = "; ".join(sed_parts)

# Start rebase
env = os.environ.copy()
env["GIT_SEQUENCE_EDITOR"] = f'sed -i "{sed_cmd}"'

proc = subprocess.run(
    ["git", "rebase", "-i", parent],
    env=env, capture_output=True, text=True
)

if proc.returncode != 0 and "Could not apply" not in proc.stderr:
    # If rebase -i doesn't work with sed on Windows, try manual approach
    subprocess.run(["git", "rebase", "--abort"], capture_output=True)
    print("Rebase approach failed, trying manual reset method...")

    # Alternative: soft-reset approach
    # Save current branch
    branch = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True, text=True
    ).stdout.strip()

    # Get all commits in order with messages
    commits = []
    for h in all_hashes:
        msg = subprocess.run(
            ["git", "log", "-1", "--format=%B", h],
            capture_output=True, text=True
        ).stdout.strip()
        # Get author info
        author_name = subprocess.run(
            ["git", "log", "-1", "--format=%an", h],
            capture_output=True, text=True
        ).stdout.strip()
        author_email = subprocess.run(
            ["git", "log", "-1", "--format=%ae", h],
            capture_output=True, text=True
        ).stdout.strip()
        author_date = subprocess.run(
            ["git", "log", "-1", "--format=%aI", h],
            capture_output=True, text=True
        ).stdout.strip()
        commits.append((h, msg, author_name, author_email, author_date))

    # Reset to before first commit
    first_commit = all_hashes[0]

    # Create orphan branch
    subprocess.run(["git", "checkout", "--orphan", "temp_clean"], capture_output=True)

    for h, msg, aname, aemail, adate in commits:
        # Checkout tree from this commit
        subprocess.run(["git", "read-tree", h], capture_output=True)
        subprocess.run(["git", "checkout-index", "-a", "-f"], capture_output=True)

        # Clean the message
        cleaned = re.sub(r'\n*Co-Authored-By:.*', '', msg).rstrip()
        # Remove trailing blank lines
        cleaned = re.sub(r'\n{3,}', '\n\n', cleaned).strip()

        env2 = os.environ.copy()
        env2["GIT_AUTHOR_NAME"] = aname
        env2["GIT_AUTHOR_EMAIL"] = aemail
        env2["GIT_AUTHOR_DATE"] = adate
        env2["GIT_COMMITTER_NAME"] = "Umang"
        env2["GIT_COMMITTER_EMAIL"] = "umang@scint.dev"

        subprocess.run(["git", "add", "-A"], capture_output=True)
        result = subprocess.run(
            ["git", "commit", "-m", cleaned, "--allow-empty"],
            env=env2, capture_output=True, text=True
        )
        short_msg = cleaned.split('\n')[0][:50]
        status = "OK" if result.returncode == 0 else "SKIP"
        print(f"  {status}: {short_msg}")

    # Point the original branch to the new history
    subprocess.run(["git", "branch", "-f", branch, "HEAD"], capture_output=True)
    subprocess.run(["git", "checkout", branch], capture_output=True)
    subprocess.run(["git", "branch", "-D", "temp_clean"], capture_output=True)
    print("Done! All Co-Authored-By tags removed.")
    sys.exit(0)

# If rebase started, amend each stopped commit
count = 0
while True:
    # Get current commit message
    msg = subprocess.run(
        ["git", "log", "-1", "--format=%B"],
        capture_output=True, text=True
    ).stdout.strip()

    # Remove Co-Authored-By line
    cleaned = re.sub(r'\n*Co-Authored-By:.*', '', msg).rstrip()
    cleaned = re.sub(r'\n{3,}', '\n\n', cleaned).strip()

    # Amend
    subprocess.run(
        ["git", "commit", "--amend", "-m", cleaned],
        capture_output=True, text=True
    )
    count += 1
    print(f"  Fixed commit {count}/{len(to_fix)}")

    # Continue rebase
    cont = subprocess.run(
        ["git", "rebase", "--continue"],
        capture_output=True, text=True
    )
    if cont.returncode != 0:
        break

print(f"Done! Removed Co-Authored-By from {count} commits.")
