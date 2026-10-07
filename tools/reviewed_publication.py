"""Publish an explicitly classified change by ordinary push after blob review.

Publication is for the existing repository/main only. Receipts stay outside the
checkout. Review-only performs no staging, commit, push or network operation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from review_publication_content import review, require, scan_tracked_documents

REMOTE = 'https://github.com/RunlaiDeng/rldcoin.git'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--selection', type=Path, required=True)
    parser.add_argument('--review-only', action='store_true')
    parser.add_argument('--message')
    parser.add_argument('--receipt-directory', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    selection = json.loads(args.selection.read_text())
    # Content checks MUST precede every Git mutation, including staging.
    reviewed = review(root, selection)
    require(not scan_tracked_documents(root), 'tracked public document content scan refuses')
    if args.review_only:
        print('Public content review completed; no Git mutation.')
        return 0
    require(bool(args.message) and args.receipt_directory is not None,
            'commit message and external receipt directory required')
    receipts = args.receipt_directory.resolve(strict=True)
    require(receipts != root and root not in receipts.parents, 'receipts must remain outside checkout')

    def git(*arguments):
        return subprocess.check_output(['git', *arguments], cwd=root, text=True).strip()

    require(git('branch', '--show-current') == 'main', 'existing main required')
    require(git('remote', 'get-url', 'origin') == REMOTE, 'exact origin required')
    require(not git('diff', '--cached', '--name-only'), 'existing staged changes require separate review')
    parent = git('rev-parse', 'HEAD')
    require(git('ls-remote', 'origin', 'refs/heads/main').split()[0] == parent,
            'remote parent changed; review new reachable history before publishing')
    files = selection['files']
    inventory = [{**item, 'sha256': hashlib.sha256((root / item['path']).read_bytes()).hexdigest()}
                 for item in reviewed]
    git('diff', '--check')
    git('add', '--', *files)
    require(set(git('diff', '--cached', '--name-only').splitlines()) == set(files),
            'exact staged selection differs')
    git('diff', '--cached', '--check')
    # Check staged bytes, not merely the prior working-tree read.
    for item in inventory:
        staged = subprocess.check_output(['git', 'show', ':' + item['path']], cwd=root)
        require(hashlib.sha256(staged).hexdigest() == item['sha256'], 'staged blob changed')
    review_record = {'parent': parent, 'content_classification': selection['content_classification'],
                     'files': inventory, 'human_review_required': True}
    (receipts / 'publication-review.json').write_text(json.dumps(review_record, indent=2) + '\n')
    git('commit', '-m', args.message)
    commit, tree = git('rev-parse', 'HEAD'), git('rev-parse', 'HEAD^{tree}')
    require(git('rev-parse', 'HEAD^') == parent, 'unexpected commit parent')
    require(set(git('diff', '--name-only', parent, commit).splitlines()) == set(files),
            'new reachable blobs differ from reviewed selection')
    for item in inventory:
        blob = subprocess.check_output(['git', 'show', commit + ':' + item['path']], cwd=root)
        require(hashlib.sha256(blob).hexdigest() == item['sha256'], 'commit blob changed')
    git('-c', 'push.followTags=false', '-c', 'remote.origin.mirror=false',
        'push', 'origin', commit + ':refs/heads/main')
    require(git('ls-remote', 'origin', 'refs/heads/main').split()[0] == commit, 'remote differs')
    gh_commit = json.loads(subprocess.check_output(
        ['gh', 'api', 'repos/RunlaiDeng/rldcoin/git/commits/' + commit], cwd=root))
    require(gh_commit['sha'] == commit and gh_commit['tree']['sha'] == tree, 'remote tree differs')
    ci = json.loads(subprocess.check_output(
        ['gh', 'api', 'repos/RunlaiDeng/rldcoin/actions/runs?head_sha=' + commit], cwd=root))
    outcome = {'commit': commit, 'tree': tree, 'remote_exact': True,
               'CI_total_count': ci['total_count'],
               'CI_runs': [{'url': x['html_url'], 'status': x['status'], 'conclusion': x['conclusion']}
                           for x in ci['workflow_runs']]}
    (receipts / 'push-outcome.json').write_text(json.dumps(outcome, indent=2) + '\n')
    print(json.dumps(outcome))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
