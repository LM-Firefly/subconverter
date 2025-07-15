import argparse
import configparser
import glob
import logging
import os
import shutil
from git import InvalidGitRepositoryError, Repo


def open_repo(path: str):
    if not os.path.exists(path):
        return None
    try:
        return Repo(path)
    except InvalidGitRepositoryError:
        return None


def update_rules(repo_path: str, save_path: str, matches: list[str], keep_tree: bool):
    os.makedirs(save_path, exist_ok=True)
    for pattern in matches:
        files = glob.glob(os.path.join(repo_path, pattern), recursive=True)
        if len(files) == 0:
            logging.warning(f"no files found for pattern {pattern}")
            continue
        for file in files:
            if os.path.isdir(file):
                continue
            file_rel_path, file_name = os.path.split(os.path.relpath(file, repo_path))
            if keep_tree:
                file_dest_dir = os.path.join(save_path, file_rel_path)
                os.makedirs(file_dest_dir, exist_ok=True)
                file_dest_path = os.path.join(file_dest_dir, file_name)
            else:
                file_dest_path = os.path.join(save_path, file_name)
            shutil.copy2(file, file_dest_path)
            logging.info(f"copied {file} to {file_dest_path}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", default="rules_config.conf")
    args = parser.parse_args()

    config = configparser.ConfigParser()
    config.read(args.config, encoding="utf-8")
    logging.basicConfig(format="%(asctime)s %(message)s", level=logging.DEBUG)

    if not config.sections():
        logging.error(f"no sections found in config {args.config}")
        raise SystemExit(1)

    failed = False
    for section in config.sections():
        repo = config.get(section, "name", fallback=section)
        url = config.get(section, "url")
        commit = config.get(section, "commit", fallback=None)
        branch = config.get(section, "branch", fallback=None)
        matches = config.get(section, "match").split("|")
        save_path = config.get(section, "dest", fallback=f"base/rules/{repo}")
        keep_tree = config.getboolean(section, "keep_tree", fallback=True)

        logging.info(f"reading files from url {url}, matches {matches}, save to {save_path} keep_tree {keep_tree}")

        repo_path = os.path.join("./tmp/repo/", repo)

        r = open_repo(repo_path)
        if r is None:
            logging.info(f"cloning repo {url} to {repo_path}")
            if commit is not None:
                # 指定 commit 需要完整历史才能 checkout
                r = Repo.clone_from(url, repo_path)
            elif branch is not None:
                # 浅克隆加速；commit 模式除外
                r = Repo.clone_from(url, repo_path, branch=branch, depth=1)
            else:
                r = Repo.clone_from(url, repo_path, depth=1)
        else:
            # 复用已有克隆（同名 section 共享）；同时刷新，避免上次中断残留的陈旧内容
            logging.info(f"repo {repo_path} exists, fetching updates")
            r.remotes.origin.fetch()

        try:
            if commit is not None:
                logging.info(f"checking out to commit {commit}")
                r.git.checkout(commit)
            elif branch is not None:
                logging.info(f"checking out to branch {branch}")
                r.git.checkout("-B", branch, f"origin/{branch}")
            else:
                default = r.git.symbolic_ref("refs/remotes/origin/HEAD", "--short").split("/")[-1]
                logging.info(f"checking out to default branch {default}")
                r.git.checkout("-B", default, f"origin/{default}")
        except Exception as e:
            logging.error(f"checkout failed {e}")
            failed = True
            continue

        update_rules(repo_path, save_path, matches, keep_tree)

    shutil.rmtree("./tmp", ignore_errors=True)
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
