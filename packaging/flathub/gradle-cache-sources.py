#!/usr/bin/env python3
# gradle-cache-sources.py: writes gradle-sources.json, the Flatpak sources list for the offline
# Gradle build, from what a real online build downloaded.
#
#   python3 packaging/flathub/gradle-cache-sources.py GRADLE_USER_HOME > packaging/flathub/gradle-sources.json
#
# Run it after `createDistributable` has succeeded online against an empty GRADLE_USER_HOME
# (packaging/flathub/README.md, step 2). Every file Gradle fetched is in that home's module
# cache, including the ones resolved outside any declared configuration (Compose's checkRuntime
# probe, for one), which a generator walking the configurations misses. Each file is listed with
# the first repository that serves it (the ones settings.gradle.kts declares), its sha256 taken
# from the cached copy, and a destination in a Maven layout under offline-repository/, which
# offline.init.gradle hands to the offline build.
#
# Native artifacts for one Linux architecture (Skiko's runtime, Compose's desktop-jvm) also get
# their counterpart for the other one, tagged with only-arches, so a single run on either x86_64
# or aarch64 covers both.

import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

REPOSITORIES = [
    "https://repo.maven.apache.org/maven2",
    "https://dl.google.com/dl/android/maven2",
    "https://plugins.gradle.org/m2",
]
ARCH_TOKENS = {"linux-x64": "x86_64", "linux-arm64": "aarch64"}
DEST_ROOT = "offline-repository"


def cached_files(gradle_home):
    """(maven path, local file) for every file in the module cache."""
    root = os.path.join(gradle_home, "caches", "modules-2", "files-2.1")
    if not os.path.isdir(root):
        sys.exit(f"no Gradle module cache at {root}")
    for group in sorted(os.listdir(root)):
        for artifact in sorted(os.listdir(os.path.join(root, group))):
            for version in sorted(os.listdir(os.path.join(root, group, artifact))):
                version_dir = os.path.join(root, group, artifact, version)
                for checksum_dir in sorted(os.listdir(version_dir)):
                    for name in sorted(os.listdir(os.path.join(version_dir, checksum_dir))):
                        path = f"{group.replace('.', '/')}/{artifact}/{version}/{name}"
                        yield path, os.path.join(version_dir, checksum_dir, name)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def request(url, method):
    for attempt in range(4):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, method=method), timeout=60) as r:
                return r.read() if method == "GET" else b""
        except urllib.error.HTTPError as e:
            if e.code in (403, 404):
                return None
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            pass
        time.sleep(1 + attempt * 2)
    raise RuntimeError(f"no answer from {url}")


def locate(path):
    """The first repository URL that serves [path], or None."""
    for repo in REPOSITORIES:
        url = f"{repo}/{path}"
        if request(url, "HEAD") is not None:
            return url
    return None


def arch_of(path):
    for token, arch in ARCH_TOKENS.items():
        if token in path:
            return token, arch
    return None, None


def entry(path, url, sha256, arch):
    directory, name = path.rsplit("/", 1)
    source = {
        "type": "file",
        "url": url,
        "sha256": sha256,
        "dest": f"{DEST_ROOT}/{directory}",
        "dest-filename": name,
    }
    if arch:
        source["only-arches"] = [arch]
    return source


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: gradle-cache-sources.py GRADLE_USER_HOME")
    local = dict(cached_files(sys.argv[1]))

    # The other architecture's natives, fetched to hash them.
    siblings = {}
    for path in local:
        token, _ = arch_of(path)
        if token:
            other = next(t for t in ARCH_TOKENS if t != token)
            twin = path.replace(token, other)
            if twin not in local:
                siblings[twin] = None

    with ThreadPoolExecutor(max_workers=16) as pool:
        urls = dict(zip(local, pool.map(locate, local)))
        sibling_urls = dict(zip(siblings, pool.map(locate, siblings)))

    sources, missing = [], []
    for path, file in local.items():
        if urls[path] is None:
            missing.append(path)
            continue
        sources.append(entry(path, urls[path], sha256_file(file), arch_of(path)[1]))
    for path, url in sibling_urls.items():
        if url is None:
            missing.append(path)
            continue
        sources.append(entry(path, url, hashlib.sha256(request(url, "GET")).hexdigest(), arch_of(path)[1]))

    for path in missing:
        print(f"not found in any repository: {path}", file=sys.stderr)
    sources.sort(key=lambda s: (s["dest"], s["dest-filename"]))
    json.dump(sources, sys.stdout, indent=2)
    sys.stdout.write("\n")
    print(f"{len(sources)} sources, {len(missing)} not found", file=sys.stderr)


if __name__ == "__main__":
    main()
