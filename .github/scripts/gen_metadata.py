from argparse import ArgumentParser
from pathlib import Path
from typing import cast, List, Generator
from io import IOBase
from lxml import etree as ET
from cabarchive import CabArchive
from hashlib import sha1, sha256
import sys
import subprocess


def url_for_file(base_url: str, path: str):
    p = Path(path)
    return f"{base_url}/{p.name}"


def process_fw_file(base_url: str, path: str) -> ET.Element:
    with open(path, "rb") as file:
        data = file.read()

    h1 = sha1(data)
    h256 = sha256(data)
    url = url_for_file(base_url, path)

    cab = CabArchive(data)

    # Inject URL to .cab files into firmware manifest.
    component = ET.fromstring(cab["firmware.metainfo.xml"].buf)
    releases = component.find("releases")

    for release in releases.findall("release"):
        location = ET.Element("location")
        location.text = url
        release.insert(0, location)

        # This is also required for fwupd to pickup update.
        artifacts = release.find("artifacts")
        artifact_cab = ET.Element("artifact", {"type": "binary"})

        artifact_cab.append(location)

        sha1_node = ET.Element("checksum", {"type": "sha1"})
        sha1_node.text = h1.hexdigest()
        artifact_cab.append(sha1_node)

        sha256_node = ET.Element("checksum", {"type": "sha256"})
        sha256_node.text = h256.hexdigest()
        artifact_cab.append(sha256_node)

        artifacts.append(artifact_cab)

    return component


def jcat(args: List[str], **kwargs):
    all_args = []
    all_args.append("jcat-tool")
    all_args.extend(args)
    subprocess.run(all_args, check=True, stderr=sys.stderr, stdout=sys.stderr, **kwargs)


def open_metadata_xml(path: str) -> Generator[ET.Element]:
    p = Path(path)
    decompressor = None
    if p.stem == "zst":
        decompressor = subprocess.Popen(
            ["zstd", "-q", "-d", "-c", path], stdout=subprocess.PIPE, stderr=sys.stderr
        )
        stream = cast(IOBase, decompressor.stdout)
    else:
        stream = open(path, "rb")

    try:
        context = ET.iterparse(stream, events=("end",), tag="component")
        for action, elem in context:
            yield elem

            elem.clear(keep_tail=True)
            while elem.getprevious() is not None:
                del elem.getparent()[0]
        pass
    finally:
        stream.close()
        if decompressor is not None:
            code = decompressor.wait()
            if code != 0:
                raise RuntimeError(f"zstd returned with error code {code}")


def main():
    parser = ArgumentParser()
    parser.add_argument("--base-url", type=str, required=True)
    parser.add_argument("--key", type=str, help="Private key used for signing")
    parser.add_argument("--cert", type=str, help="Certificate used for signing")
    parser.add_argument(
        "--old-metadata",
        type=str,
        required=False,
        help="Old metadata from which to copy component descriptions",
    )
    parser.add_argument(
        "--metadata-out", type=str, required=True, help="Metadata output file"
    )
    parser.add_argument("file", nargs="*")
    args = parser.parse_args()

    if args.key and not args.cert:
        print("--key requires --cert", file=sys.stderr)
        sys.exit(1)

    if args.cert and not args.key:
        print("--cert requires --key", file=sys.stderr)
        sys.exit(1)

    old_meta = None
    if args.old_metadata:
        old_meta = open_metadata_xml(args.old_metadata)

    compressor = subprocess.Popen(
        ["zstd", "-q", "-19", "-f", "-o", args.metadata_out],
        stderr=sys.stderr,
        stdin=subprocess.PIPE,
    )
    stdin = cast(IOBase, compressor.stdin)
    stdin.write(
        b"""<?xml version='1.0' encoding='utf-8'?><components origin="lvfs" version="0.9">"""
    )

    if old_meta is not None:
        # TODO: allow filtering-out old firmware to prevent metadata growing unbounded
        for component in old_meta:
            stdin.write(ET.tostring(component))

    for file in args.file:
        component = process_fw_file(args.base_url, file)
        stdin.write(ET.tostring(component))

    stdin.write(b"""</components>""")
    stdin.close()

    code = compressor.wait()
    if code != 0:
        raise RuntimeError(f"zstd returned with error code {code}")


if __name__ == "__main__":
    main()
