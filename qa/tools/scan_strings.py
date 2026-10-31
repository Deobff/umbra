#!/usr/bin/env python3
"""Static readability scan for an obfuscated jar.

Parses class files directly (no javap dependency), then reports:

* number of constant-pool UTF-8 entries, human-readable text candidates,
  class references and member names;
* which known demo markers (string literals, class/method/field names) are
  still present in clear text and in which class;
* plaintext resources inside the archive.

The output is a JSON document so the verification summary can quote exact
numbers.  This is evidence for the deobfuscation-resistance section: it is the
same thing an analyst gets by unzipping the jar and running `strings`/`javap`.
"""

import argparse
import hashlib
import io
import json
import re
import struct
import sys
import zipfile

# Markers from demo/ that a protected jar should no longer expose in clear text,
# except where a feature deliberately keeps them (reflection keep rules).
STRING_MARKERS = [
    "Hello, Umbra!",
    "hello, umbra!",
    "HELLO, UMBRA!",
    "Hello, World!",
    "the quick brown fox jumps over the lazy dog 0123456789",
    "umbra-demo-string-sentinel-42",
    "\u4f60\u597d\uff0c\u4e16\u754c",
    "\u00dcn\u00efc\u00f6d\u00e9 Caf\u00e9",
    "\u03b1\u03b2\u03b3\u03b4\u03b5",
    "tag/42/3.50/Z",
    "umbra-depot",
    "resource-ok",
    "umbra-demo-resource",
    "alpha=17",
    "gamma=" + "\u4f60\u597d",
    "umbra-demo",
]

CLASS_MARKERS = [
    "demo/Main",
    "demo/StringSuite",
    "demo/MathSuite",
    "demo/FlowSuite",
    "demo/ExceptionSuite",
    "demo/ShapeSuite",
    "demo/FunctionalSuite",
    "demo/ArraySuite",
    "demo/Inventory",
    "demo/InventorySuite",
    "demo/ReflectionProbe",
    "demo/WorkerSuite",
    "demo/ResourceSuite",
    "demo/Shape",
    "demo/BaseShape",
    "demo/Circle",
    "demo/Rectangle",
    "demo/Square",
    "demo/Color",
    "demo/DemoException",
    "demo/Checks",
]

METHOD_MARKERS = [
    "secretNumber",
    "tag",
    "factorial",
    "fibonacci",
    "collatzSteps",
    "dayName",
    "wordRank",
    "charClass",
    "temperature",
    "clamp",
    "divide",
    "safeParse",
    "perimeter",
    "describe",
]

FIELD_MARKERS = [
    "hidden",
    "TAG",
    "INT_MAGIC",
    "LONG_MAGIC",
    "DOUBLE_MAGIC",
    "STORE_NAME",
    "MAX_SLOTS",
    "instances",
    "stock",
]

DESCRIPTOR_RE = re.compile(r"^[\[(].*[;)VZBCSIJFD\[/<>$]*$")
CLASS_NAME_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$/]*(?:<[^>]*>)?$")
MEMBER_NAME_RE = re.compile(r"^[A-Za-z_$<>][A-Za-z0-9_$<>/]*$")
MARKER_NAME_RE = re.compile(r"^[A-Za-z0-9_$]+$")


class ClassFileError(Exception):
    pass


def read_constant_pool(data):
    """Returns (utf8 dict, class_refs set, cp_list, position after pool)."""
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        raise ClassFileError("not a class file")
    cp_count = struct.unpack(">H", data[8:10])[0]
    utf8 = {}
    cp = [None] * cp_count
    index = 10
    slot = 1
    while slot < cp_count:
        if index >= len(data):
            raise ClassFileError("truncated constant pool")
        tag = data[index]
        index += 1
        if tag == 1:  # CONSTANT_Utf8
            length = struct.unpack(">H", data[index:index + 2])[0]
            index += 2
            raw = data[index:index + length]
            index += length
            value = raw.decode("utf-8", "replace")
            utf8[slot] = value
            cp[slot] = (tag, value)
        elif tag in (3, 4):  # Integer, Float
            index += 4
            cp[slot] = (tag, None)
        elif tag in (5, 6):  # Long, Double (take two slots)
            index += 8
            cp[slot] = (tag, None)
            slot += 1
        elif tag in (7, 8, 16, 19, 20):  # Class, String, MethodType, Module, Package
            ref = struct.unpack(">H", data[index:index + 2])[0]
            index += 2
            cp[slot] = (tag, ref)
        elif tag in (9, 10, 11, 12, 17, 18):  # refs, NameAndType, Dynamic
            first, second = struct.unpack(">HH", data[index:index + 4])
            index += 4
            cp[slot] = (tag, (first, second))
        elif tag == 15:  # MethodHandle
            index += 3
            cp[slot] = (tag, None)
        else:
            raise ClassFileError("unknown constant pool tag %d" % tag)
        slot += 1
    return utf8, cp, index


def read_members(data, position, utf8, count_names):
    names = set()
    try:
        member_count = struct.unpack(">H", data[position:position + 2])[0]
    except struct.error:
        raise ClassFileError("truncated member table")
    position += 2
    for _ in range(member_count):
        if position + 8 > len(data):
            raise ClassFileError("truncated member")
        _access, name_index, _descriptor, attribute_count = struct.unpack(
            ">HHHH", data[position:position + 8])
        position += 8
        name = utf8.get(name_index)
        if name and (count_names is None or name in count_names):
            names.add(name)
        for _ in range(attribute_count):
            if position + 6 > len(data):
                raise ClassFileError("truncated attribute")
            attribute_length = struct.unpack(">I", data[position + 2:position + 6])[0]
            position += 6 + attribute_length
    return names, position


def scan_class(data):
    utf8, cp, position = read_constant_pool(data)
    class_refs = set()
    for entry in cp:
        if not entry:
            continue
        tag, value = entry
        if tag == 7 and value:
            name = utf8.get(value)
            if name:
                class_refs.add(name)
    # access_flags, this_class, super_class
    if position + 6 > len(data):
        raise ClassFileError("truncated class header")
    position += 6
    interface_count = struct.unpack(">H", data[position:position + 2])[0]
    position += 2 + interface_count * 2
    field_names, position = read_members(data, position, utf8, None)
    method_names, position = read_members(data, position, utf8, None)
    return {
        "utf8": utf8,
        "class_refs": class_refs,
        "field_names": field_names,
        "method_names": method_names,
    }


def is_human_text(value):
    if len(value) < 4:
        return False
    if DESCRIPTOR_RE.match(value):
        return False
    if value.startswith("java/") or value.startswith("javax/"):
        return False
    if value in ("Code", "LineNumberTable", "LocalVariableTable", "SourceFile",
                 "StackMapTable", "Exceptions", "Signature", "InnerClasses",
                 "BootstrapMethods", "ConstantValue", "this", "<init>", "<clinit>"):
        return False
    if any(ord(ch) > 127 for ch in value):
        return True
    if " " in value:
        return True
    return False


def is_identifier(value):
    return bool(MEMBER_NAME_RE.match(value)) and len(value) >= 2 and not DESCRIPTOR_RE.match(value)


def locate_markers(utf8_values, class_refs, field_names, method_names,
                   string_markers, class_markers, method_markers, field_markers,
                   class_name):
    """Returns {category: {marker: [class names]}} for one class."""
    hits = {"strings": {}, "classes": {}, "methods": {}, "fields": {}}
    values = list(utf8_values)
    for marker in string_markers:
        if marker in values:
            hits["strings"].setdefault(marker, []).append(class_name)
    for marker in class_markers:
        if marker in class_refs:
            hits["classes"].setdefault(marker, []).append(class_name)
    for marker in method_markers:
        if marker in method_names:
            hits["methods"].setdefault(marker, []).append(class_name)
    for marker in field_markers:
        if marker in field_names:
            hits["fields"].setdefault(marker, []).append(class_name)
    return hits


def scan_jar(jar_path):
    result = {
        "jar": jar_path,
        "sha256": None,
        "sizeBytes": 0,
        "entries": 0,
        "classes": 0,
        "resources": [],
        "counts": {
            "utf8Total": 0,
            "humanText": 0,
            "classRefs": 0,
            "methodNames": 0,
            "fieldNames": 0,
            "identifiersLong": 0,
        },
        "humanTextSample": [],
        "classNames": [],
        "methodNameSample": [],
        "fieldNameSample": [],
        # Lists of {"marker": ..., "classes": [...]} so that markers differing
        # only by case stay distinct for case-insensitive JSON parsers.
        "markerHits": {"strings": [], "classes": [], "methods": [], "fields": []},
        "markerSummary": {"strings": 0, "classes": 0, "methods": 0, "fields": 0,
                          "totals": {"strings": len(STRING_MARKERS), "classes": len(CLASS_MARKERS),
                                     "methods": len(METHOD_MARKERS), "fields": len(FIELD_MARKERS)}},
        "parseFailures": [],
        "resourceMarkerHits": [],
    }
    with open(jar_path, "rb") as handle:
        data = handle.read()
    result["sizeBytes"] = len(data)
    result["sha256"] = hashlib.sha256(data).hexdigest()

    utf8_all = set()
    class_names = set()
    method_names = set()
    field_names = set()
    marker_found = {"strings": {}, "classes": {}, "methods": {}, "fields": {}}
    resource_found = {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        result["entries"] = len(archive.infolist())
        for info in archive.infolist():
            name = info.filename
            if name.endswith("/"):
                continue
            blob = archive.read(name)
            if name.endswith(".class"):
                result["classes"] += 1
                try:
                    parsed = scan_class(blob)
                except ClassFileError as error:
                    result["parseFailures"].append({"class": name, "error": str(error)})
                    continue
                class_name = name[:-6]
                class_names.add(class_name)
                utf8_all.update(parsed["utf8"].values())
                method_names.update(parsed["method_names"])
                field_names.update(parsed["field_names"])
                hits = locate_markers(
                    parsed["utf8"].values(), parsed["class_refs"],
                    parsed["field_names"], parsed["method_names"],
                    STRING_MARKERS, CLASS_MARKERS, METHOD_MARKERS, FIELD_MARKERS,
                    class_name)
                for category, found in hits.items():
                    for marker, classes in found.items():
                        marker_found[category].setdefault(marker, [])
                        marker_found[category][marker].extend(classes)
            else:
                resource = {
                    "name": name,
                    "sizeBytes": len(blob),
                    "text": False,
                    "markers": [],
                }
                try:
                    text = blob.decode("utf-8")
                    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
                    if text and printable / len(text) > 0.95:
                        resource["text"] = True
                        for marker in STRING_MARKERS:
                            if marker in text:
                                resource["markers"].append(marker)
                                resource_found.setdefault(marker, []).append(name)
                except UnicodeDecodeError:
                    pass
                result["resources"].append(resource)

    human = [value for value in utf8_all if is_human_text(value)]
    identifiers = [value for value in utf8_all if is_identifier(value) and len(value) >= 8]
    result["counts"]["utf8Total"] = len(utf8_all)
    result["counts"]["humanText"] = len(human)
    result["counts"]["classRefs"] = len(class_names)
    result["counts"]["methodNames"] = len(method_names)
    result["counts"]["fieldNames"] = len(field_names)
    result["counts"]["identifiersLong"] = len(identifiers)
    result["humanTextSample"] = sorted(human)[:80]
    result["classNames"] = sorted(class_names)[:80]
    result["methodNameSample"] = sorted(method_names)[:80]
    result["fieldNameSample"] = sorted(field_names)[:80]
    for category, found in marker_found.items():
        result["markerHits"][category] = [
            {"marker": marker, "classes": sorted(set(classes))[:8]}
            for marker, classes in sorted(found.items())
        ]
        result["markerSummary"][category] = len(found)
    result["resourceMarkerHits"] = [
        {"marker": marker, "resources": sorted(set(resources))}
        for marker, resources in sorted(resource_found.items())
    ]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jar", required=True, help="jar to scan")
    parser.add_argument("--out", default="", help="write JSON result here")
    parser.add_argument("--label", default="", help="label stored in the JSON")
    args = parser.parse_args()
    result = scan_jar(args.jar)
    if args.label:
        result["label"] = args.label
    text = json.dumps(result, indent=2, ensure_ascii=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
        hits = result["markerHits"]
        summary = ("scanned {jar}: classes={classes} humanText={h} classRefs={c} "
                   "markers present: strings={s}/{st} classes={cl}/{ct} "
                   "methods={m}/{mt} fields={f}/{ft} resources={res}").format(
            jar=args.jar,
            classes=result["classes"],
            h=result["counts"]["humanText"],
            c=result["counts"]["classRefs"],
            s=len(hits["strings"]), st=len(STRING_MARKERS),
            cl=len(hits["classes"]), ct=len(CLASS_MARKERS),
            m=len(hits["methods"]), mt=len(METHOD_MARKERS),
            f=len(hits["fields"]), ft=len(FIELD_MARKERS),
            res=len(result["resources"]))
        print(summary)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
