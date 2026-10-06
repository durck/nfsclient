"""Reproduce narrow build repairs for the disposable, pinned LizardFS fixture.

The existing ../repair-context.py separately owns the Ganesha DS lifetime fix.
This script does not modify layout producers, stripe mapping, or DS I/O.
"""
from pathlib import Path
import argparse
import difflib
import hashlib
import json


def digest(data):
    return hashlib.sha256(data).hexdigest()


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--lizard-source", required=True, type=Path)
parser.add_argument("--ganesha-source", required=True, type=Path,
                    help="Ganesha src directory")
parser.add_argument("--check", action="store_true", help="Validate without writing")
args = parser.parse_args()
lz = args.lizard_source.resolve(strict=True)
g = args.ganesha_source.resolve(strict=True)
fsal = g / "FSAL/FSAL_LIZARDFS"
changes = []


def prepare(path, replacements):
    original = path.read_bytes()
    updated = original.decode("utf-8")
    backup = path.with_name(path.name + ".pnfs10-original")
    assert not backup.exists(), f"Backup already exists: {backup}"
    for old, new in replacements:
        assert updated.count(old) == 1, f"Unexpected or already repaired source: {path}: {old!r}"
        updated = updated.replace(old, new)
    changes.append((path, backup, original, updated.encode("utf-8")))


prepare(lz / "src/common/io_limits_config_loader.h", [
    ("#include <map>\n", "#include <map>\n#include <cstdint>\n")])
prepare(lz / "src/mount/client/lizard_client_c_linkage.h", [
    ("int lizardfs_opendir(LizardClient::Context &ctx, LizardClient::Inode ino);",
     "int lizardfs_opendir(LizardClient::Context &ctx, LizardClient::Inode ino, uint64_t opendirSessionID);")])
prepare(lz / "src/mount/client/lizard_client_c_linkage.cc", [
    ("int lizardfs_opendir(Context &ctx, Inode ino) {\n\ttry {\n\t\tLizardClient::opendir(ctx, ino);",
     "int lizardfs_opendir(Context &ctx, Inode ino, uint64_t opendirSessionID) {\n\ttry {\n"
     "\t\tLizardClient::opendir(ctx, ino);\n\t\tLizardClient::update_readdir_session(opendirSessionID, 0);")])
prepare(lz / "src/mount/client/client.cc", [
    ("\tint ret = lizardfs_opendir_(ctx, inode);",
     "\tuint64_t opendirSessionID = nextOpendirSessionID_++;\n"
     "\tint ret = lizardfs_opendir_(ctx, inode, opendirSessionID);"),
    ("FileInfo *fileinfo = new FileInfo(inode, nextOpendirSessionID_++);",
     "FileInfo *fileinfo = new FileInfo(inode, opendirSessionID);")])
lock_fields = ("\tflock_wrapper.l_start = lock->l_start;\n"
               "\tflock_wrapper.l_len = lock->l_len;\n"
               "\tflock_wrapper.l_pid = lock->l_pid;\n"
               "\tstd::error_code ec;\n")
prepare(lz / "src/mount/client/lizardfs_c_api.cc", [
    ('#include "mount/client/iovec_traits.h"\n',
     '#include "mount/client/iovec_traits.h"\n#include "mount/fuse/lock_conversion.h"\n'),
    ("\tif (lizardfs_error_code < 0) {\n",
     "\tif (lizardfs_error_code == LIZARDFS_ERROR_WAITING) {\n"
     "\t\treturn EAGAIN;\n\t} else if (lizardfs_error_code < 0) {\n"),
    ("\tflock_wrapper.l_type = lock->l_type;\n" + lock_fields +
     "\tliz_lock_interrupt_info_t interrupt_info;",
     "\tflock_wrapper.l_type = lzfs_locks::posixOpConv(lock->l_type, handler != nullptr);\n" +
     lock_fields + "\tliz_lock_interrupt_info_t interrupt_info;"),
    ("\tflock_wrapper.l_type = lock->l_type;\n" + lock_fields +
     "\tclient.getlk(context, fi->inode, fi, flock_wrapper, ec);",
     "\tflock_wrapper.l_type = lzfs_locks::posixOpConv(lock->l_type, true);\n" +
     lock_fields + "\tclient.getlk(context, fi->inode, fi, flock_wrapper, ec);"),
    ("\tlock->l_type = flock_wrapper.l_type;\n",
     "\tlock->l_type = lzfs_locks::convertToFlock(flock_wrapper).l_type;\n")])
prepare(fsal / "CMakeLists.txt", [
    ("   export.c\n", "   export.c\n   fileinfo_cache.c\n")])
prepare(fsal / "lzfs_acl.c", [
    ("void lzfs_int_apply_masks(liz_acl_t *lzfs_acl, uint32_t owner);", ""),
    ("lzfs_int_apply_masks(acl, owner_id);", "liz_acl_apply_masks(acl, owner_id);")])
prepare(fsal / "lzfs_internal.h", [
    ("\tstruct fsal_obj_handle handle; /*< The public handle */\n",
     "\tstruct fsal_obj_handle handle; /*< The public handle */\n\tstruct fsal_obj_ops obj_ops;\n")])
prepare(fsal / "lzfs_internal.c", [
    ("\tfsal_obj_handle_init(&result->handle,\n",
     "\tresult->handle.obj_ops = &result->obj_ops;\n"
     "\tfsal_default_obj_ops_init(result->handle.obj_ops);\n"
     "\tlzfs_fsal_handle_ops_init(lzfs_export, result->handle.obj_ops);\n\n"
     "\tfsal_obj_handle_init(&result->handle,\n"),
    ("\t\t\t     posix2fsal_type(attr->st_mode));\n"
     "\tlzfs_fsal_handle_ops_init(lzfs_export, result->handle.obj_ops);\n",
     "\t\t\t     posix2fsal_type(attr->st_mode));\n")])
prepare(fsal / "handle.c", [
    ("\tfor (i = 0; i < write_arg->iov_count; i++) {\n",
     "\twrite_arg->io_amount = 0;\n\tfor (i = 0; i < write_arg->iov_count; i++) {\n"),
    ("\t\t\twrite_arg->io_amount = nb_written;\n", "")])
prepare(g / "Protocols/NFS/nfs4_op_layoutreturn.c", [
    ("\t\t     sizeof(void *) * (recalls - 1));\n",
     "\t\t     sizeof(void *) * (recalls ? recalls - 1 : 0));\n")])

symbols = ["fsal_supports", "fsal_maxfilesize", "fsal_maxread", "fsal_maxwrite",
           "fsal_maxlink", "fsal_maxnamelen", "fsal_maxpathlen", "fsal_umask"]
version = g / "MainNFSD/libganesha_nfsd.ver"
version_text = version.read_text()
helpers = (g / "FSAL/fsal_config.c").read_text()
for symbol in symbols:
    assert symbol + ";" not in version_text, f"Already exported: {symbol}"
    assert symbol + "(" in helpers, f"Missing existing helper: {symbol}"
prepare(version, [("global:", "global:\n" + "".join("\t" + s + ";\n" for s in symbols))])

cache_source = lz / "src/nfs-ganesha/fileinfo_cache.c"
cache_target = fsal / "fileinfo_cache.c"
cache_bytes = cache_source.read_bytes()
assert not cache_target.exists(), f"Cache implementation already exists: {cache_target}"
assert "liz_acl_apply_masks(acl, owner_id);" in (lz / "src/nfs-ganesha/lzfs_acl.c").read_text()

report = {"check_only": args.check, "repairs": [], "import": {
    "source": str(cache_source), "target": str(cache_target), "sha256": digest(cache_bytes)}}
for path, backup, original, updated in changes:
    report["repairs"].append({
        "path": str(path), "backup": str(backup),
        "original_sha256": digest(original), "repaired_sha256": digest(updated),
        "diff": "".join(difflib.unified_diff(
            original.decode("utf-8").splitlines(True), updated.decode("utf-8").splitlines(True),
            fromfile=str(backup), tofile=str(path)))})
if not args.check:
    for path, backup, original, updated in changes:
        backup.write_bytes(original)
        path.write_bytes(updated)
    cache_target.write_bytes(cache_bytes)
print(json.dumps(report, indent=2))
