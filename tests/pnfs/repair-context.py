"""Narrow, fixture-only Ganesha 4.3 pNFS context lifetime repair.

Keep the original source beside the patched file. Never apply to a host service.
Current upstream clears ctx_pnfs_ds after releasing its reference; 4.3 does not.
"""
from pathlib import Path
import hashlib
import json
import sys

source = Path(sys.argv[1])
original = source.with_suffix(".c.pnfs-original")
text = source.read_text()
start = text.index("static inline void clear_op_context_export_impl(void)")
end = text.index("void clear_op_context_export(void)", start)
old = "\tif (op_ctx->ctx_pnfs_ds != NULL)\n\t\tpnfs_ds_put(op_ctx->ctx_pnfs_ds);"
new = "\tif (op_ctx->ctx_pnfs_ds != NULL) {\n\t\tpnfs_ds_put(op_ctx->ctx_pnfs_ds);\n\t\top_ctx->ctx_pnfs_ds = NULL;\n\t}"
section = text[start:end]
assert section.count(old) == 1, "unexpected source or already repaired"
assert not original.exists(), "original already retained"
original.write_bytes(source.read_bytes())
source.write_text(text[:start] + section.replace(old, new) + text[end:])
print(json.dumps({"original_sha256": hashlib.sha256(original.read_bytes()).hexdigest(),
                  "repaired_sha256": hashlib.sha256(source.read_bytes()).hexdigest()}))
