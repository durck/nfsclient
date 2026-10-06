"""Opt-in, disposable Ganesha 4.3/Gluster recall trigger; never a server repair.

The production FSAL does not invoke layoutrecall. This fixture-only hook queues
its normal upcall 500 ms after LAYOUTGET when NFS_VIEWER_TEST_RECALL=1. It does
not construct callback packets or replace the server's callback/state machinery.
Keep the export configured until pending callbacks finish, then stop the daemon.
"""
from pathlib import Path
import hashlib
import json
import sys

path = Path(sys.argv[1])
original = path.read_text()
marker = "/* NFS_VIEWER_TEST_RECALL: disposable fixture instrumentation. */"
backup = path.with_name(path.name + ".recall-original")
if marker in original:
    original = backup.read_text()
if backup.exists():
    assert backup.read_text() == original, "original backup differs"
anchor = "#define MAX_DS_COUNT 100\n"
assert original.count(anchor) == 1
hook = r'''
#include <pthread.h>
#include <unistd.h>
#include "fridgethr.h"

/* NFS_VIEWER_TEST_RECALL: disposable fixture instrumentation. */
struct nv_recall_job {
    const struct fsal_up_vector *vec;
    struct gsh_export *exp;
    size_t length;
    unsigned char key[128];
};

static void nv_recall_result(void *unused, state_status_t status)
{
    LogEvent(COMPONENT_PNFS, "NFS_VIEWER_TEST_RECALL result=%d", status);
}

static void *nv_recall_run(void *opaque)
{
    struct nv_recall_job *job = opaque;
    usleep(500000);
    struct gsh_buffdesc key = { .addr = job->key, .len = job->length };
    struct pnfs_segment segment = { .io_mode = LAYOUTIOMODE4_ANY,
                                   .offset = 0, .length = UINT64_MAX };
    fsal_status_t status = up_async_layoutrecall(general_fridge, job->vec,
        &key, LAYOUT4_NFSV4_1_FILES, false, &segment, NULL, NULL,
        nv_recall_result, NULL);
    LogEvent(COMPONENT_PNFS, "NFS_VIEWER_TEST_RECALL queued=%d", status.major);
    put_gsh_export(job->exp);
    gsh_free(job);
    return NULL;
}

static void nv_recall_schedule(struct fsal_obj_handle *obj,
                               struct glusterfs_export *export)
{
    const char *enabled = getenv("NFS_VIEWER_TEST_RECALL");
    struct gsh_buffdesc key;
    struct nv_recall_job *job;
    pthread_t worker;
    if (enabled == NULL || strcmp(enabled, "1") != 0)
        return;
    obj->obj_ops->handle_to_key(obj, &key);
    if (key.len > 128)
        return;
    job = gsh_calloc(1, sizeof(*job));
    job->vec = export->gl_fs->up_ops;
    job->exp = op_ctx->ctx_export;
    get_gsh_export_ref(job->exp);
    job->length = key.len;
    memcpy(job->key, key.addr, key.len);
    if (pthread_create(&worker, NULL, nv_recall_run, job) != 0) {
        put_gsh_export(job->exp);
        gsh_free(job);
    } else
        pthread_detach(worker);
}
'''
changed = original.replace(anchor, anchor + hook)
anchor = "\tres->last_segment       = true;"
assert changed.count(anchor) == 1
changed = changed.replace(anchor, anchor + "\n\tnv_recall_schedule(obj_pub, export);")
if not backup.exists():
    backup.write_text(original)
path.write_text(changed)
print(json.dumps({"instrumented": True, "original_sha256": hashlib.sha256(backup.read_bytes()).hexdigest(),
                  "instrumented_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}, indent=2))
