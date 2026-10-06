package session

import "testing"

func TestRootCandidatesHaveCompleteXFSFileIDs(t *testing.T) {
	// Linux fs/xfs/xfs_export.c:xfs_fileid_length requires two words for
	// FILEID_INO32_GEN and four for FILEID_INO32_GEN_PARENT. A three-word
	// parent form is accepted by generic exportfs but always rejected by XFS,
	// before the server can even validate the candidate inode/generation.
	fh := []byte{1, 0, 1, 0, 4, 5, 6, 7}
	candidates := RootCandidates(fh)
	if len(candidates) < 2 {
		t.Fatal("missing inode root candidates")
	}
	for _, candidate := range candidates[:2] {
		fileID := candidate[8:]
		switch candidate[3] {
		case 1:
			if len(fileID) != 8 {
				t.Fatalf("incomplete parentless file ID: %d", len(fileID))
			}
		case 2:
			if len(fileID) != 16 {
				t.Fatalf("incomplete XFS parent file ID: %d", len(fileID))
			}
		default:
			t.Fatalf("unsupported XFS inode file ID type: %d", candidate[3])
		}
	}
}
