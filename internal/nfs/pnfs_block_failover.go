package nfs

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"strconv"

	"nfs-viewer/internal/iscsi"
)

func validateBlockReadAlternates(o PNFSOptions, out *PNFSOptions) error {
	if o.ReadFailover && len(o.BlockTargets) == 0 || len(o.BlockReadAlternates) != 0 && !o.ReadFailover {
		return errors.New("block alternate portals require --read-failover and approved iSCSI targets")
	}
	out.BlockReadAlternates = map[string][]string{}
	for primary, alternates := range o.BlockReadAlternates {
		if !slices.Contains(o.BlockTargets, primary) || len(alternates) == 0 || len(alternates) > 8 {
			return errors.New("block alternate mapping requires an approved primary and 1..8 portals")
		}
		p, err := iscsi.ParseTarget(primary)
		if err != nil {
			return err
		}
		seen := map[iscsi.Target]bool{}
		for _, raw := range alternates {
			a, err := iscsi.ParseTarget(raw)
			if err != nil || a.Name != p.Name || a.LUN != p.LUN || seen[a] {
				return errors.New("block alternate changes target/LUN or duplicates a portal")
			}
			seen[a] = true
		}
		canonical := "iscsi://" + p.Endpoint + "/" + p.Name + "/" + strconv.Itoa(int(p.LUN))
		out.BlockReadAlternates[canonical] = slices.Clone(alternates)
	}
	return nil
}

func (files blockFiles) enableReadRecovery(o PNFSOptions, devices map[string][]*blockVolume, guard func() error) error {
	for _, file := range files {
		remote, ok := file.file.(*iscsi.Volume)
		if !ok {
			continue
		}
		var alternates []iscsi.Target
		for _, raw := range o.BlockReadAlternates[file.path] {
			target, err := iscsi.ParseTarget(raw)
			if err != nil {
				return err
			}
			alternates = append(alternates, target)
		}
		var signatures []blockSignature
		for _, volumes := range devices {
			for _, volume := range volumes {
				if volume.kind == 0 && volume.file == file.file {
					for _, signature := range volume.signatures {
						signatures = append(signatures, blockSignature{signature.offset, bytes.Clone(signature.data)})
					}
				}
			}
		}
		if len(signatures) == 0 {
			continue
		} // Unused approvals do not receive a recovery policy.
		validate := func(fresh io.ReaderAt) error {
			for _, signature := range signatures {
				if err := guard(); err != nil {
					return err
				}
				offset := signature.offset
				if offset < 0 {
					offset += file.info.Size()
				}
				data := make([]byte, len(signature.data))
				if _, err := fresh.ReadAt(data, offset); err != nil {
					return err
				}
				if !bytes.Equal(data, signature.data) {
					return errors.New("reconnected block volume signature changed")
				}
			}
			return guard()
		}
		if err := remote.EnableReadRecovery(alternates, guard, validate); err != nil {
			return err
		}
	}
	return nil
}
