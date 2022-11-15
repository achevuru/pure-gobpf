package ebpf

import "C"

import (
	"fmt"
	"unsafe"
	"path"

	"golang.org/x/sys/unix"
	"github.com/jayanthvn/pure-gobpf/pkg/logger"
)

/*
struct bpf_map_def {
  __u32 map_type;
  __u32 key_size;
  __u32 value_size;
  __u32 max_entries;
  __u32 map_flags;
};
*/

var log = logger.Get()

const (
	// BPF map type constants. Must match enum bpf_map_type from linux/bpf.h
	BPF_MAP_TYPE_UNSPEC           = 0
	BPF_MAP_TYPE_HASH             = 1
	BPF_MAP_TYPE_ARRAY            = 2
	BPF_MAP_TYPE_PROG_ARRAY       = 3
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4
	BPF_MAP_TYPE_PERCPU_HASH      = 5
	BPF_MAP_TYPE_PERCPU_ARRAY     = 6
	BPF_MAP_TYPE_STACK_TRACE      = 7
	BPF_MAP_TYPE_CGROUP_ARRAY     = 8
	BPF_MAP_TYPE_LRU_HASH         = 9
	BPF_MAP_TYPE_LRU_PERCPU_HASH  = 10
	BPF_MAP_TYPE_LPM_TRIE         = 11
	BPF_MAP_TYPE_ARRAY_OF_MAPS    = 12
	BPF_MAP_TYPE_HASH_OF_MAPS     = 13
	BPF_MAP_TYPE_DEVMAP           = 14

	// BPF syscall command constants. Must match enum bpf_cmd from linux/bpf.h
	BPF_MAP_CREATE         = 0
	BPF_MAP_LOOKUP_ELEM    = 1
	BPF_MAP_UPDATE_ELEM    = 2
	BPF_MAP_DELETE_ELEM    = 3
	BPF_MAP_GET_NEXT_KEY   = 4
	BPF_PROG_LOAD          = 5
	BPF_OBJ_PIN            = 6
	BPF_OBJ_GET            = 7
	BPF_PROG_ATTACH        = 8
	BPF_PROG_DETACH        = 9
	BPF_PROG_TEST_RUN      = 10
	BPF_PROG_GET_NEXT_ID   = 11
	BPF_MAP_GET_NEXT_ID    = 12
	BPF_PROG_GET_FD_BY_ID  = 13
	BPF_MAP_GET_FD_BY_ID   = 14
	BPF_OBJ_GET_INFO_BY_FD = 15

	// Flags for BPF_MAP_UPDATE_ELEM. Must match values from linux/bpf.h
	BPF_ANY     = 0
	BPF_NOEXIST = 1
	BPF_EXIST   = 2

	BPF_F_NO_PREALLOC   = 1 << 0
	BPF_F_NO_COMMON_LRU = 1 << 1
)

//Ref: https://elixir.bootlin.com/linux/v5.10.153/source/samples/bpf/bpf_load.h#L20
type BpfMapDef struct {
	Type uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
}

type BpfMapData struct {
	Def BpfMapDef
	numaNode uint32
	Name string 
}

type ubaCommon struct {
	mapType    uint32
	keySize    uint32
	valueSize  uint32
	maxEntries uint32
	mapFlags   uint32
	innerID    uint32
}

// This struct must be in sync with union bpf_attr's anonymous struct
// used by the BPF_MAP_CREATE command
type ubaMapName struct {
	ubaCommon
	numaNode uint32
	mapName  [16]byte
}

func (m *BpfMapData) CreateMap() (int, error) {
	// This struct must be in sync with union bpf_attr's anonymous struct
	// used by the BPF_MAP_CREATE command
	mapName := path.Base(m.Name)
	var name [16]byte
	copy(name[:], mapName)
	/*
	mapSysData := struct {
		mapType    uint32
		keySize    uint32
		valueSize  uint32
		maxEntries uint32
		mapFlags   uint32
		mapName  [16]byte
	}{
		uint32(m.Def.Type),
		uint32(m.Def.KeySize),
		uint32(m.Def.ValueSize),
		uint32(m.Def.MaxEntries),
		uint32(m.Def.Flags),
		name,
	}*/

			u := ubaMapName{
			ubaCommon: ubaCommon{
				mapType:    uint32(m.Def.Type),
				keySize:    m.Def.KeySize,
				valueSize:  m.Def.ValueSize,
				maxEntries: m.Def.MaxEntries,
				mapFlags:   m.Def.Flags,
			},
			mapName: name,
		}
		uba := unsafe.Pointer(&u)
		ubaSize := unsafe.Sizeof(u)

	log.Infof("Calling BPFsys for name %s and flags %d", m.Name, m.Def.Flags)

	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_CREATE,
		uintptr(uba),
		ubaSize,
	)

	if ret != 0 {
		log.Infof("Created map and ret %d and err %s", int(ret), err)
		return int(ret), nil
	}
	log.Infof("Unable to create map %s", err)
	return 0, fmt.Errorf("Unable to create map: %s", err)
}
