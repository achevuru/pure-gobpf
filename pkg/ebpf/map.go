package ebpf

import "C"

import (
	"fmt"
	"unsafe"

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

/*
struct bpf_elf_map {
        __u32 map_type;
        __u32 key_size;
        __u32 value_size;
        __u32 max_entries;
        __u32 map_flags;
        __u32 id;
        __u32 pinning;
};
*/

/*
nion bpf_attr {
        struct {
                __u32 map_type;
                __u32 key_size;
                __u32 value_size;
                __u32 max_entries;
                __u32 map_flags;
                __u32 inner_map_fd;
                __u32 numa_node;
                char map_name[16];
                __u32 map_ifindex;
                __u32 btf_fd;
                __u32 btf_key_type_id;
                __u32 btf_value_type_id;
        };
*/
//Ref: https://elixir.bootlin.com/linux/v5.10.153/source/samples/bpf/bpf_load.h#L20
type BpfMapDef struct {
	Type uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
	InnerMapFd uint32
}

type BpfMapData struct {
	Def BpfMapDef
	numaNode uint32
	Name [16]byte 
}

func (m *BpfMapData) CreateMap() (int, error) {
	// This struct must be in sync with union bpf_attr's anonymous struct
	// used by the BPF_MAP_CREATE command

	mapCont := BpfMapData{
		Def: BpfMapDef{
			Type:    uint32(m.Def.Type),
			KeySize:    m.Def.KeySize,
			ValueSize:  m.Def.ValueSize,
			MaxEntries: m.Def.MaxEntries,
			Flags:   m.Def.Flags,
			InnerMapFd:    0,
		},
		Name: m.Name,
	}
	mapData := unsafe.Pointer(&mapCont)
	mapDataSize := unsafe.Sizeof(mapCont)

	log.Infof("Calling BPFsys for name %s mapType %d keysize %d valuesize %d max entries %d and flags %d",string(m.Name[:]), m.Def.Type, m.Def.KeySize, m.Def.ValueSize, m.Def.MaxEntries, m.Def.Flags)

	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_CREATE,
		uintptr(mapData),
		mapDataSize,
	)
        
	if ret != 0 {
		log.Infof("Unable to create map and ret %d and err %s", int(ret), err)
		return int(ret), fmt.Errorf("Unable to create map: %s", err)
	}


	log.Infof("Create map done")
	return 0, nil
}
