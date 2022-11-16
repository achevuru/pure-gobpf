package ebpf

/*
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include "bpf.h"
#include "bpf_helpers.h"
// Mac has syscall() deprecated and this produces some noise during package install.
// Wrap all syscalls into macro.
#ifdef __linux__
#define SYSCALL_BPF(command)		\
	syscall(__NR_bpf, command, &attr, sizeof(attr));
#else
#define SYSCALL_BPF(command)		0
#endif
// Since eBPF mock package is optional and have definition of "__maps_head" symbol
// it may cause link error, so defining weak symbol here as well
struct __create_map_def maps_head;
__attribute__((weak)) struct __maps_head_def *__maps_head = (struct __maps_head_def*) &maps_head;
static int ebpf_map_create(const char *name, __u32 map_type, __u32 key_size, __u32 value_size,
		__u32 max_entries, __u32 flags, __u32 inner_fd, void *log_buf, size_t log_size)
{
	union bpf_attr attr = {};
	attr.map_type = map_type;
	attr.key_size = key_size;
	attr.value_size = value_size;
	attr.max_entries = max_entries;
	attr.map_flags = flags;
	attr.inner_map_fd = inner_fd;
	strncpy((char*)&attr.map_name, name, BPF_OBJ_NAME_LEN - 1);
	int res = SYSCALL_BPF(BPF_MAP_CREATE);
	strncpy(log_buf, strerror(errno), log_size);
	return res;
}

*/
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
//Ref: https://elixir.bootlin.com/linux/v5.10.153/source/samples/bpf/bpf_load.h#L20
type BpfMapDef struct {
	Type uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
	Id         uint32
	Pinning    uint32
}

type BpfMapData struct {
	Def BpfMapDef
	numaNode uint32
	Name string 
}

func (m *BpfMapData) CreateMap() (int, error) {
	// This struct must be in sync with union bpf_attr's anonymous struct
	// used by the BPF_MAP_CREATE command
	mapName := path.Base(m.Name)
	var name [16]byte
	copy(name[:], mapName)
	mapSysData := struct {
		mapType    uint32
		keySize    uint32
		valueSize  uint32
		maxEntries uint32
		mapFlags   uint32
		Pinning    uint32
		mapName  [16]byte
	}{
		uint32(m.Def.Type),
		uint32(m.Def.KeySize),
		uint32(m.Def.ValueSize),
		uint32(m.Def.MaxEntries),
		uint32(m.Def.Flags),
		uint32(m.Def.Pinning),
		name,
	}

	log.Infof("Calling BPFsys for name %s mapType %d keysize %d valuesize %d max entries %d and flags %d", m.Name, m.Def.Type, m.Def.KeySize, m.Def.ValueSize, m.Def.MaxEntries, m.Def.Flags)

	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_CREATE,
		uintptr(unsafe.Pointer(&mapSysData)),
		unsafe.Sizeof(mapSysData),
	)
	
	var logBuf [100]byte
	nameStr := C.CString(m.Name)
	//Trying dropbox way
	newFd := int(C.ebpf_map_create(
		nameStr,
		C.__u32(m.Def.Type),
		C.__u32(m.Def.KeySize),
		C.__u32(m.Def.ValueSize),
		C.__u32(m.Def.MaxEntries),
		C.__u32(m.Def.Flags),
		C.__u32(0),
		unsafe.Pointer(&logBuf[0]),
		C.size_t(unsafe.Sizeof(logBuf)),
	))
	log.Infof("Drop box way of creation %d", newFd)

	if ret != 0 {
		log.Infof("Created map and ret %d and err %s", int(ret), err)
		return int(ret), nil
	}


	log.Infof("Unable to create map %s", err)
	return 0, fmt.Errorf("Unable to create map: %s", err)
}
