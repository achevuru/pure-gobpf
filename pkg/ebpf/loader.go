package ebpf
/*
#include <linux/unistd.h>
#include <linux/bpf.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ptr_to_u64(ptr) ((__u64)(unsigned long)(ptr))

int bpf_pin_object(int fd, const char *pathname)
{
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.pathname = ptr_to_u64((void *)pathname);
	attr.bpf_fd = fd;
	return syscall(__NR_bpf, BPF_OBJ_PIN, &attr, sizeof(attr));
}
*/
import "C"

import (
	"fmt"
	"unsafe"
	"os"
	"path/filepath"
	//"strings"

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

//var log = logger.Get()

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

	// BPF MAP pinning
	PIN_NONE      = 0
	PIN_OBJECT_NS = 1
	PIN_GLOBAL_NS = 2
	PIN_CUSTOM_NS = 3

	BPF_DIR_MNT     = "/sys/fs/bpf/"
	BPF_DIR_GLOBALS	= "globals"

	BPF_PROG_TYPE_UNSPEC 		= 0       /* Reserve 0 as invalidprogram type */
	BPF_PROG_TYPE_SOCKET_FILTER 	= 1
	BPF_PROG_TYPE_KPROBE 		= 2
	BPF_PROG_TYPE_SCHED_CLS 	= 3
	BPF_PROG_TYPE_SCHED_ACT		= 4
	BPF_PROG_TYPE_TRACEPOINT	= 5
	BPF_PROG_TYPE_XDP 		= 6
	BPF_PROG_TYPE_PERF_EVENT 	= 7
	BPF_PROG_TYPE_CGROUP_SKB 	= 8
	BPF_PROG_TYPE_CGROUP_SOCK 	= 9
	BPF_PROG_TYPE_LWT_IN 		= 10
	BPF_PROG_TYPE_LWT_OUT 		= 11
	BPF_PROG_TYPE_LWT_XMIT 		= 12
	BPF_PROG_TYPE_SOCK_OPS 		= 13
	BPF_PROG_TYPE_SK_SKB 		= 14
	BPF_PROG_TYPE_CGROUP_DEVICE 	= 15
	BPF_PROG_TYPE_SK_MSG 		= 16
	BPF_PROG_TYPE_RAW_TRACEPOINT 	= 17
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR 	= 18
	BPF_PROG_TYPE_LWT_SEG6LOCAL 	= 19
	BPF_PROG_TYPE_LIRC_MODE2 	= 20
	BPF_PROG_TYPE_SK_REUSEPORT 	= 21
	BPF_PROG_TYPE_FLOW_DISSECTOR 	= 22
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
Union bpf_attr {
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
	Pinning    uint32
}

type BpfMapData struct {
	Def BpfMapDef
	numaNode uint32
	Name [16]byte 
}

type BpfMapPin struct {
	Pathname  uintptr
	Fd     uint32
	FileFlags uint32
}

/*
	struct { anonymous struct used by BPF_PROG_LOAD command
		__u32		prog_type;	one of enum bpf_prog_type 
		__u32		insn_cnt;
		__aligned_u64	insns;
		__aligned_u64	license;
		__u32		log_level;	verbosity level of verifier 
		__u32		log_size;	size of user buffer 
		__aligned_u64	log_buf;	user supplied buffer 
		__u32		kern_version;	not used 
		__u32		prog_flags;
		char		prog_name[BPF_OBJ_NAME_LEN];
		__u32		prog_ifindex;	ifindex of netdev to prep for 
		For some prog types expected attach type must be known at
		  load time to verify attach type specific parts of prog
		  (context accesses, allowed helpers, etc).
		 
		__u32		expected_attach_type;
		__u32		prog_btf_fd;	 fd pointing to BTF type data 
		__u32		func_info_rec_size;	userspace bpf_func_info size 
		__aligned_u64	func_info;	func info 
		__u32		func_info_cnt;	number of bpf_func_info records
		__u32		line_info_rec_size;	userspace bpf_line_info size
		__aligned_u64	line_info;	line info 
		__u32		line_info_cnt;	number of bpf_line_info records 
	};
*/

type BpfProgDef struct {
	Type uint32
	InsnCnt uint32
	Insns uintptr
	License uintptr
}

func (m *BpfMapData) CreateMap() (int, error) {
	var log = logger.Get()
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

	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_CREATE,
		uintptr(mapData),
		mapDataSize,
	)
        
	if errno < 0 {
		log.Infof("Unable to create map and ret %d and err %s", int(ret), errno)
		return int(ret), fmt.Errorf("Unable to create map: %s", errno)
	}


	log.Infof("Create map done with fd : %d", int(ret))
	return int(ret), nil
}

func (m *BpfMapData) PinMap(mapFD int) (error) {
	var log = logger.Get()
	if m.Def.Pinning == PIN_NONE {
		return nil
	}

	if m.Def.Pinning == PIN_GLOBAL_NS {
		//pinPath := BPF_DIR_MNT+"tc/"+BPF_DIR_GLOBALS+"/test"
		//fd := mapFD
		pinPath := "/sys/fs/bpf/tc/globals/my-name"

		err := os.MkdirAll(filepath.Dir(pinPath), 0755)
		if err != nil {
			log.Infof("error creating directory %q: %v", filepath.Dir(pinPath), err)
			return fmt.Errorf("error creating directory %q: %v", filepath.Dir(pinPath), err)
		}
		_, err = os.Stat(pinPath)
		if err == nil {
			log.Infof("aborting, found file at %q", pinPath)
			return fmt.Errorf("aborting, found file at %q", pinPath)
		}
		if err != nil && !os.IsNotExist(err) {
			log.Infof("failed to stat %q: %v", pinPath, err)
			return fmt.Errorf("failed to stat %q: %v", pinPath, err)
		}
		/*
		pinPathC := C.CString(pinPath)
		defer C.free(unsafe.Pointer(pinPathC))

		p, err := unix.BytePtrFromString(pinPath)
		if err != nil {
			return fmt.Errorf("failed to create byte ptr to string: %v", err)
		}
	
		pathPointer := Pointer{ptr: unsafe.Pointer(p)}
                */

		cPath :=  []byte(pinPath + "\x00")

		//log.Infof("byte ptr %d string %d pathPointersize %d mapfd %d", unsafe.Sizeof(p), unsafe.Sizeof(pinPath), unsafe.Sizeof(pathPointer), unsafe.Sizeof(mapFD))
		pinAttr := BpfMapPin{
			Fd:    uint32(mapFD),
			Pathname: uintptr(unsafe.Pointer(&cPath[0])),
		}
		pinData := unsafe.Pointer(&pinAttr)
		pinDataSize := unsafe.Sizeof(pinAttr)

		log.Infof("Calling BPFsys for FD %d and Path %s",mapFD, pinPath)

		ret, _, errno := unix.Syscall(
			unix.SYS_BPF,
			uintptr(BPF_OBJ_PIN),
			uintptr(pinData),
			uintptr(int(pinDataSize)),
		)
		if errno < 0 {
			log.Infof("Unable to pin map and ret %d and err %s", int(ret), errno)
			return fmt.Errorf("Unable to pin map: %s", errno)
		}
		log.Infof("Pin done with fd : %d and errno %d", ret, errno)
		return nil

		/*
		err := os.MkdirAll(path.Dir(pathname), 0644)
		if err != nil {
			log.Infof("Error while making the directory")
			return fmt.Errorf("error while making directories: %w, make sure bpffs is mounted at '%s'", err, BPF_DIR_MNT)
		}*/

		/*
		cPath := []byte(pathname + "\x00")
		pinAttr := BpfMapPin{
			Fd:    uint32(mapFD),
			Pathname: uintptr(unsafe.Pointer(&cPath[0])),
		}
		pinData := unsafe.Pointer(&pinAttr)
		pinDataSize := unsafe.Sizeof(pinData)

		log.Infof("Calling BPFsys for FD %d and Path %s",mapFD, pathname)

		ret, _, errno := unix.Syscall(
			unix.SYS_BPF,
			BPF_OBJ_PIN,
			uintptr(pinData),
			pinDataSize,
		)
		if errno < 0 {
			log.Infof("Unable to pin map and ret %d and err %s", int(ret), errno)
			return fmt.Errorf("Unable to pin map: %s", errno)
		}
		log.Infof("Pin done with fd : %d and errno %d", ret, errno)
		return nil
		*/

		/*
		fd := mapFD
		pinPath := "/sys/fs/bpf/tc/globals/my-name"
		err := os.MkdirAll(filepath.Dir(pinPath), 0755)
		if err != nil {
			log.Infof("error creating directory %q: %v", filepath.Dir(pinPath), err)
			return fmt.Errorf("error creating directory %q: %v", filepath.Dir(pinPath), err)
		}
		_, err = os.Stat(pinPath)
		if err == nil {
			log.Infof("aborting, found file at %q", pinPath)
			return fmt.Errorf("aborting, found file at %q", pinPath)
		}
		if err != nil && !os.IsNotExist(err) {
			log.Infof("failed to stat %q: %v", pinPath, err)
			return fmt.Errorf("failed to stat %q: %v", pinPath, err)
		}
		pinPathC := C.CString(pinPath)
		defer C.free(unsafe.Pointer(pinPathC))
		ret, err := C.bpf_pin_object(C.int(fd), pinPathC)
		if ret != 0 {
			log.Infof("error pinning object to %q: %v", pinPath, err)
			return fmt.Errorf("error pinning object to %q: %v", pinPath, err)
		}
		*/
	}
	return nil

}

func (m *BpfProgDef) LoadProg(progType string) (int, error) {
	var log = logger.Get()
	
	var prog_type uint32
	switch(progType) {
	case "xdp":
		prog_type = BPF_PROG_TYPE_XDP
	default:
		prog_type = BPF_PROG_TYPE_UNSPEC	 
	}
	
	loadProg := BpfProgDef{
		Type: uint32(prog_type),
		InsnCnt: m.InsnCnt,
		Insns: m.Insns,
		License: m.License,
	}
	
	progData := unsafe.Pointer(&loadProg)
	progDataSize := unsafe.Sizeof(loadProg)

	log.Infof("Calling BPFsys for prog load ")
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		uintptr(BPF_PROG_LOAD),
		uintptr(progData),
		uintptr(int(progDataSize)),
	)
	if errno < 0 {
		log.Infof("Unable to load prog and ret %d and err %s", int(ret), errno)
		return int(ret), fmt.Errorf("Unable to load prog: %s", errno)
	}


	log.Infof("Load prog done with fd : %d", int(ret))
	return int(ret), nil
}
