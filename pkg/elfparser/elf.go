package elfparser

/*
#include <stdint.h>
#include <linux/unistd.h>
#include <linux/bpf.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct bpf_map_def {
  uint32_t map_type;
  uint32_t key_size;
  uint32_t value_size;
  uint32_t max_entries;
  uint32_t map_flags;
  uint32_t pinning;
  uint32_t inner_map_fd;
};

#define BPF_MAP_DEF_SIZE sizeof(struct bpf_map_def)
#define ptr_to_u64(ptr) ((__u64)(unsigned long)(ptr))


static int bpf_prog_load(enum bpf_prog_type prog_type,
	const struct bpf_insn *insns, int prog_len,
	const char *license, int kern_version)
{
	int ret;
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.prog_type = prog_type;
	attr.insn_cnt = prog_len / sizeof(struct bpf_insn);
	attr.insns = ptr_to_u64((void *) insns);
	attr.license = ptr_to_u64((void *) license);
	attr.log_buf = ptr_to_u64(NULL);
	attr.log_size = 0;
	attr.log_level = 0;
	attr.kern_version = kern_version;
	ret = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	return ret;
}

*/
import "C"

import (
	"debug/elf"
	"os"
	"io"
	"fmt"
	"encoding/binary"
	"path"
	"unsafe"
	"strings"
	"strconv"
	"regexp"
	"syscall"

	"github.com/jayanthvn/pure-gobpf/pkg/ebpf"
	"github.com/jayanthvn/pure-gobpf/pkg/logger"
)

//Ref:https://github.com/torvalds/linux/blob/v5.10/samples/bpf/bpf_load.c
//var log = logger.Get()

func LoadBpfFile(path string) error {
	var log = logger.Get()
	f, err := os.Open(path)
	if err != nil {
		log.Infof("LoadBpfFile failed to open")
		return err
	}
	defer f.Close()

	return doLoadELF(f)
}

func NullTerminatedStringToString(val []byte) string {
	// Calculate null terminated string len
	slen := len(val)
	for idx, ch := range val {
		if ch == 0 {
			slen = idx
			break
		}
	}
	return string(val[:slen])
}

func loadElfMapsSection(mapsShndx int, dataMaps *elf.Section, elfFile *elf.File) error {
	var log = logger.Get()
	//Replace this TODO
	mapDefinitionSize := C.BPF_MAP_DEF_SIZE
	GlobalMapData := []ebpf.BpfMapData{}
	data, err := dataMaps.Data()
	if err != nil {
		log.Infof("Error while loading section")
		return fmt.Errorf("error while loading section': %w", err)
	}

	symbols, err := elfFile.Symbols()
	if err != nil {
		log.Infof("Get symbol failed")
		return fmt.Errorf("get symbols: %w", err)
	}

	log.Infof("Dumping MAP %v and size %d", data, mapDefinitionSize)

	for offset := 0; offset < len(data); offset += mapDefinitionSize {
		log.Infof("Offset %d", offset)
		mapData := ebpf.BpfMapData{}
		mapDef := ebpf.BpfMapDef{
			Type:       uint32(binary.LittleEndian.Uint32(data[offset : offset+4])),
			KeySize:    uint32(binary.LittleEndian.Uint32(data[offset+4 : offset+8])),
			ValueSize:  uint32(binary.LittleEndian.Uint32(data[offset+8 : offset+12])),
			MaxEntries: uint32(binary.LittleEndian.Uint32(data[offset+12 : offset+16])),
			Flags:      uint32(binary.LittleEndian.Uint32(data[offset+16 : offset+20])),
			Pinning:    uint32(binary.LittleEndian.Uint32(data[offset+20 : offset+24])),
		}

		log.Infof("DUMP Type %d KeySize %d ValueSize %d MaxEntries %d Flags %d Pinning %d", uint32(binary.LittleEndian.Uint32(data[offset : offset+4])), 
				uint32(binary.LittleEndian.Uint32(data[offset+4 : offset+8])), uint32(binary.LittleEndian.Uint32(data[offset+8 : offset+12])),
			        uint32(binary.LittleEndian.Uint32(data[offset+12 : offset+16])), uint32(binary.LittleEndian.Uint32(data[offset+16 : offset+20])),
			        uint32(binary.LittleEndian.Uint32(data[offset+20 : offset+24])))

		
		for _, sym := range symbols {
			if int(sym.Section) == mapsShndx && int(sym.Value) == offset {
				var name [16]byte
				mapName := path.Base(sym.Name)
				copy(name[:], mapName)
				mapData.Name = name
				break
			}
		}
		mapNameStr := string(mapData.Name[:])
		if mapNameStr == "" {
			log.Infof("Unable to get map name")
			return fmt.Errorf("Unable to get map name (section offset=%d)", offset)
		} else {
			log.Infof("Found map name %s", mapData.Name)
		}
		mapData.Def = mapDef
		GlobalMapData = append(GlobalMapData, mapData)
	}

	
	log.Infof("Total maps found - %d", len(GlobalMapData))

	for index := 0; index < len(GlobalMapData); index++ {
		log.Infof("Loading maps")
		loadedMaps := GlobalMapData[index]
		mapFD, _ := loadedMaps.CreateMap()
		if (mapFD == -1) {
			//Even if one map fails, we error out
			log.Infof("Failed to create map, continue to next map..just for debugging")
			continue
			//return fmt.Errorf("Failed to create map")
		}
		loadedMaps.PinMap(mapFD)
	}
	return nil
}

var versionRegex = regexp.MustCompile(`^(\d+)\.(\d+).(\d+).*$`)

func utsnameStr(in []int8) string {
	out := make([]byte, len(in))
	for i := 0; i < len(in); i++ {
		if in[i] == 0 {
			break
		}
		out = append(out, byte(in[i]))
	}
	return string(out)
}

func KernelVersionFromReleaseString(releaseString string) (uint32, error) {
	versionParts := versionRegex.FindStringSubmatch(releaseString)
	if len(versionParts) != 4 {
		return 0, fmt.Errorf("got invalid release version %q (expected format '4.3.2-1')", releaseString)
	}
	major, err := strconv.Atoi(versionParts[1])
	if err != nil {
		return 0, err
	}

	minor, err := strconv.Atoi(versionParts[2])
	if err != nil {
		return 0, err
	}

	patch, err := strconv.Atoi(versionParts[3])
	if err != nil {
		return 0, err
	}
	out := major*256*256 + minor*256 + patch
	return uint32(out), nil
}

func currentVersionUname() (uint32, error) {
	var buf syscall.Utsname
	if err := syscall.Uname(&buf); err != nil {
		return 0, err
	}
	releaseString := strings.Trim(utsnameStr(buf.Release[:]), "\x00")
	return KernelVersionFromReleaseString(releaseString)
}

func loadElfProgSection(dataProg *elf.Section, license string, progType string) error {
	var log = logger.Get()
	data, err := dataProg.Data()
	if err != nil {
		log.Infof("Error while loading section")
		return fmt.Errorf("error while loading section': %w", err)
	}

	version, err := KernelVersionFromReleaseString("5.4.209-116") 
	if err != nil {
		log.Infof("Failed to get kernel")
		return fmt.Errorf("Failed to get kernel version")
	}

	var defaultLogSize uint32 = 524288
	logBuf := make([]int, defaultLogSize)
	/*
	Insns: uint64(*(*uint64)(unsafe.Pointer(&data[0]))),
		License: uint64(*(*uint64)(unsafe.Pointer(C.CString(string(license))))),
		LogBuf: uint64(*(*uint64)(unsafe.Pointer(&logBuf[0]))),
	*/ 
	progData := ebpf.BpfProgDef{
		InsnCnt: uint32(C.int(len(data))),
		Insns: uintptr(unsafe.Pointer(&data[0])),
		License: uintptr(unsafe.Pointer(C.CString(string(license)))),
		LogBuf: uintptr(unsafe.Pointer(&logBuf[0])),
		LogLevel: uint32(0),
		LogSize: uint32(C.int(len(logBuf))),
		KernelVersion: uint32(version),
	}
	progFD, _ := progData.LoadProg(progType)
	if (progFD == -1) {
		log.Infof("Failed to load prog")
		return fmt.Errorf("Failed to Load the prog")	
	}
	log.Infof("loaded prog with %d", progFD)

	/*
	version, err := currentVersionUname() 
	if err != nil {
		log.Infof("Failed to get kernel")
		return fmt.Errorf("Failed to get kernel version")
	}

	insns := (*C.struct_bpf_insn)(unsafe.Pointer(&data[0]))

	lp := unsafe.Pointer(C.CString(license))
	defer C.free(lp)

	var prog_t uint32
	if progType == "xdp" {
		prog_t = 6
		progFd, err := C.bpf_prog_load(prog_t,
			insns, C.int(dataProg.Size),
			(*C.char)(lp), C.int(version))
		if progFd < 0 {
			return fmt.Errorf("error while loading %q (%v)%s", dataProg.Name, err)
		}
		log.Infof("loaded prog with %d", progFd)
	}*/
	return nil
}

func doLoadELF(r io.ReaderAt) error {
	var log = logger.Get()
	elfFile, err := elf.NewFile(r)
	if err != nil {
		return err
	}

	var dataMaps *elf.Section
	var mapsShndx int
	var strtabidx uint32
	license := ""
	for index, section := range elfFile.Sections {
		if section.Name == "license" {
			data, err := section.Data()
			if err != nil {
				return fmt.Errorf("Failed to read data for section %s: %v", section.Name, err)
			}
			license = string(data)
			log.Infof("License %s", license)
			//license = NullTerminatedStringToString(data)
			break
		} else if section.Name == "maps" {
			dataMaps = section
			mapsShndx = index
		} 
	}

	log.Infof("strtabidx %d", strtabidx)
	
	if (dataMaps != nil) {
		err := loadElfMapsSection(mapsShndx, dataMaps, elfFile)
		if err != nil {
			return nil
		}
	}

	//Load prog
	for _, section := range elfFile.Sections {
		if section.Type != elf.SHT_PROGBITS {
			continue
		}
		progType := strings.ToLower(strings.Split(section.Name, "/")[0])
		log.Infof("Found the progType %s", progType)
		if progType != "xdp" {
			log.Infof("Not supported program %s", progType)
			continue
		}
		dataProg := section
		err := loadElfProgSection(dataProg, license, progType)
		if err != nil {
			log.Infof("Failed to load the prog")
			return fmt.Errorf("Failed to load prog %q - %v", dataProg.Name, err)
		}
	}
	return nil
}

