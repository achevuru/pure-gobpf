package elfparser

/*
#include <stdint.h>

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

*/
import "C"

import (
	"debug/elf"
	"os"
	"io"
	"fmt"
	"encoding/binary"
	"path"

	"github.com/jayanthvn/pure-gobpf/pkg/ebpf"
	"github.com/jayanthvn/pure-gobpf/pkg/logger"
)

//Ref:https://github.com/torvalds/linux/blob/v5.10/samples/bpf/bpf_load.c
var log = logger.Get()

func LoadBpfFile(path string) error {
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
			log.Infof("Failed to create map")
			return fmt.Errorf("Failed to create map")
		}
		loadedMaps.PinMap(mapFD)
	}
	return nil
}

func doLoadELF(r io.ReaderAt) error {
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
			license = NullTerminatedStringToString(data)
			break
		} else if section.Name == "maps" {
			dataMaps = section
			mapsShndx = index
		} 
	}

	log.Infof("License %s", license)
	log.Infof("strtabidx %d", strtabidx)
	
	if (dataMaps != nil) {
		err := loadElfMapsSection(mapsShndx, dataMaps, elfFile)
		if err != nil {
			return nil
		}
	}
	return nil
}

