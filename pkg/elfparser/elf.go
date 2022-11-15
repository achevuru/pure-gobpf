package elfparser

/*
#include <stdint.h>

struct bpf_map_def {
  uint32_t map_type;
  uint32_t key_size;
  uint32_t value_size;
  uint32_t max_entries;
  uint32_t map_flags;
};

#define BPF_MAP_DEF_SIZE sizeof(struct bpf_map_def)

*/
import "C"

import (
	"debug/elf"
	"os"
	"io"
	"fmt"

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

	for offset := 0; offset < len(data); offset += mapDefinitionSize {
		mapData := ebpf.BpfMapData{}
		mapDef := ebpf.BpfMapDef{
			Type:       uint32(elfFile.ByteOrder.Uint32(data[offset : offset+4])),
			KeySize:    elfFile.ByteOrder.Uint32(data[offset+4 : offset+8]),
			ValueSize:  elfFile.ByteOrder.Uint32(data[offset+8 : offset+12]),
			MaxEntries: elfFile.ByteOrder.Uint32(data[offset+12 : offset+16]),
			Flags:      uint32(elfFile.ByteOrder.Uint32(data[offset+16 : offset+20])),
		}
		// Retrieve map name by looking up symbols table:
		// Each symbol contains section index and arbitrary value which for our case
		// is offset in section's data
		for _, sym := range symbols {
			if int(sym.Section) == mapsShndx && int(sym.Value) == offset {
				mapData.Name = sym.Name
				break
			}
		}
		if mapData.Name == "" {
			log.Infof("Unable to get map name")
			return fmt.Errorf("Unable to get map name (section offset=%d)", offset)
		}
		mapData.Def = mapDef
		GlobalMapData = append(GlobalMapData, mapData)
	}

	
	//load maps
	for index := 0; index < len(GlobalMapData); index++ {
		loadedMaps := GlobalMapData[index]
		loadedMaps.CreateMap()
	}
	return nil
}

func doLoadELF(r io.ReaderAt) error {
	elfFile, err := elf.NewFile(r)
	if err != nil {
		return err
	}

	/* scan over all elf sections to get license and map info */
	var dataMaps *elf.Section
	//var symbolTab *elf.Section
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
		} /*else if section.Type == elf.SHT_SYMTAB {
			strtabidx = section.Link
			symbolTab = section
		}*/
	}

	log.Infof("License %s", license)
	log.Infof("strtabidx %d", strtabidx)
	/*
	if (symbolTab == nil) {
		log.Infof("missing SHT_SYMTAB section\n")
		return nil
	}
	*/
	if (dataMaps != nil) {
		err := loadElfMapsSection(mapsShndx, dataMaps, elfFile)
		if err != nil {
			return nil
		}
	}
	return nil
}

