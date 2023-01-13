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

#define BPF_INS_DEF_SIZE sizeof(struct bpf_insn)
*/
import "C"

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path"
	"strings"
	"unsafe"

	//"syscall/cgo"

	"github.com/achevuru/pure-gobpf/pkg/ebpf"
	"github.com/jayanthvn/pure-gobpf/pkg/logger"
)

// Length of BPF instruction
const bpfInstructionLen = 8

// Other BPF constants that are not present in "golang.org/x/sys/unix"
const bpfDw = 0x18 // ld/ldx double word

//Ref:https://github.com/torvalds/linux/blob/v5.10/samples/bpf/bpf_load.c
type ELFContext struct {
	// .elf will have multiple sections and maps
	Section map[string]ELFSection // Indexed by section type
	Maps    map[string]ELFMap     // Index by map name
}

type ELFSection struct {
	// Each sections will have a program but a single section type can have multiple programs
	// like tc_cls
	Programs map[string]ELFProgram // Index by program name
}

type ELFProgram struct {
	// return program name, prog FD and pinPath
	ProgFD  int
	PinPath string
}

type ELFMap struct {
	// return map type, map FD and pinPath
	MapType int
	MapFD   int
	PinPath string
}

type bpfInstruction struct {
	code   uint8  // Opcode
	dstReg uint8  // 4 bits: destination register, r0-r10
	srcReg uint8  // 4 bits: source register, r0-r10
	offset uint16 // Signed offset
	imm    uint32 // Immediate constant
}

// Loads BPF instruction from binary slice
func (b *bpfInstruction) load(data []byte) error {
	if len(data) < bpfInstructionLen {
		return errors.New("Invalid BPF bytecode")
	}

	b.code = data[0]
	b.dstReg = data[1] & 0xf
	b.srcReg = data[1] >> 4
	b.offset = binary.LittleEndian.Uint16(data[2:])
	b.imm = binary.LittleEndian.Uint32(data[4:])

	return nil
}

// Converts BPF instruction into bytes
func (b *bpfInstruction) save() []byte {
	res := make([]byte, bpfInstructionLen)
	res[0] = b.code
	res[1] = (b.srcReg << 4) | (b.dstReg & 0x0f)
	binary.LittleEndian.PutUint16(res[2:], b.offset)
	binary.LittleEndian.PutUint32(res[4:], b.imm)

	return res
}

func LoadBpfFile(path string) (*ELFContext, error) {
	var log = logger.Get()
	f, err := os.Open(path)
	if err != nil {
		log.Infof("LoadBpfFile failed to open")
		return nil, err
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

func (c *ELFContext) loadElfMapsSection(mapsShndx int, dataMaps *elf.Section, elfFile *elf.File) error {
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

		log.Infof("DUMP Type %d KeySize %d ValueSize %d MaxEntries %d Flags %d Pinning %d", uint32(binary.LittleEndian.Uint32(data[offset:offset+4])),
			uint32(binary.LittleEndian.Uint32(data[offset+4:offset+8])), uint32(binary.LittleEndian.Uint32(data[offset+8:offset+12])),
			uint32(binary.LittleEndian.Uint32(data[offset+12:offset+16])), uint32(binary.LittleEndian.Uint32(data[offset+16:offset+20])),
			uint32(binary.LittleEndian.Uint32(data[offset+20:offset+24])))

		for _, sym := range symbols {
			if int(sym.Section) == mapsShndx && int(sym.Value) == offset {
				mapName := path.Base(sym.Name)
				cstr := C.CString(mapName)
				b := C.GoBytes(unsafe.Pointer(cstr), C.int(unsafe.Sizeof(mapName)))
				str := string(b)
				mapData.Name = str
				C.free(unsafe.Pointer(cstr))
				break
			}
		}
		log.Infof("Found map name %s", mapData.Name)
		mapData.Def = mapDef
		GlobalMapData = append(GlobalMapData, mapData)
	}

	log.Infof("Total maps found - %d", len(GlobalMapData))

	for index := 0; index < len(GlobalMapData); index++ {
		log.Infof("Loading maps")
		loadedMaps := GlobalMapData[index]
		mapFD, _ := loadedMaps.CreateMap()
		if mapFD == -1 {
			//Even if one map fails, we error out
			log.Infof("Failed to create map, continue to next map..just for debugging")
			continue
		}

		mapNameStr := loadedMaps.Name
		pinPath := "/sys/fs/bpf/globals/" + mapNameStr
		loadedMaps.PinMap(mapFD, pinPath)
		c.Maps[mapNameStr] = ELFMap{
			MapType: int(loadedMaps.Def.Type),
			MapFD:   mapFD,
			PinPath: pinPath,
		}
	}
	return nil
}

type relocationEntry struct {
	offset int
	symbol elf.Symbol
}

func parseRelocationSection(reloSection *elf.Section, elfFile *elf.File) ([]relocationEntry, error) {
	var log = logger.Get()
	symbols, err := elfFile.Symbols()
	if err != nil {
		return nil, fmt.Errorf("unable to load symbols(): %v", err)
	}
	// Read section data
	data, err := reloSection.Data()
	if err != nil {
		return nil, fmt.Errorf("unable to read data from section '%s': %v", reloSection.Name, err)
	}

	// Parse all entries
	var result []relocationEntry
	reader := bytes.NewReader(data)

	for {
		var err error
		var offset, symbolIndex int

		switch elfFile.Class {
		case elf.ELFCLASS64:
			var rel elf.Rel64
			err = binary.Read(reader, elfFile.ByteOrder, &rel)
			symbolIndex = int(elf.R_SYM64(rel.Info)) - 1
			offset = int(rel.Off)
		case elf.ELFCLASS32:
			var rel elf.Rel32
			err = binary.Read(reader, elfFile.ByteOrder, &rel)
			symbolIndex = int(elf.R_SYM32(rel.Info)) - 1
			offset = int(rel.Off)
		default:
			return nil, fmt.Errorf("Unsupported arch %v", elfFile.Class)
		}
		// Ignore EOF error
		if err == io.EOF {
			// No more relocations
			return result, nil
		}

		if err != nil {
			return nil, err
		}
		// Ensure that symbol exists
		if symbolIndex >= len(symbols) {
			return nil, fmt.Errorf("Invalid Relocation section entry'%v': symbol index %v does not exist",
				reloSection, symbolIndex)
		}
		log.Infof("Relocation section entry: %s @ %v", symbols[symbolIndex].Name, offset)
		result = append(result, relocationEntry{
			offset: offset,
			symbol: symbols[symbolIndex],
		})
	}
}

func (c *ELFContext) applyRelocations(dataProg *elf.Section, relocationEntries []relocationEntry) error {
	var log = logger.Get()
	data, err := dataProg.Data()
	if err != nil {
		return err
	}

	log.Infof("Applying Relocations..")

	for _, relocationEntry := range relocationEntries {
		if relocationEntry.offset >= len(data) {
			return fmt.Errorf("Invalid offset spotted in relocation section %d", relocationEntry.offset)
		}

		// Load BPF instruction that needs to be modified ("relocated")
		instruction := &bpfInstruction{}
		err = instruction.load(data[relocationEntry.offset:])
		if err != nil {
			return err
		}
		log.Infof("BPF Instruction code: %s", instruction.code)
		// Ensure that instruction is valid
		if instruction.code != (unix.BPF_LD | unix.BPF_IMM | bpfDw) {
			return fmt.Errorf("Invalid BPF instruction (at %d): %v",
				relocationEntry.offset, instruction)
		}
		// Patch instruction to use proper map fd
		mapName := relocationEntry.symbol.Name
		if progMap, ok := c.Maps[mapName]; ok {
			instruction.srcReg = 1
			instruction.imm = uint32(progMap.MapFD)
			log.Infof("Map to be relocated; Name: %s, FD: %v", mapName, progMap.MapFD)
			copy(data[relocationEntry.offset:], instruction.save())
		} else {
			return fmt.Errorf("map '%s' doesn't exist", mapName)
		}
	}
	return nil
}

func (c *ELFContext) loadElfProgSection(dataProg *elf.Section, reloSection *elf.Section, license string, progType string, sectionIndex int, elfFile *elf.File) error {
	var log = logger.Get()

	insDefSize := uint64(C.BPF_INS_DEF_SIZE)
	data, err := dataProg.Data()
	if err != nil {
		return err
	}

	log.Infof("Loading Program with relocation section; Info:%v; Name: %s, Type: %s; Size: %v", reloSection.Info,
		reloSection.Name, reloSection.Type, reloSection.Size)

	//Single section might have multiple programs. So we retrieve one prog at a time and load.
	symbolTable, err := elfFile.Symbols()
	if err != nil {
		log.Infof("Get symbol failed")
		return fmt.Errorf("get symbols: %w", err)
	}

	relocations, err := parseRelocationSection(reloSection, elfFile)
	if err != nil || len(relocations) == 0 {
		return fmt.Errorf("Unable to parse relocation entries....")
	}

	err = c.applyRelocations(dataProg, relocations)

	var pgmList = make(map[string]ELFProgram)
	// Iterate over the symbols in the symbol table
	for _, symbol := range symbolTable {
		// Check if the symbol is a function
		if elf.ST_TYPE(symbol.Info) == elf.STT_FUNC {
			// Check if sectionIndex matches
			if int(symbol.Section) == sectionIndex && elf.ST_BIND(symbol.Info) == elf.STB_GLOBAL {
				// Check if the symbol's value (offset) is within the range of the section data

				progSize := symbol.Size
				secOff := symbol.Value
				ProgName := symbol.Name

				if secOff+progSize > dataProg.Size {
					log.Infof("Section out of bound secOff %d - progSize %d for name %s and data size %d", progSize, secOff, ProgName, dataProg.Size)
					return fmt.Errorf("Failed to Load the prog")
				}

				log.Infof("Sec '%s': found program '%s' at insn offset %d (%d bytes), code size %d insns (%d bytes)\n", progType, ProgName, secOff/insDefSize, secOff, progSize/insDefSize, progSize)
				if symbol.Value >= dataProg.Addr && symbol.Value < dataProg.Addr+dataProg.Size {
					// Extract the BPF program data from the section data
					log.Infof("Data offset - %d", symbol.Value-dataProg.Addr)
					log.Infof("Data len - %d", len(data))

					dataStart := (symbol.Value - dataProg.Addr)
					dataEnd := dataStart + progSize
					programData := make([]byte, progSize)
					copy(programData, data[dataStart:dataEnd])

					log.Infof("Program Data size - %d", len(programData))

					pinPath := "/sys/fs/bpf/globals/" + ProgName
					progFD, _ := ebpf.LoadProg(progType, programData, license, pinPath)
					if progFD == -1 {
						log.Infof("Failed to load prog")
						return fmt.Errorf("Failed to Load the prog")
					}
					log.Infof("loaded prog with %d", progFD)
					pgmList[ProgName] = ELFProgram{
						ProgFD:  progFD,
						PinPath: pinPath,
					}
				} else {
					log.Infof("Invalid ELF file\n")
					return fmt.Errorf("Failed to Load the prog")
				}
			}
		}
	}
	c.Section[progType] = ELFSection{
		Programs: pgmList,
	}

	return nil
}

func doLoadELF(r io.ReaderAt) (*ELFContext, error) {
	var log = logger.Get()
	var err error
	elfFile, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}

	c := &ELFContext{}
	c.Section = make(map[string]ELFSection)
	c.Maps = make(map[string]ELFMap)
	reloSectionMap := make(map[uint32]*elf.Section)

	var dataMaps *elf.Section
	var mapsShndx int
	var strtabidx uint32
	license := ""
	for index, section := range elfFile.Sections {
		if section.Name == "license" {
			data, _ := section.Data()
			if err != nil {
				return nil, fmt.Errorf("Failed to read data for section %s", section.Name)
			}
			license = string(data)
			log.Infof("License %s", license)
			break
		} else if section.Name == "maps" {
			dataMaps = section
			mapsShndx = index
		}
	}

	log.Infof("strtabidx %d", strtabidx)

	if dataMaps != nil {
		err := c.loadElfMapsSection(mapsShndx, dataMaps, elfFile)
		if err != nil {
			return nil, nil
		}
	}

	//Gather relocation section info
	for _, reloSection := range elfFile.Sections {
		if reloSection.Type == elf.SHT_REL {
			log.Infof("Found a relocation section; Info:%v; Name: %s, Type: %s; Size: %v", reloSection.Info,
				reloSection.Name, reloSection.Type, reloSection.Size)
			reloSectionMap[reloSection.Info] = reloSection
		}
	}

	//Load prog
	for sectionIndex, section := range elfFile.Sections {
		if section.Type != elf.SHT_PROGBITS {
			continue
		}

		log.Infof("Found PROG Section at Index %v", sectionIndex)
		progType := strings.ToLower(strings.Split(section.Name, "/")[0])
		log.Infof("Found the progType %s", progType)
		if progType != "xdp" && progType != "tc_cls" && progType != "tc_act" {
			log.Infof("Not supported program %s", progType)
			continue
		}
		dataProg := section
		err = c.loadElfProgSection(dataProg, reloSectionMap[uint32(sectionIndex)], license, progType, sectionIndex, elfFile)
		if err != nil {
			log.Infof("Failed to load the prog")
			return nil, fmt.Errorf("Failed to load prog %q - %v", dataProg.Name, err)
		}
	}

	return c, nil
}
