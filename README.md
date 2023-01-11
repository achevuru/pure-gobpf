# pure-gobpf

This is a SDK to load BPF programs implemented in golang. The SDK internally calls the bpf() system calls to load the programs and maps defined in the elf. Initial release will support only attaching TC and XDP but will support all map types.

Contributions welcome!

# Getting started

## How to build elf file?

```
clang -I../../.. -O2 -target bpf -c <C file> -o <ELF file>
```

## How to build SDK?

Run `make buid-linux` - this will build the sdk binary.

## How to use the SDK?

In your application, 

1. Get the latest SDK -

```
GOPROXY=direct go get github.com/jayanthvn/pure-gobpf
```

2. Import the elfparser - 

```
goebpfelfparser "gitlab.aws.dev/varavaj/aws-ebpf-gosdk/pkg/elfparser"
```

3. Load the elf -

```
goebpfelfparser.LoadBpfFile(<ELF file>)
```

This return ELFContext which contains all programs under a section and all maps.

```
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
```

## How to attach XDP?

1. Import the ebpf package - 

```
goebpf "github.com/jayanthvn/pure-gobpf/pkg/ebpf"
```

2. Attach XDP -

Pass the interface name, program FD and program name.

```
elfcontext, err := goebpfelfparser.LoadBpfFile(<ELF file>)

Retrieve the progFD for the intended program from elfcontext -

err = goebpf.XDPAttach(hostVethName, progFD)
```

## How to attach TC?

1. Import the ebpf package - 

```
goebpf "github.com/jayanthvn/pure-gobpf/pkg/ebpf"
```

2. Attach TC - 

```
elfcontext, err := goebpfelfparser.LoadBpfFile(<ELF file>)

Retrieve the progFD for the intended program from elfcontext -

err = goebpf.TCIngressAttach(hostVethName, progFD)
```

## Sample example to fetch program from ELFContext - 

```
var elfContext *goebpfelfparser.ELFContext
elfContext, err = goebpfelfparser.LoadBpfFile(<ELF file>)
if err != nil {
	log.Errorf("LoadElf() failed: %v", err)
}

for pgmName, pgmData := range elfContext.Section["xdp"].Programs {
	log.Infof("xdp -> PgmName %s : ProgFD %d and PinPath %s", pgmName, pgmData.ProgFD, pgmData.PinPath)
}

for pgmName, pgmData := range elfContext.Section["tc_cls"].Programs {
	log.Infof("tc_cls -> PgmName %s : ProgFD %d and PinPath %s", pgmName, pgmData.ProgFD, pgmData.PinPath)
}
```
