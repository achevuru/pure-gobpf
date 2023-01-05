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

This return the program FD.

## How to attach XDP?

1. Import the ebpf package - 

```
goebpf "github.com/jayanthvn/pure-gobpf/pkg/ebpf"
```

2. Attach XDP -

Pass the interface name, program FD and program name.

```
progFD, err := goebpfelfparser.LoadBpfFile(<ELF file>)
err = goebpf.XDPAttach(hostVethName, progFD)
```

## How to attach TC?

1. Import the ebpf package - 

```
goebpf "github.com/jayanthvn/pure-gobpf/pkg/ebpf"
```

2. Attach TC - 

```
progFD, err := goebpfelfparser.LoadBpfFile(<ELF file>)
err = goebpf.TCIngressAttach(hostVethName, progFD)
```
