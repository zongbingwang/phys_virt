# phys_to_virt

A simple windows driver to translate (or "map") physical memory addresses into calling process virtual address space.  This is going to support more operations soon.  
There's a user mode application included to demonstrate how this would be used.

## About

This was mainly made for educational purposes and discovery.

## License

Licensed under MIT as described in the sources.

## Currently supported operations

This driver currently supports the following operations:
- Map memory
- Unmap memory

Unsupported operations:
- Find out which process has the virtual/physical address(es) mapped to it's address space.

There's more to come.