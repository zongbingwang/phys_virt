/*
 * Copyright (c) 2015 Ahmed Samy  <f.fallen45@gmail.com>
 *
 * See physmem.c for more information.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
*/
#ifndef __physmem_h
#define __physmem_h

#define DEVICE_NAME				L"PhysMem"
#define DEVICE_LINK				L"\\Device\\"		## DEVICE_NAME
#define DEVICE_DOS				L"\\DosDevices\\"	## DEVICE_NAME
#define DEVICE_IOCTL			L"\\\\.\\"			## DEVICE_NAME
#define FILE_DEVICE_PHYSMEM		0x00008005
#define IOCTL_PHYSMEM_MAP		CTL_CODE(FILE_DEVICE_PHYSMEM, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PHYSMEM_UNMAP		CTL_CODE(FILE_DEVICE_PHYSMEM, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PHYSMEM_WHOIS		CTL_CODE(FILE_DEVICE_PHYSMEM, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Make things a bit more simple	(Ex{Allocate,Free}PoolWithTag)
#define PHYSMEM_POOL_TAG		'memp'

/*
 * Following structure is passed to and from user.
 * If passed from user:
 *  - Map: The "addr" is supposed to be the
 *		physical address to map into their address space (and ours)
 *		plus it's size.
 *	- Unmap: The "addr" is supposed to be the
 *		virtual address that was previously mapped
 *
 * If passed to user, the "addr" is the mapped virtual address. 
 * And the size shall stay the same (Only for the case of mapping).
 *
 * Currently, every operation signaled to this driver is supposed
 * to pass this structure.
*/
typedef struct {
	void *addr;
	size_t size;
} rqaddr_t;

#endif
