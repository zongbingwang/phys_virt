/*
 * Copyright (c) 2015 Ahmed Samy  <f.fallen45@gmail.com>
 *
 * Physical memory driver communication
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
#include <Windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "physmem.h"

int main(void)
{
	HANDLE hDriver;
	rqaddr_t rq;
	void *virt;
	size_t ret;

	hDriver = CreateFileW(DEVICE_IOCTL,
		GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ,
		NULL, OPEN_EXISTING, 0, NULL);
	if (hDriver == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "Driver not loaded?\n");
		return 1;
	}

	rq.addr = 0x00000000;
	rq.size = 8;

	// Map memory
	if (DeviceIoControl(hDriver,
		IOCTL_PHYSMEM_MAP, &rq, sizeof(rq), &virt, sizeof(void *), &ret, NULL)) {
		printf("Success: Mapped physical address 0x%X into 0x%X (virtual) (size: %d)\n",
			rq.addr, virt, ret);
	} else {
		fprintf(stderr, "DeviceIoControl failed for some reason: %d\n", GetLastError());
		goto out;
	}

	printf("Virtual old: %d\n", *(int *)virt);
	*(int *)virt = 5;
	printf("Virtual new: %d\n", *(int *)virt);

	// Unmap
	rq.addr = virt;
	if (DeviceIoControl(hDriver,
		IOCTL_PHYSMEM_UNMAP, &rq, sizeof(rqaddr_t), NULL, 0, NULL, NULL)) {
		fprintf(stderr, "Successfully unmapped memory!\n");
	} else {
		fprintf(stderr, "DeviceIoControl failed for some reason: %d\n", GetLastError());
	}

out:
	CloseHandle(hDriver);
	for (;;);
	return 0;
}
