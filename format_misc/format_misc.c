#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <roots.h>
#include "libvolumeutils_ui.h"

#define USE_MISC_SIZE	200

int main(int argc, char **argv)
{
	Volume* v;
        char bufToWrite[USE_MISC_SIZE];
	int i;

	load_volume_table();

	v = volume_for_path("/misc");
	if (v == NULL) {
		LOGE("cannot get volume\n");
		return -1;
	}
	FILE* f = fopen(v->device, "wb");
	if (f == NULL) {
		LOGE("cannot open device\n");
		return -1;
	}

	for(i=0; i<USE_MISC_SIZE; i++){
		bufToWrite[i]=0;
	}
	int count = fwrite(bufToWrite, USE_MISC_SIZE, 1, f);

	if (count != 1) {
		LOGE("cannot write full buffer\n");
                fclose(f);
		return -1;
	}

	if (fclose(f) != 0) {
		LOGE("cannot close file\n");
		return -1;
	}

	return 0;
}

