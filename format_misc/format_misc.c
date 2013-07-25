#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <roots.h>

int main(int argc, char **argv)
{
	load_volume_table();

	format_volume("/misc", NULL);

    return 0;
}
