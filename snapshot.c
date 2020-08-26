#include <fcntl.h>
#include <sys/ioctl.h>

struct setup_params {
        char *bdev_path;
        char *cow_path;
        unsigned long cow_size;
};

int main(int argc, char **argv) {
	struct setup_params p;
	p.bdev_path = argv[1];
	p.cow_path = argv[2];
	p.cow_size = atoi(argv[3]);
	return ioctl(open("/dev/snapshot-ctl", O_RDONLY), 0, &p);
}
