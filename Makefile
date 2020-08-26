obj-m += blsnapshot.o

all:
	gcc snapshot.c -o snapshot
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	-rm snapshot
