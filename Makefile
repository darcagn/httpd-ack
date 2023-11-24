# Put the filename of the output binary here
VERSION = "20071123"
TARGET = httpd-ack.elf

# List all of your C files here, but change the extension to ".o"
OBJS = httpd-ack.o romdisk.o

LWIPDIR = $(KOS_BASE)/../kos-ports/lwip/lwip/src
ARCHDIR = $(LWIPDIR)/../../kos

KOS_CFLAGS += -DIPv4 \
	-I$(LWIPDIR)/include -I$(ARCHDIR)/include \
	-I$(LWIPDIR)/include/ipv4 -DVERSION=$(VERSION)

all: rm-elf $(TARGET)

include $(KOS_BASE)/Makefile.rules

clean:
	rm -f $(TARGET) $(OBJS) romdisk.img release/*.zip romdisk/*.zip cdrom/*
 
rm-elf:
	rm -f $(TARGET) romdisk.*

$(TARGET): $(OBJS)
	$(KOS_CC) $(KOS_CFLAGS) $(KOS_LDFLAGS) -o $(TARGET) $(KOS_START) \
		$(OBJS) $(OBJEXTRA) -llwip4 -lkosutils -lconio $(KOS_LIBS)

romdisk.img:
	zip -9 -r romdisk/source.zip source/
	$(KOS_GENROMFS) -f romdisk.img -d romdisk -v

romdisk.o: romdisk.img
	$(KOS_BASE)/utils/bin2o/bin2o romdisk.img romdisk romdisk.o

run: $(TARGET)
	dc-tool -n -x $(TARGET)

release: $(TARGET)
	kos-strip $(TARGET)
	rm -f release/*.zip
	cd release;zip -9 httpd-ack-$(VERSION).zip *

# boot cd related stuff
# misc utils for making boot cd
CDRECORD = cdrecord speed=4 dev= ATAPI:0,0,0
SCRAMBLE = util/scramble
MAKEIP = util/makeip
MAKEIP_TMPL = util/IP.TMPL


cdrom/1ST_READ.BIN: $(TARGET)
	kos-strip $(TARGET)
	kos-objcopy -O binary -R .stack $(TARGET) cdrom/temp.bin
	$(SCRAMBLE) cdrom/temp.bin cdrom/1ST_READ.BIN

cdrom/IP.BIN: $(TARGET)
	cpp -DVERSION=$(VERSION) ip.txt | grep -v \# > cdrom/ip.txt
	IP_TEMPLATE_FILE=$(MAKEIP_TMPL) $(MAKEIP) cdrom/ip.txt cdrom/IP.BIN

# make and burn audio track
cdrom/audio.raw: 
	dd if=/dev/zero of=cdrom/audio.raw bs=2352 count=300

cdrom/burn-audio: cdrom/audio.raw
	$(CDRECORD) -multi -audio cdrom/audio.raw
	touch cdrom/burn-audio

# make data track
cdrom/tmp.iso: cdrom/1ST_READ.BIN cdrom/IP.BIN cdrom/burn-audio
	mkisofs -C `$(CDRECORD) -msinfo` -o cdrom/tmp.iso cdrom/1ST_READ.BIN

cdrom/data.raw: cdrom/tmp.iso cdrom/IP.BIN
	( cat cdrom/IP.BIN ; dd if=cdrom/tmp.iso bs=2048 skip=16 ) > cdrom/data.raw

burn-cd: cdrom/data.raw
	$(CDRECORD) -xa cdrom/data.raw
	rm -f cdrom/burn-audio cdrom/data.raw cdrom/tmp.iso	
