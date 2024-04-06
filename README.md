# Repurposing SMAP and PAN for Intra-kernel Privilege Separation on x86 and ARM

### Build LLVM
```
$ cd <rootdir>
$ ./buildscript/llvm-compile.sh
$ export $PATH=<rootdir>/build/sysroot/bin:$PATH
```

### Build Rootfs
```
$ wget https://buildroot.org/downloads/buildroot-2021.02.4.tar.gz
$ tar xf buildroot-2021.02.4.tar.gz && cd buildroot-2021.02.4
$ make pc_x86_64_bios_defconfig
$ make menuconfig
  [ Build options -> build packages with debugging symbols (y) ]
  [ Toolchain -> C library (glibc) ]
  [ System configuration ->Init system (systemd) ]
  [ Target packages -> System tools -> systemd -> enable login deamon]
$ make -j$(nproc)
```

### QEMU Debugging
```
$ cd linux-5.9
$ make x86_64_defconfig
$ ./make.sh

$ sudo qemu-system-x86_64 -s -S -kernel arch/x86/boot/bzImage -boot c -m 16G -hda <rootfs> \
  -append "root=/dev/sda rw console==ttyS0,115200 acpi=off nokaslr pti=on" \
  -serial stdio -display none -cpu host,smap,smep,pcid,invpcid -enable-kvm
  [ (optional) -L /usr/share/OVMF -bios OVMF_CODE.fd ]

$ gdb vmlinux
  (gdb) target remote localhost:1234
  (gdb) hbreak start_kernel
```

### Run on a real machine
* **Operating System**: Linux 5.9
* **Distribution**: Ubuntu 20.04.2 LTS
* **CPU**: Intel i9-9900K

```
$ cd linux-5.9
$ cp -v /boot/config-$(uname -r) .config
$ make olddefconfig
$ make menuconfig [optional]
$ ./make.sh deb
$ cd ..
$ sudo dpkg -i *.deb
$ sudo reboot
```

### Boot Command
* Turn off kaslr
* Enable KPTI
* Disable NMI watchdog

```
$ sudo sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT=\"splash nokaslr pti=on ignore_loglevel nmi_watchdog=0\"/' /etc/default/grub
  [ refer: https://www.kernel.org/doc/Documentation/admin-guide/kernel-parameters.txt ]
$ sudo update-grub
```

### BUGS
The current version fails to run some daemons reliably at boot time.\
Systemd waits for all required daemons to run...\
The following commands disable problematic daemon services.

```
$ sudo systemctl disable systemd-timesyncd.service // Network Time Synchronization
$ sudo systemctl disable systemd-resolved.service  // Network Name Resolution
$ sudo systemctl set-default multi-user.target  // GNOME Display Manager
```
