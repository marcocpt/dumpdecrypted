#if TARGET_OS_SIMULATOR
#error Do not support the simulator, please use the real iPhone Device.
#endif

/*
 
 Dumps decrypted iPhone Applications to a file - better solution than those GDB scripts for non working GDB versions
 (C) Copyright 2011-2014 Stefan Esser
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <Foundation/Foundation.h>

#define swap32(value) (((value & 0xFF000000) >> 24) | ((value & 0x00FF0000) >> 8) | ((value & 0x0000FF00) << 8) | ((value & 0x000000FF) << 24) )

void dumptofile(const char *path, const struct mach_header *mh){
    struct load_command *lc;
    struct encryption_info_command *eic;
    struct fat_header *fh;
    struct fat_arch *arch;
    char buffer[1024];
    char rpath[4096],npath[4096]; /* should be big enough for PATH_MAX */
    unsigned int fileoffs = 0, off_cryptid = 0, restsize;
    int i,fd,outfd,r,n,toread;
    char *tmp;
  
    // 获取绝对路径
    if (realpath(path, rpath) == NULL) {
        // 复制 path 到 rpath, sizeof(rpath) 用来避免缓冲区溢出
        strlcpy(rpath, path, sizeof(rpath));
    }
    
    /* extract basename */
    // 查找一个字符串在另一个字符串中 末次 出现的位置，并返回从字符串中的这个位置起，一直到字符串结束的所有字符；
    tmp = strrchr(rpath, '/');
    printf("\n\n");
    if (tmp == NULL) {
        printf("@Monkey-dump: [-] Unexpected error with filename.\n");
        _exit(1);
    } else {
        printf("@Monkey-dump: [+] Dumping %s\n", tmp+1);
    }
    
    /* detect if this is a arm64 binary */
    if (mh->magic == MH_MAGIC_64) {
        lc = (struct load_command *)((unsigned char *)mh + sizeof(struct mach_header_64));
        NSLog(@"@Monkey-dump: [+] detected 64bit ARM binary in memory.\n");
    } else { /* we might want to check for other errors here, too */
        lc = (struct load_command *)((unsigned char *)mh + sizeof(struct mach_header));
        NSLog(@"@Monkey-dump: [+] detected 32bit ARM binary in memory.\n");
    }
    
    /* searching all load commands for an LC_ENCRYPTION_INFO load command */
    for (i=0; i<mh->ncmds; i++) {
        /*printf("@Monkey-dump: Load Command (%d): %08x\n", i, lc->cmd);*/
        
        if (lc->cmd == LC_ENCRYPTION_INFO || lc->cmd == LC_ENCRYPTION_INFO_64) {
            eic = (struct encryption_info_command *)lc;
            
            /* If this load command is present, but data is not crypted then exit */
            if (eic->cryptid == 0) {
                break;
            }
            off_cryptid=(off_t)((void*)&eic->cryptid - (void*)mh);
            
            NSLog(@"@Monkey-dump: [+] offset to cryptid found: @%p(from %p) = %x\n", &eic->cryptid, mh, off_cryptid);
            
            NSLog(@"@Monkey-dump: [+] Found encrypted data at address %08x of length %u bytes - type %u.\n", eic->cryptoff, eic->cryptsize, eic->cryptid);
            
            NSLog(@"@Monkey-dump: [+] Opening %s for reading.\n", rpath);
            fd = open(rpath, O_RDONLY);
            if (fd == -1) {
                NSLog(@"@Monkey-dump: [-] Failed opening.\n");
                return;
            }
            
            NSLog(@"@Monkey-dump: [+] Reading header\n");
            n = read(fd, (void *)buffer, sizeof(buffer));
            if (n != sizeof(buffer)) {
                NSLog(@"@Monkey-dump: [W] Warning read only %d bytes\n", n);
            }
            
            NSLog(@"@Monkey-dump: [+] Detecting header type\n");
            fh = (struct fat_header *)buffer;
            
            /* Is this a FAT file - we assume the right endianess */
            if (fh->magic == FAT_CIGAM) {
                NSLog(@"@Monkey-dump: [+] Executable is a FAT image - searching for right architecture\n");
                // &fh[1] 为偏移 struct fat_header 的地址，及为第一个架构的 struct fat_arch 首地址
                arch = (struct fat_arch *)&fh[1];
                for (i=0; i<swap32(fh->nfat_arch); i++) {
                    if ((mh->cputype == swap32(arch->cputype)) && (mh->cpusubtype == swap32(arch->cpusubtype))) {
                        fileoffs = swap32(arch->offset);
                        NSLog(@"@Monkey-dump: [+] Correct arch is at offset %u in the file\n", fileoffs);
                        break;
                    }
                    arch++;
                }
                if (fileoffs == 0) {
                    NSLog(@"@Monkey-dump: [-] Could not find correct arch in FAT image\n");
                    _exit(1);
                }
            } else if (fh->magic == MH_MAGIC || fh->magic == MH_MAGIC_64) {
                NSLog(@"@Monkey-dump: [+] Executable is a plain MACH-O image\n");
            } else {
                NSLog(@"@Monkey-dump: [-] Executable is of unknown type\n");
                return;
            }
            
            //获取程序Document目录路径
            NSString *docPath = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)[0];
            
            strlcpy(npath, docPath.UTF8String, sizeof(npath));
            strlcat(npath, tmp, sizeof(npath));
            strlcat(npath, ".decrypted", sizeof(npath));
            strlcpy(buffer, npath, sizeof(buffer));
            
            NSLog(@"@Monkey-dump: [+] Opening %s for writing.\n", npath);
            outfd = open(npath, O_RDWR|O_CREAT|O_TRUNC, 0644);
            if (outfd == -1) {
                if (strncmp("/private/var/mobile/Applications/", rpath, 33) == 0) {
                    NSLog(@"@Monkey-dump: [-] Failed opening. Most probably a sandbox issue. Trying something different.\n");
                    
                    /* create new name */
                    strlcpy(npath, "/private/var/mobile/Applications/", sizeof(npath));
                    tmp = strchr(rpath+33, '/');
                    if (tmp == NULL) {
                        NSLog(@"@Monkey-dump: [-] Unexpected error with filename.\n");
                        return;
                    }
                    tmp++;
                    *tmp++ = 0;
                    strlcat(npath, rpath+33, sizeof(npath));
                    strlcat(npath, "tmp/", sizeof(npath));
                    strlcat(npath, buffer, sizeof(npath));
                    NSLog(@"@Monkey-dump: [+] Opening %s for writing.\n", npath);
                    outfd = open(npath, O_RDWR|O_CREAT|O_TRUNC, 0644);
                }
                if (outfd == -1) {
                    NSLog(@"@Monkey-dump: [-] Failed opening\n");
                    return;
                }
            }
            
            /* calculate address of beginning of crypted data */
            n = fileoffs + eic->cryptoff;
            // lseek -- reposition read/write file offset,
            // If whence is SEEK_END, the offset is set to the size of the file plus offset bytes;
            // If whence is SEEK_SET, the offset is set to offset bytes
            // If whence is SEEK_CUR, the offset is set to its current location plus offset bytes.
            restsize = lseek(fd, 0, SEEK_END) - n - eic->cryptsize;
            lseek(fd, 0, SEEK_SET);
            
            NSLog(@"@Monkey-dump: [+] Copying the not encrypted start of the file\n");
            /* first copy all the data before the encrypted data */
            while (n > 0) {
                toread = (n > sizeof(buffer)) ? sizeof(buffer) : n;
                r = read(fd, buffer, toread);
                if (r != toread) {
                    NSLog(@"@Monkey-dump: [-] Error reading file\n");
                    return;
                }
                n -= r;
                
                r = write(outfd, buffer, toread);
                if (r != toread) {
                    NSLog(@"@Monkey-dump: [-] Error writing file\n");
                    return;
                }
            }
            
            /* now write the previously encrypted data */
            NSLog(@"@Monkey-dump: [+] Dumping the decrypted data into the file\n");
            r = write(outfd, (unsigned char *)mh + eic->cryptoff, eic->cryptsize);
            if (r != eic->cryptsize) {
                NSLog(@"@Monkey-dump: [-] Error writing file\n");
                return;
            }
            
            /* and finish with the remainder of the file */
            n = restsize;
            lseek(fd, eic->cryptsize, SEEK_CUR);
            NSLog(@"@Monkey-dump: [+] Copying the not encrypted remainder of the file\n");
            while (n > 0) {
                toread = (n > sizeof(buffer)) ? sizeof(buffer) : n;
                r = read(fd, buffer, toread);
                if (r != toread) {
                    NSLog(@"@Monkey-dump: [-] Error reading file\n");
                    return;
                }
                n -= r;
                
                r = write(outfd, buffer, toread);
                if (r != toread) {
                    NSLog(@"@Monkey-dump: [-] Error writing file\n");
                    return;
                }
            }
            
            if (off_cryptid) {
                uint32_t zero=0;
                off_cryptid+=fileoffs;
                NSLog(@"@Monkey-dump: [+] Setting the LC_ENCRYPTION_INFO->cryptid to 0 at offset %x\n", off_cryptid);
                if (lseek(outfd, off_cryptid, SEEK_SET) != off_cryptid || write(outfd, &zero, 4) != 4) {
                    NSLog(@"@Monkey-dump: [-] Error writing cryptid value\n");
                }
            }
            
            NSLog(@"@Monkey-dump: [+] Closing original file\n");
            close(fd);
            NSLog(@"@Monkey-dump: [+] Closing dump file\n");
            close(outfd);
            
            return;
        }
        
        lc = (struct load_command *)((unsigned char *)lc+lc->cmdsize);
    }
    NSLog(@"@Monkey-dump: [-] This mach-o file is not encrypted. Nothing was decrypted.\n");
    return;
}

static void image_added(const struct mach_header *mh, intptr_t slide) {
    Dl_info image_info;
    // dladdr -- find the image containing a given address
    int result = dladdr(mh, &image_info);
    dumptofile(image_info.dli_fname, mh);
}

__attribute__((constructor))
static void dumpexecutable() {
    printf("@Monkey-dump: mach-o decryption dumper\n\n");
    printf("@Monkey-dump: DISCLAIMER: This tool is only meant for security research purposes, not for application crackers.");
    // dyld 加载 image 后调用的回调函数
    _dyld_register_func_for_add_image(&image_added);
}


