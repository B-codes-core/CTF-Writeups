
## 1.  Deleted File

#Forensics
#### Description :
Oh no, I deleted a file. I need to get it back.

#### Solution :
We first run the file command on the image file to determine the file system in use
`$ file disk.img`             
`disk.img: DOS/MBR boot sector, code offset 0x3c+2, OEM-ID "mkfs.fat", sectors/cluster 4, root entries 512, sectors 2048 (volumes <=32 MB), Media descriptor 0xf8, sectors/FAT 2, sectors/track 16, serial number 0xb0918da5, unlabeled, FAT (12 bit)`

We see that it is a DOS Master Boot Record with FAT file system. So, we can mount it

``` 
$ mkdir disk.dir
$ mount disk.img disk.dir
```

Now, to recover the deleted files, we use "Sleuthkit" which is a collection of command line tools which allows us to investigate disk files. It supports the following partitions DOS, BSD, Mac and GPT Disks and support s the following filesystems : NTFS, FAT, Ext3, Ext4 etc.

See : [List of Commands](https://wiki.sleuthkit.org/index.php?title=The_Sleuth_Kit_commands)

We use `fls` command to see all the directories and files including deleted ones
```
$ fls -r disk.img
r/r * 4:        ziptA2iU
r/r * 6:        flag.zip
r/r 9:  zip-password.txt
v/v 32691:      $MBR
v/v 32692:      $FAT1
v/v 32693:      $FAT2
V/V 32694:      $OrphanFiles
```

We can see that there is a `flag.zip` at inode number 6 and `zip-password.txt` at inode number 9. The * indicates that they have been deleted. To recover the files we use the command line tool `icat`. It cats the contents of a file present in a particular [inode number](https://www.stackscale.com/blog/inodes-linux/#:~:text=the%20wc%20command-,What%20is%20an%20inode%3F,known%20as%20%E2%80%9Cinode%20number%E2%80%9D.)

We use the below commands to extract the 2 files by specifying their inode numbers that we got in the previous command

```
$ icat disk.img 6 > flag.zip
$ icat disk.img 9 > zip-password.txt
$ cat zip-password.txt 
The password is: password
```

We use the given password to unlock flag.zip and read the contents of flag.txt present inside the zip file

**Flag : openECSC{thank_you_for_recovering_my_file}**
