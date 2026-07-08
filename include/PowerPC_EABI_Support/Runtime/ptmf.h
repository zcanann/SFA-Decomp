#ifndef PTMF_H
#define PTMF_H

typedef struct __ptmf {
	long this_delta; // self-explanatory
	long v_offset;   // vtable offset
	union {
		void* f_addr;   // function address
		long ve_offset; // virtual function entry offset (of vtable)
	} f_data;
} __ptmf;

long __ptmf_test(register __ptmf* ptmf);
void __ptmf_scall(...);

#endif /* PTMF_H */
