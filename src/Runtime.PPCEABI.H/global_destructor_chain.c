#include "PowerPC_EABI_Support/Runtime/NMWException.h"
#include "PowerPC_EABI_Support/Runtime/MWCPlusLib.h"

DestructorChain* __global_destructor_chain;

void __destroy_global_chain(void) {
    DestructorChain* iter;
    while ((iter = __global_destructor_chain) != 0) {
        __global_destructor_chain = iter->next;
        DTORCALL_COMPLETE(iter->destructor, iter->object);
    }
}

static __declspec(section ".dtors") void* const __destroy_global_chain_reference = __destroy_global_chain;
