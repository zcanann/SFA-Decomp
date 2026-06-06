#include <dolphin.h>

OSModuleQueue __OSModuleInfoList AT_ADDRESS(OS_BASE_CACHED | 0x30C8);
const void* __OSStringTable AT_ADDRESS(OS_BASE_CACHED | 0x30D0);

void __OSModuleInit(void) {
    __OSModuleInfoList.tail = NULL;
    __OSModuleInfoList.head = NULL;
    __OSStringTable = NULL;
}
