#include <dolphin.h>
#include <dolphin/ax.h>

void __AXAllocInit(void);
void __AXVPBInit(void);
void __AXSPBInit(void);
void __AXAuxInit(void);
void __AXClInit(void);
void __AXOutInit(void);
void __AXAllocQuit(void);
void __AXVPBQuit(void);
void __AXSPBQuit(void);
void __AXAuxQuit(void);
void __AXClQuit(void);
void __AXOutQuit(void);

#ifdef DEBUG
const char* __AXVersion = "<< Dolphin SDK - AX\tdebug build: Apr  5 2004 03:56:21 (0x2301) >>";
#else
const char* __AXVersion = "<< Dolphin SDK - AX\trelease build: Mar 11 2003 11:19:39 (0x2301) >>";
#endif

void AXInit(void) {
    OSRegisterVersion(__AXVersion);

    __AXAllocInit();
    __AXVPBInit();
    __AXSPBInit();
    __AXAuxInit();
    __AXClInit();
    __AXOutInit();
}

void AXQuit(void) {
#ifdef DEBUG
    OSReport("Shutting down AX\n");
#endif
    __AXAllocQuit();
    __AXVPBQuit();
    __AXSPBQuit();
    __AXAuxQuit();
    __AXClQuit();
    __AXOutQuit();
}
