#include <dolphin/db.h>
#include <dolphin/os.h>

extern int DBVerbose;
extern const char lbl_8032D818[];

extern void __DBExceptionStart();
extern void __DBExceptionEnd();
extern void __DBExceptionSetNumber();

void DBInit(void) {
  __DBInterface = (DBInterface*)OSPhysicalToCached(OS_DBINTERFACE_ADDR);
  __DBInterface->ExceptionDestination = (void (*)())OSCachedToPhysical(__DBExceptionDestination);
  DBVerbose = TRUE;
}

void __DBExceptionDestinationAux(void) {
  u32* contextAddr = (void*)0x00C0;
  OSContext* context = (OSContext*)OSPhysicalToCached(*contextAddr);

  OSReport(lbl_8032D818);
  OSDumpContext(context);
  PPCHalt();
}

/* clang-format off */
asm void __DBExceptionDestination(void) {
    nofralloc
    mfmsr       r3
    ori         r3, r3, 0x10|0x20
    mtmsr       r3

    b __DBExceptionDestinationAux
}
/* clang-format on */

BOOL __DBIsExceptionMarked(__OSException exception) {
  u32 mask = 1 << exception;

  return (BOOL)(__DBInterface->exceptionMask & mask);
}

void DBPrintf(char* format, ...) {}
