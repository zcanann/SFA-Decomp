#include <dolphin.h>
#include <dolphin/os.h>

extern void DBPrintf(char*, ...);
void OSSwitchFPUContext(__OSException exception, OSContext* context);
extern volatile OSContext* __OSFPUContext;

static char _oscontext_msg[] = "FPU-unavailable handler installed\n";

void __OSContextInit(void) {
    __OSSetExceptionHandler(__OS_EXCEPTION_FLOATING_POINT, OSSwitchFPUContext);
    __OSFPUContext = NULL;
    DBPrintf(_oscontext_msg);
}
