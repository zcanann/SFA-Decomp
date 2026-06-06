#ifndef MAIN_DLL_CNTCOUNTER_STATE_H_
#define MAIN_DLL_CNTCOUNTER_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/* cntcounter_state_GENERATED
 * CntCounterState - the obj+0xB8 extra record observed in cntcounter.c. Field widths
 * mirror the observed deref widths; unobserved ranges are padded. The
 * span covers every observed access - the true allocation may be larger.
 */
typedef struct CntCounterState {
    int unk0;
    u8 unk4;
    u8 unk5[0xC - 0x5];
} CntCounterState;

#endif /* MAIN_DLL_CNTCOUNTER_STATE_H_ */
