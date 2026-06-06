#ifndef MAIN_DLL_CNTHITOBJEC_STATE_H_
#define MAIN_DLL_CNTHITOBJEC_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/* cnthitobjec_state_GENERATED
 * CntHitObjectState - the obj+0xB8 extra record observed in cnthitobjec.c. Field widths
 * mirror the observed deref widths; unobserved ranges are padded. The
 * span covers every observed access - the true allocation may be larger.
 */
typedef struct CntHitObjectState {
    int unk0;
    int unk4;
    u8 unk8;
    u8 unk9[0x10 - 0x9];
} CntHitObjectState;

#endif /* MAIN_DLL_CNTHITOBJEC_STATE_H_ */
