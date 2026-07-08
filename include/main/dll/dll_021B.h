#ifndef MAIN_DLL_DLL_021B_H_
#define MAIN_DLL_DLL_021B_H_

#include "global.h"
#include "main/obj_placement.h"

typedef struct Dll21BState
{
    s16 driveGameBit;
} Dll21BState;

STATIC_ASSERT(sizeof(Dll21BState) == 0x2);

/*
 * Class-specific placement record for DLL 0x21B: the common ObjPlacement
 * head (position / mapId at 0x00..0x17) followed by the slide parameters.
 *  - 0x18 s8 initRotByte: seeds anim.rotX (<<8) at init
 *  - 0x19 s8 direction:   1 selects the negative-Z-open slide convention
 *  - 0x1E s16 driveGameBit: game bit that drives the slide
 */
typedef struct Dll21BPlacement
{
    ObjPlacement base; /* 0x00 */
    s8 initRotByte;    /* 0x18 */
    s8 direction;      /* 0x19 */
    u8 pad1A[4];       /* 0x1A */
    s16 driveGameBit;  /* 0x1E */
} Dll21BPlacement;

STATIC_ASSERT(offsetof(Dll21BPlacement, initRotByte) == 0x18);
STATIC_ASSERT(offsetof(Dll21BPlacement, direction) == 0x19);
STATIC_ASSERT(offsetof(Dll21BPlacement, driveGameBit) == 0x1e);

int dll_21B_getExtraSize_ret_4(void);
int dll_21B_getObjectTypeId(void);
void dll_21B_free(int obj);
void dll_21B_render_nop(void);
void dll_21B_hitDetect_nop(void);
void dll_21B_update(int obj);
void dll_21B_init(int* obj, Dll21BPlacement* init);
void dll_21B_release_nop(void);
void dll_21B_initialise_nop(void);

#endif /* MAIN_DLL_DLL_021B_H_ */
