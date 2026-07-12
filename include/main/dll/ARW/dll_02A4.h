#ifndef MAIN_DLL_ARW_DLL_02A4_H
#define MAIN_DLL_ARW_DLL_02A4_H

#include "global.h"
#include "main/game_object.h"

typedef struct Dll2A4State
{
    f32 fadeTimer;
    s16 spinRateX;
    s16 spinRateY;
    s16 spinRateZ;
    u8 pad0A[2];
} Dll2A4State;

STATIC_ASSERT(sizeof(Dll2A4State) == 0x0c);
STATIC_ASSERT(offsetof(Dll2A4State, spinRateX) == 0x04);
STATIC_ASSERT(offsetof(Dll2A4State, spinRateY) == 0x06);
STATIC_ASSERT(offsetof(Dll2A4State, spinRateZ) == 0x08);

extern f32 lbl_803E7138;
extern const f32 lbl_803E713C;
extern f32 lbl_803E7140;

int dll_2A4_getExtraSize_ret_12(void);
int dll_2A4_getObjectTypeId(void);
void dll_2A4_free_nop(void);
void dll_2A4_hitDetect_nop(void);
void dll_2A4_render(int obj, int p2, int p3, int p4, int p5);
void dll_2A4_update(GameObject* obj);
void dll_2A4_init(GameObject* obj);
void dll_2A4_release_nop(void);
void dll_2A4_initialise_nop(void);

#endif
