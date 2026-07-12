#ifndef MAIN_DLL_ARW_DLL_02A3_H
#define MAIN_DLL_ARW_DLL_02A3_H

#include "global.h"
#include "main/game_object.h"

typedef struct Dll2A3State
{
    f32 lifetime;
    s16 rotXSpeed;
    s16 rotYSpeed;
    s16 rotZSpeed;
    u8 pad0A[2];
} Dll2A3State;

typedef struct Dll2A3Velocity
{
    f32 x;
    f32 y;
    f32 z;
} Dll2A3Velocity;

STATIC_ASSERT(sizeof(Dll2A3State) == 0x0c);
STATIC_ASSERT(offsetof(Dll2A3State, rotXSpeed) == 0x04);
STATIC_ASSERT(offsetof(Dll2A3State, rotYSpeed) == 0x06);
STATIC_ASSERT(offsetof(Dll2A3State, rotZSpeed) == 0x08);

extern int lbl_803DDD90;
extern int lbl_803DDD94;
extern f32 lbl_803E7118;
extern f32 lbl_803E711C;
extern f32 lbl_803E7120;
extern f32 lbl_803E7124;

int dll_2A3_getExtraSize_ret_12(void);
int dll_2A3_getObjectTypeId(void);
void dll_2A3_free(void);
void dll_2A3_render(int obj, int p2, int p3, int p4, int p5);
void dll_2A3_hitDetect(void);
void dll_2A3_update(GameObject* obj);
void dll_2A3_init(GameObject* obj);
void dll_2A3_release_nop(void);
void dll_2A3_initialise_nop(void);

void fn_8023134C(GameObject* obj, int lifetime);
void fn_8023137C(GameObject* obj, Dll2A3Velocity* velocity);

#endif
