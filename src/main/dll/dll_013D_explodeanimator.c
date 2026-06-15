#include "main/effect_interfaces.h"
#include "main/game_object.h"

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();


#include "main/map_block.h"
#include "main/dll/MMP/MMP_asteroid.h"
#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/path_control_interface.h"
#include "main/game_object.h"

typedef struct ExplodeanimatorState
{
    u8 pad0[0x2 - 0x0];
    u8 unk2;
    u8 pad3[0x4 - 0x3];
} ExplodeanimatorState;

typedef struct ExplodeanimatorPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    s16 unk22;
    s16 unk24;
    u8 pad26[0x28 - 0x26];
    s16 unk28;
    s16 unk2A;
    u8 pad2C[0x2E - 0x2C];
    s16 unk2E;
    s16 unk30;
    s16 unk32;
    s16 unk34;
    u8 pad36[0x38 - 0x36];
} ExplodeanimatorPlacement;

extern f32 lbl_803E4020;

void explodeanimator_render(void)
{
}

void explodeanimator_hitDetect(void)
{
}

void explodeanimator_release(void)
{
}

void explodeanimator_initialise(void)
{
}

void explodeanimator_update(int* obj)
{
    int i;
    u8* sub;
    u8* def;
    f32 buf[6];
    f32 vel[2];

    sub = ((GameObject*)obj)->extra;
    if ((sub[2] & 1) != 0) return;
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (GameBit_Get(((ExplodeanimatorPlacement*)def)->unk34) == 0) return;
    GameBit_Set(((ExplodeanimatorPlacement*)def)->unk32, 1);
    sub[2] = (u8)(sub[2] | 1);
    {
    f32 mult = lbl_803E4020;
    for (i = 0; i < def[0x2c]; i++)
    {
        vel[0] = mult * (f32)(s32)
        randomGetRange(((ExplodeanimatorPlacement*)def)->unk2E, ((ExplodeanimatorPlacement*)def)->unk28);
        vel[1] = mult * (f32)(s32)
        randomGetRange(((ExplodeanimatorPlacement*)def)->unk30, ((ExplodeanimatorPlacement*)def)->unk2A);
        buf[3] = (f32)(s32)
        randomGetRange(((ExplodeanimatorPlacement*)def)->unk18, ((ExplodeanimatorPlacement*)def)->unk1E);
        buf[4] = (f32)(s32)
        randomGetRange(((ExplodeanimatorPlacement*)def)->unk1A, ((ExplodeanimatorPlacement*)def)->unk20);
        buf[5] = (f32)(s32)
        randomGetRange(((ExplodeanimatorPlacement*)def)->unk1C, ((ExplodeanimatorPlacement*)def)->unk22);
        (*gPartfxInterface)->spawnObject(obj, ((ExplodeanimatorPlacement*)def)->unk24, buf, 2, -1, vel);
    }
    }
}

void dimbossicesmash_hitDetect(void);

int explodeanimator_getExtraSize(void) { return 0x4; }
int explodeanimator_getObjectTypeId(void) { return 0x0; }
int dimbossicesmash_getExtraSize(void);

void explodeanimator_free(int x) { ObjGroup_RemoveObject(x, 0x1a); }

u32 dimbossicesmash_getObjectTypeId(int* obj);

void explodeanimator_init(int* obj, int* def)
{
    int* state = ((GameObject*)obj)->extra;
    int v;
    if ((u32)GameBit_Get(*(s16*)((char*)def + 50)) != 0u)
    {
        v = 1;
    }
    else
    {
        v = 0;
    }
    ((ExplodeanimatorState*)state)->unk2 = (u8)v;
    ObjGroup_AddObject(obj, 26);
}

void xyzanimator_init(int obj);

/* EN v1.0 0x80197068  size: 284b  dimbossicesmash_init. */
