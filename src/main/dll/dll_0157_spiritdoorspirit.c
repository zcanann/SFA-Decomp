/*
 * DLL 0x157 - spirit door spirit; the last entry of the sandwormBoss
 * 10-DLL container (0x14A CFPowerBase .. 0x157 SpiritDoorSpirit) covering
 * [8019D578-801A0B14).
 *
 * A spirit-door spirit is a fade-in/fade-out apparition gated on a game
 * bit (placement->gateGameBit). While the bit is clear the spirit is "active":
 * it joins object group 0x4E, runs its idle effect (fn_80098B18), and
 * fades alpha up to 0xFF; once the bit is set it leaves the group and
 * fades alpha back to 0. It only renders while active.
 */
#include "main/game_object.h"
#include "main/dll/VF/vf_shared.h"
#include "main/gamebits.h"

#define SPIRITDOORSPIRIT_OBJGROUP 0x4e
extern u64 ObjGroup_RemoveObject();
extern u32 ObjGroup_AddObject();
extern f32 lbl_803E42B8;
extern f32 lbl_803DBE78;
extern void fn_80098B18(int obj, float f, int a, int b, int c, int d);

/* spiritdoorspirit_getExtraSize == 0x1. */
typedef struct SpiritDoorSpiritState
{
    u8 active; /* gamebit not yet set: render + group 0x4e membership */
} SpiritDoorSpiritState;

typedef struct SpiritdoorspiritPlacement
{
    u8 pad0[0x1E];
    s16 gateGameBit;
    u8 pad20[0x28 - 0x20];
} SpiritdoorspiritPlacement;

STATIC_ASSERT(offsetof(SpiritdoorspiritPlacement, gateGameBit) == 0x1E);

void spiritdoorspirit_hitDetect(void)
{
}

void spiritdoorspirit_release(void)
{
}

void spiritdoorspirit_initialise(void)
{
}

int spiritdoorspirit_getExtraSize(void) { return 0x1; }
int spiritdoorspirit_getObjectTypeId(void) { return 0x0; }

#pragma scheduling off
void spiritdoorspirit_free(int x) { ObjGroup_RemoveObject(x, SPIRITDOORSPIRIT_OBJGROUP); }
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off

void spiritdoorspirit_init(int* obj)
{
    SpiritDoorSpiritState* state = ((GameObject*)obj)->extra;
    state->active = 0;
    *(s8*)&((GameObject*)obj)->anim.alpha = 0;
}

void spiritdoorspirit_update(int* obj)
{
    SpiritDoorSpiritState* state;
    u8* def;
    u8 active;

    state = ((GameObject*)obj)->extra;
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (state->active == 0)
    {
        state->active = active = (u8)(GameBit_Get(((SpiritdoorspiritPlacement*)def)->gateGameBit) == 0);
        if (active != 0)
        {
            ObjGroup_AddObject(obj, SPIRITDOORSPIRIT_OBJGROUP);
        }
        if (((GameObject*)obj)->anim.alpha != 0)
        {
            ((GameObject*)obj)->anim.alpha--;
        }
    }
    else
    {
        fn_80098B18((int)obj, lbl_803DBE78, 5, 0, 0, 0);
        state->active = active = (u8)(GameBit_Get(((SpiritdoorspiritPlacement*)def)->gateGameBit) == 0);
        if (active == 0)
        {
            ObjGroup_RemoveObject(obj, SPIRITDOORSPIRIT_OBJGROUP);
        }
        if (((GameObject*)obj)->anim.alpha < 0xff)
        {
            ((GameObject*)obj)->anim.alpha++;
        }
    }
}

void spiritdoorspirit_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    SpiritDoorSpiritState* state = ((GameObject*)obj)->extra;
    if (visible == 0 || state->active == 0)
    {
        return;
    }

    ((void(*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E42B8);
}

#pragma peephole reset
#pragma scheduling reset
