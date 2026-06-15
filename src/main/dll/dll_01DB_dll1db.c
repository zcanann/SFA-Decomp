/* DLL 0x1DB — DIM2 snowball / conveyor / crusher-platform objects [801B8798-801B8860) */
#include "main/dll/dim2pathgeneratorstate_struct.h"
#include "main/dll/dim2snowballstate_struct.h"
#include "main/dll/truthhornicestate_struct.h"
#include "main/dll/dim2conveyorstate_struct.h"
#include "main/dll/dll1d6state_struct.h"
#include "main/game_object.h"

STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);

STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);

STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);

STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);

/* dim2pathgenerator_getExtraSize == 0x9a8 (incl. three 200-entry curve
 * tables filled by the RomCurve interface). */

STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);

static inline int* DIM2snowball_GetActiveModel(void* obj);

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);

extern f32 timeDelta;

extern void objRenderFn_8003b8f4(f32);
extern void* Obj_GetPlayerObject(void);

#include "main/game_object.h"
#include "main/audio/sfx_ids.h"

typedef struct Dll1DBPlacement
{
    u8 pad0[0x1 - 0x0];
    u8 unk1;
    u8 pad2[0x3 - 0x2];
    u8 unk3;
    u8 unk4;
    u8 pad5[0xC - 0x5];
    f32 unkC;
    u8 pad10[0x1E - 0x10];
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} Dll1DBPlacement;

typedef struct Dll1DBState
{
    s8 unk0;
    u8 pad1[0x2 - 0x1];
    s8 unk2;
    u8 pad3[0x4 - 0x3];
    u8 unk4;
    u8 pad5[0x24 - 0x5];
    f32 unk24;
} Dll1DBState;

#pragma scheduling on
#pragma peephole on
extern u32 GameBit_Get(int id);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern f32 lbl_803E4B0C;
extern f32 lbl_803E4B10;
extern f32 lbl_803E4B14;
extern f32 lbl_803E4B18;
extern f32 lbl_803E4B1C;
extern f32 lbl_803E4B20;
extern f32 lbl_803E4B24;
extern f32 lbl_803E4B08;

void FUN_801b9cc4(int param_1)
{
    char* pcVar1;
    int iVar2;

    pcVar1 = ((GameObject*)param_1)->extra;
    if ((pcVar1[2] & 1U) == 0)
    {
        iVar2 = *(int*)&((GameObject*)param_1)->anim.placementData;
        if (('\0' < *pcVar1) && (*pcVar1 = *pcVar1 + -1, *pcVar1 == '\0'))
        {
            pcVar1[2] = pcVar1[2] | 1;
            GameBit_Set((int)*(short*)(iVar2 + 0x1e), 1);
        }
    }
    return;
}

void dll_1DA_release(void);

#pragma scheduling off
#pragma peephole off
void dll_1DB_free(void)
{
}

void dll_1DB_hitDetect(void)
{
}

void dll_1DB_release(void)
{
}

void dll_1DB_initialise(void)
{
}

void dim2icefloe_free(void);

void dll_1DB_update(int obj)
{
    extern void Sfx_PlayFromObject(int obj, int sfxId);
    int sub;
    int state;
    int found;
    u32 player;
    int i;
    int n;
    int base;

    sub = *(int*)&((GameObject*)obj)->extra;
    player = (u32)Obj_GetPlayerObject();
    state = *(int*)&((GameObject*)obj)->anim.placementData;
    found = 0;
    i = 0;
    base = *(int*)(obj + 0x58);
    for (n = (int)*(s8*)(base + 0x10f); n > 0; n--)
    {
        u32 entry = *(u32*)(base + i + 0x100);
        if (entry == player)
        {
            found = 1;
            break;
        }
        i += 4;
    }
    switch (((Dll1DBState*)sub)->unk4)
    {
    case 1:
        Sfx_StopObjectChannel(obj, 8);
        if (found == 0)
        {
            *(u8*)(sub + 6) = 1;
        }
        else if (*(u8*)(sub + 6) != 0 && *(u8*)(sub + 5) != 0)
        {
            Sfx_PlayFromObject(obj, SFXsp_lfoot_taunt3);
            ((Dll1DBState*)sub)->unk4 = 4;
            *(f32*)sub = lbl_803E4B0C;
        }
        if (GameBit_Get(((Dll1DBPlacement*)state)->unk20) != 0)
        {
            Sfx_PlayFromObject(obj, SFXsp_lfoot_taunt3);
            ((Dll1DBState*)sub)->unk4 = 4;
            *(f32*)sub = lbl_803E4B0C;
        }
        break;
    case 2:
        Sfx_StopObjectChannel(obj, 8);
        if (*(u8*)(sub + 5) != 0)
        {
            if (found == 0)
            {
                Sfx_PlayFromObject(obj, SFXsp_lfoot_taunt3);
                ((Dll1DBState*)sub)->unk4 = 3;
                *(f32*)sub = lbl_803E4B0C;
                *(u8*)(sub + 5) = 0;
                GameBit_Set(((Dll1DBPlacement*)state)->unk1E, 0);
            }
        }
        else
        {
            if (GameBit_Get(((Dll1DBPlacement*)state)->unk20) == 0)
            {
                Sfx_PlayFromObject(obj, SFXsp_lfoot_taunt3);
                ((Dll1DBState*)sub)->unk4 = 3;
                *(f32*)sub = lbl_803E4B0C;
                *(u8*)(sub + 5) = 0;
                GameBit_Set(((Dll1DBPlacement*)state)->unk1E, 0);
            }
        }
        break;
    case 3:
        *(f32*)sub = *(f32*)sub + (lbl_803E4B10 * timeDelta +
            lbl_803E4B14 * (f32)(s32)(*(f32*)sub < lbl_803E4B0C));
        {
            f32 v = *(f32*)sub;
            if (v > lbl_803E4B18)
            {
                *(f32*)sub = *(f32*)&lbl_803E4B18;
            }
        }
        ((GameObject*)obj)->anim.localPosY = *(f32*)sub * timeDelta + ((GameObject*)obj)->anim.localPosY;
        if (((GameObject*)obj)->anim.localPosY > ((Dll1DBPlacement*)state)->unkC)
        {
            Sfx_PlayFromObject(obj, SFXchar_on_firelp);
            ((GameObject*)obj)->anim.localPosY = ((Dll1DBPlacement*)state)->unkC;
            ((Dll1DBState*)sub)->unk4 = 1;
            if (found != 0)
            {
                *(u8*)(sub + 5) = 1;
                *(u8*)(sub + 6) = 0;
            }
        }
        break;
    case 4:
        *(f32*)sub = lbl_803E4B1C * timeDelta + *(f32*)sub;
        {
            f32 v = *(f32*)sub;
            if (v < lbl_803E4B20)
            {
                *(f32*)sub = *(f32*)&lbl_803E4B20;
            }
        }
        ((GameObject*)obj)->anim.localPosY = *(f32*)sub * timeDelta + ((GameObject*)obj)->anim.localPosY;
        if (((GameObject*)obj)->anim.localPosY < ((Dll1DBPlacement*)state)->unkC - lbl_803E4B24)
        {
            Sfx_PlayFromObject(obj, SFXchar_on_firelp);
            ((GameObject*)obj)->anim.localPosY = ((Dll1DBPlacement*)state)->unkC - lbl_803E4B24;
            ((Dll1DBState*)sub)->unk4 = 2;
            GameBit_Set(((Dll1DBPlacement*)state)->unk1E, 1);
        }
        if (*(u8*)(sub + 5) == 0)
        {
            if (GameBit_Get(((Dll1DBPlacement*)state)->unk20) == 0)
            {
                ((Dll1DBState*)sub)->unk4 = 3;
                GameBit_Set(((Dll1DBPlacement*)state)->unk1E, 0);
            }
        }
        break;
    }
}

/* dll_1DA_update: rolling-rock physics -- damp velocity, bounce off geometry normal,
 * fall, land on contact object, clamp to floor height. */

void dll_1DA_update(int obj);

/* fn_801B9ECC: DIM boss player-vs-baddie reaction dispatcher -- picks a player anim
 * from distance/anim-state via the interface vtables. */

int dll_1DB_getExtraSize(void) { return 0x8; }
int dll_1DB_getObjectTypeId(void) { return 0x0; }
int dim2icefloe_getExtraSize(void);

void dll_1DB_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4B08);
}

void dim2icefloe_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

/* dll_1DF_init: similar romlist param init, but reads three u8 fields, packs to s16
 *              fields, and on a u8 flag does a u32->f32 conversion (MWCC emits the
 *              magic-2^52 trick using a 2^52 constant) to scale obj[0x50]->f4 into
 *              obj[8]. Also sets obj[0xB8]->f10 from a constant and OR-merges flags
 *              into obj[0x64]->u32_30 (0x810) and obj[0xB0]'s u16 (0x2000). */

/* dim2lavacontrol_setScale: every-frame tick -- if not already "armed" (bit 0 of
 *   sub.b2 is clear), decrement sub.b0 counter; when it hits 0 set the armed bit
 *   and tell the game-event tracker (via param.s16_1E) that this trigger fired. */

/* dll_1DF_update: per-frame texture-color update + proximity-driven expgfx trigger.
 *   - objFindTexture(obj,0,0); if non-null and obj.s16_46 == 209 set tex.color
 *     (bytes 0xC..0xE) to (u8)(int)lbl_803E4B9C via three independent fctiwz casts,
 *     else do the same dest writes (different scheduling).
 *   - Then if (distance^2 from player to obj position < lbl_803E4BA0) and sub.f24
 *     decremented by timeDelta is < lbl_803E4B9C, call gPartfxInterface->vt[2] with
 *     (obj, 525, 0, 2, -1, 0) and reset sub.f24 to lbl_803E4BA4. */

/* dll_1DB_init: read romlist params, set s16 at obj[0] and a u8 flag on obj->sub_B8
 *              from a GameBit, and OR-set bit 0x2000 in obj->flags_B0. */
void dll_1DB_init(void* obj, void* p)
{
    void* sub = ((GameObject*)obj)->extra;
    s16 t = (s16)((s32) * (s8*)((char*)p + 0x18) << 8);
    ((GameObject*)obj)->anim.rotX = t;
    if (GameBit_Get(*(s16*)((char*)p + 0x1E)) != 0)
    {
        ((Dll1DBState*)sub)->unk4 = 2;
    }
    else
    {
        ((Dll1DBState*)sub)->unk4 = 1;
    }
    ((GameObject*)obj)->objectFlags |= 0x2000;
}
