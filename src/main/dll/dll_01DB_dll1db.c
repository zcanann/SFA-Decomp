/*
 * DLL 0x1DB - DIM2 rising/lowering crusher-platform object.
 *
 * A platform that moves vertically between a bottom rest position and a top
 * position (placement->topPosY). It is driven by a 4-state machine on
 * state->state:
 *   STATE_TOP    (1): held at the top; drops when no player is standing on it
 *                     and the contact flag is set, or when the trigger game bit
 *                     (placement->triggerBit) becomes set.
 *   STATE_BOTTOM (2): held at the bottom; rises again when a player boards or
 *                     the trigger bit clears.
 *   STATE_RISING (3): integrates upward velocity until localPosY reaches
 *                     topPosY, then latches STATE_TOP.
 *   STATE_FALLING(4): integrates downward velocity until localPosY reaches
 *                     topPosY - lbl_803E4B24, then latches STATE_BOTTOM.
 * Player contact is detected by scanning the contact-object list at obj+0x58
 * for the player object. Motion constants live in the lbl_803E4B0C..B24 pool;
 * lbl_803E4B08 is the render LOD/scale passed to objRenderModelAndHitVolumes.
 *
 * dll_1DB_init reads the romlist placement (rotXByte at 0x18, and the boardedBit
 * at 0x1E whose game-bit value selects the initial up/down rest state) and sets
 * object flag 0x2000.
 */
#include "main/dll/dim2conveyorstate_struct.h"
#include "main/dll/dim2pathgeneratorstate_struct.h"
#include "main/dll/dim2snowballstate_struct.h"
#include "main/dll/dll1d6state_struct.h"
#include "main/dll/truthhornicestate_struct.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/gamebits.h"
#include "main/dll/fx_800944A0_shared.h"

#define DLL1DB_OBJFLAG_HITDETECT_DISABLED 0x2000

STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);
STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);
STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);
STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);
STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);

extern void Sfx_StopObjectChannel(int obj, int channel);
extern void Sfx_PlayFromObject(u32 obj, u16 sfxId);

extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern f32 lbl_803E4B08; /* render scale */
extern f32 lbl_803E4B0C;
extern f32 lbl_803E4B10;
extern f32 lbl_803E4B14;
extern f32 lbl_803E4B18;
extern f32 lbl_803E4B1C;
extern f32 lbl_803E4B20;
extern f32 lbl_803E4B24;

enum
{
    STATE_TOP = 1,
    STATE_BOTTOM = 2,
    STATE_RISING = 3,
    STATE_FALLING = 4
};

typedef struct Dll1DBPlacement
{
    u8 pad0[0x1 - 0x0];
    u8 unk1;
    u8 pad2[0x3 - 0x2];
    u8 unk3;
    u8 unk4;
    u8 pad5[0xC - 0x5];
    f32 topPosY; /* 0x0C */
    u8 pad10[0x18 - 0x10];
    s8 rotXByte;     /* 0x18: seeds anim.rotX in dll_1DB_init */
    u8 pad19[0x1E - 0x19];
    s16 boardedBit;  /* 0x1E: game bit selecting the initial rest state / set while a player rides */
    s16 triggerBit;  /* 0x20: external trigger that releases the platform */
    u8 pad22[0x28 - 0x22];
} Dll1DBPlacement;

STATIC_ASSERT(offsetof(Dll1DBPlacement, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(Dll1DBPlacement, boardedBit) == 0x1E);

typedef struct Dll1DBState
{
    f32 velocity;        /* 0x00 */
    u8 state;            /* 0x04: STATE_* */
    u8 boardedFlag;      /* 0x05 */
    u8 contactLostFlag;  /* 0x06 */
    u8 pad7;
} Dll1DBState;

STATIC_ASSERT(sizeof(Dll1DBState) == 0x8);

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

void dll_1DB_update(int obj)
{
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
    switch (((Dll1DBState*)sub)->state)
    {
    case STATE_TOP:
        Sfx_StopObjectChannel(obj, 8);
        if (found == 0)
        {
            ((Dll1DBState*)sub)->contactLostFlag = 1;
        }
        else if (((Dll1DBState*)sub)->contactLostFlag != 0 && ((Dll1DBState*)sub)->boardedFlag != 0)
        {
            Sfx_PlayFromObject(obj, SFXsp_lfoot_taunt3);
            ((Dll1DBState*)sub)->state = STATE_FALLING;
            ((Dll1DBState*)sub)->velocity = lbl_803E4B0C;
        }
        if (GameBit_Get(((Dll1DBPlacement*)state)->triggerBit) != 0)
        {
            Sfx_PlayFromObject(obj, SFXsp_lfoot_taunt3);
            ((Dll1DBState*)sub)->state = STATE_FALLING;
            ((Dll1DBState*)sub)->velocity = lbl_803E4B0C;
        }
        break;
    case STATE_BOTTOM:
        Sfx_StopObjectChannel(obj, 8);
        if (((Dll1DBState*)sub)->boardedFlag != 0)
        {
            if (found == 0)
            {
                Sfx_PlayFromObject(obj, SFXsp_lfoot_taunt3);
                ((Dll1DBState*)sub)->state = STATE_RISING;
                ((Dll1DBState*)sub)->velocity = lbl_803E4B0C;
                ((Dll1DBState*)sub)->boardedFlag = 0;
                GameBit_Set(((Dll1DBPlacement*)state)->boardedBit, 0);
            }
        }
        else
        {
            if (GameBit_Get(((Dll1DBPlacement*)state)->triggerBit) == 0)
            {
                Sfx_PlayFromObject(obj, SFXsp_lfoot_taunt3);
                ((Dll1DBState*)sub)->state = STATE_RISING;
                ((Dll1DBState*)sub)->velocity = lbl_803E4B0C;
                ((Dll1DBState*)sub)->boardedFlag = 0;
                GameBit_Set(((Dll1DBPlacement*)state)->boardedBit, 0);
            }
        }
        break;
    case STATE_RISING:
        ((Dll1DBState*)sub)->velocity = ((Dll1DBState*)sub)->velocity + (lbl_803E4B10 * timeDelta +
            lbl_803E4B14 * (f32)(s32)(((Dll1DBState*)sub)->velocity < lbl_803E4B0C));
        {
            f32 v = ((Dll1DBState*)sub)->velocity;
            if (v > lbl_803E4B18)
            {
                ((Dll1DBState*)sub)->velocity = *(f32*)&lbl_803E4B18;
            }
        }
        ((GameObject*)obj)->anim.localPosY = ((Dll1DBState*)sub)->velocity * timeDelta + ((GameObject*)obj)->anim.localPosY;
        if (((GameObject*)obj)->anim.localPosY > ((Dll1DBPlacement*)state)->topPosY)
        {
            Sfx_PlayFromObject(obj, SFXchar_on_firelp);
            ((GameObject*)obj)->anim.localPosY = ((Dll1DBPlacement*)state)->topPosY;
            ((Dll1DBState*)sub)->state = STATE_TOP;
            if (found != 0)
            {
                ((Dll1DBState*)sub)->boardedFlag = 1;
                ((Dll1DBState*)sub)->contactLostFlag = 0;
            }
        }
        break;
    case STATE_FALLING:
        ((Dll1DBState*)sub)->velocity = lbl_803E4B1C * timeDelta + ((Dll1DBState*)sub)->velocity;
        {
            f32 v = ((Dll1DBState*)sub)->velocity;
            if (v < lbl_803E4B20)
            {
                ((Dll1DBState*)sub)->velocity = *(f32*)&lbl_803E4B20;
            }
        }
        ((GameObject*)obj)->anim.localPosY = ((Dll1DBState*)sub)->velocity * timeDelta + ((GameObject*)obj)->anim.localPosY;
        if (((GameObject*)obj)->anim.localPosY < ((Dll1DBPlacement*)state)->topPosY - lbl_803E4B24)
        {
            Sfx_PlayFromObject(obj, SFXchar_on_firelp);
            ((GameObject*)obj)->anim.localPosY = ((Dll1DBPlacement*)state)->topPosY - lbl_803E4B24;
            ((Dll1DBState*)sub)->state = STATE_BOTTOM;
            GameBit_Set(((Dll1DBPlacement*)state)->boardedBit, 1);
        }
        if (((Dll1DBState*)sub)->boardedFlag == 0)
        {
            if (GameBit_Get(((Dll1DBPlacement*)state)->triggerBit) == 0)
            {
                ((Dll1DBState*)sub)->state = STATE_RISING;
                GameBit_Set(((Dll1DBPlacement*)state)->boardedBit, 0);
            }
        }
        break;
    }
}

int dll_1DB_getExtraSize(void) { return 0x8; }
int dll_1DB_getObjectTypeId(void) { return 0x0; }

void dll_1DB_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E4B08);
}

void dll_1DB_init(void* obj, void* p)
{
    void* sub = ((GameObject*)obj)->extra;
    s16 t = (s16)((s32)((Dll1DBPlacement*)p)->rotXByte << 8);
    ((GameObject*)obj)->anim.rotX = t;
    if (GameBit_Get(((Dll1DBPlacement*)p)->boardedBit) != 0)
    {
        ((Dll1DBState*)sub)->state = STATE_BOTTOM;
    }
    else
    {
        ((Dll1DBState*)sub)->state = STATE_TOP;
    }
    ((GameObject*)obj)->objectFlags |= DLL1DB_OBJFLAG_HITDETECT_DISABLED;
}
