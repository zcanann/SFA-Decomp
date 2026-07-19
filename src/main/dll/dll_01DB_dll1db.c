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
 *                     topPosY - 235.5f, then latches STATE_BOTTOM.
 * Player contact is detected by scanning the contact-object list at obj+0x58
 * for the player object. Motion constants live in the 0.0f..B24 pool;
 * 1.0f is the render LOD/scale passed to objRenderModelAndHitVolumes.
 *
 * dll_1DB_init reads the romlist placement (rotXByte at 0x18, and the boardedBit
 * at 0x1E whose game-bit value selects the initial up/down rest state) and sets
 * object flag 0x2000.
 */
#include "main/dll/dim2conveyorstate_struct.h"
#include "main/object_render.h"
#include "main/dll/dim2pathgeneratorstate_struct.h"
#include "main/dll/dim2snowballstate_struct.h"
#include "main/dll/dll1d6state_struct.h"
#include "main/dll/truthhornicestate_struct.h"
#include "main/game_object.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/gamebits.h"
#include "main/frame_timing.h"
#include "main/object_api.h"
#include "main/object_descriptor.h"

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
    s8 rotXByte; /* 0x18: seeds anim.rotX in dll_1DB_init */
    u8 pad19[0x1E - 0x19];
    s16 boardedBit; /* 0x1E: game bit selecting the initial rest state / set while a player rides */
    s16 triggerBit; /* 0x20: external trigger that releases the platform */
    u8 pad22[0x28 - 0x22];
} Dll1DBPlacement;

typedef struct Dll1DBState
{
    f32 velocity;       /* 0x00 */
    u8 state;           /* 0x04: STATE_* */
    u8 boardedFlag;     /* 0x05 */
    u8 contactLostFlag; /* 0x06 */
    u8 pad7;
} Dll1DBState;

STATIC_ASSERT(offsetof(Dll1DBPlacement, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(Dll1DBPlacement, boardedBit) == 0x1E);
STATIC_ASSERT(sizeof(Dll1DBState) == 0x8);
STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);
STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);
STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);
STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);
STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);

#define DLL1DB_OBJFLAG_HITDETECT_DISABLED 0x2000

enum
{
    STATE_TOP = 1,
    STATE_BOTTOM = 2,
    STATE_RISING = 3,
    STATE_FALLING = 4
};



int dll_1DB_getExtraSize(void)
{
    return 0x8;
}
int dll_1DB_getObjectTypeId(void)
{
    return 0x0;
}

void dll_1DB_free(void)
{
}

void dll_1DB_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void dll_1DB_hitDetect(void)
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
            Sfx_PlayFromObject(obj, SFXTRIG_mv_wickpickup16);
            ((Dll1DBState*)sub)->state = STATE_FALLING;
            ((Dll1DBState*)sub)->velocity = 0.0f;
        }
        if (mainGetBit(((Dll1DBPlacement*)state)->triggerBit) != 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_mv_wickpickup16);
            ((Dll1DBState*)sub)->state = STATE_FALLING;
            ((Dll1DBState*)sub)->velocity = 0.0f;
        }
        break;
    case STATE_BOTTOM:
        Sfx_StopObjectChannel(obj, 8);
        if (((Dll1DBState*)sub)->boardedFlag != 0)
        {
            if (found == 0)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_mv_wickpickup16);
                ((Dll1DBState*)sub)->state = STATE_RISING;
                ((Dll1DBState*)sub)->velocity = 0.0f;
                ((Dll1DBState*)sub)->boardedFlag = 0;
                mainSetBits(((Dll1DBPlacement*)state)->boardedBit, 0);
            }
        }
        else
        {
            if (mainGetBit(((Dll1DBPlacement*)state)->triggerBit) == 0)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_mv_wickpickup16);
                ((Dll1DBState*)sub)->state = STATE_RISING;
                ((Dll1DBState*)sub)->velocity = 0.0f;
                ((Dll1DBState*)sub)->boardedFlag = 0;
                mainSetBits(((Dll1DBPlacement*)state)->boardedBit, 0);
            }
        }
        break;
    case STATE_RISING:
        ((Dll1DBState*)sub)->velocity =
            ((Dll1DBState*)sub)->velocity +
            (0.02f * timeDelta + 0.1f * (f32)(s32)(((Dll1DBState*)sub)->velocity < 0.0f));
        {
            f32 v = ((Dll1DBState*)sub)->velocity;
            if (v > 1.5f)
            {
                ((Dll1DBState*)sub)->velocity = 1.5f;
            }
        }
        ((GameObject*)obj)->anim.localPosY =
            ((Dll1DBState*)sub)->velocity * timeDelta + ((GameObject*)obj)->anim.localPosY;
        if (((GameObject*)obj)->anim.localPosY > ((Dll1DBPlacement*)state)->topPosY)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_en_lflsh2_b);
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
        ((Dll1DBState*)sub)->velocity = -0.02f * timeDelta + ((Dll1DBState*)sub)->velocity;
        {
            f32 v = ((Dll1DBState*)sub)->velocity;
            if (v < -1.5f)
            {
                ((Dll1DBState*)sub)->velocity = -1.5f;
            }
        }
        ((GameObject*)obj)->anim.localPosY =
            ((Dll1DBState*)sub)->velocity * timeDelta + ((GameObject*)obj)->anim.localPosY;
        if (((GameObject*)obj)->anim.localPosY < ((Dll1DBPlacement*)state)->topPosY - 235.5f)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_en_lflsh2_b);
            ((GameObject*)obj)->anim.localPosY = ((Dll1DBPlacement*)state)->topPosY - 235.5f;
            ((Dll1DBState*)sub)->state = STATE_BOTTOM;
            mainSetBits(((Dll1DBPlacement*)state)->boardedBit, 1);
        }
        if (((Dll1DBState*)sub)->boardedFlag == 0)
        {
            if (mainGetBit(((Dll1DBPlacement*)state)->triggerBit) == 0)
            {
                ((Dll1DBState*)sub)->state = STATE_RISING;
                mainSetBits(((Dll1DBPlacement*)state)->boardedBit, 0);
            }
        }
        break;
    }
}

void dll_1DB_init(GameObject* obj, void* p)
{
    void* sub = obj->extra;
    s16 t = (s16)((s32)((Dll1DBPlacement*)p)->rotXByte << 8);
    obj->anim.rotX = t;
    if (mainGetBit(((Dll1DBPlacement*)p)->boardedBit) != 0)
    {
        ((Dll1DBState*)sub)->state = STATE_BOTTOM;
    }
    else
    {
        ((Dll1DBState*)sub)->state = STATE_TOP;
    }
    obj->objectFlags |= DLL1DB_OBJFLAG_HITDETECT_DISABLED;
}

void dll_1DB_release(void)
{
}

void dll_1DB_initialise(void)
{
}

ObjectDescriptor dll_1DB = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_1DB_initialise,
    (ObjectDescriptorCallback)dll_1DB_release,
    0,
    (ObjectDescriptorCallback)dll_1DB_init,
    (ObjectDescriptorCallback)dll_1DB_update,
    (ObjectDescriptorCallback)dll_1DB_hitDetect,
    (ObjectDescriptorCallback)dll_1DB_render,
    (ObjectDescriptorCallback)dll_1DB_free,
    (ObjectDescriptorCallback)dll_1DB_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)dll_1DB_getExtraSize,
};
