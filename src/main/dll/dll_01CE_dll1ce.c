/*
 * dll_1CE: hatch-door object. The lid coasts open under a clamped velocity
 * while idle; once a key object (seqId 0x18F or 0x1D6) is in range it counts
 * down, sets its placement gamebit, and - if the load isn't locked and the
 * placement's spawnGameBitValue matches gamebit 0x46D - spawns its contents object
 * (subtype 0x246) seeded from the door's transform.
 *
 * The TU also hosts dimmagicbridge_* and explosion_* sibling exports (in
 * DIM/dll_01CC_dimmagicbridge.c / DIM/dll_01CA_dimexplosion.c); their forward
 * declarations and the descriptor that combines them live in this object's DLL.
 */
#include "main/dll/dimmagicbridge_state.h"
#include "main/dll/dll1ceplacement_struct.h"
#include "main/dll/fnexplosionreleasev11unusedstate_struct.h"
#include "main/dll/dimwooddoor2state_struct.h"
#include "main/dll/fbwgpipe_struct.h"
#include "main/dll/dll1cestate_struct.h"
#include "main/dll/explosionpartfxsource_struct.h"
#include "main/dll/explosion_state.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/objseq.h"
#include "main/resource.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"

#define DLL1CE_OBJFLAG_HITDETECT_DISABLED 0x2000

/*
 * Per-object extra state for the dimwooddoor2 burnable door
 * (dimwooddoor2_getExtraSize == 0xC).
 */

STATIC_ASSERT(sizeof(DimWoodDoor2State) == 0xC);

/*
 * Per-object extra state for the dll_1CE hatch door
 * (dll_1CE_getExtraSize == 0xC).
 */

STATIC_ASSERT(sizeof(Dll1CEState) == 0xC);

/*
 * Per-object extra state for the dimmagicbridge flame bridge
 * (dimmagicbridge_getExtraSize == 0x68). init/SeqFn here, dll_199/19A
 * variants in dimmagicbridge.c use their own layout.
 */

STATIC_ASSERT(sizeof(DimMagicBridgeState) == 0x68);

STATIC_ASSERT(sizeof(ExplosionPartfxSource) == 0x38);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, rootMotionScale) == 0x08);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, localPosX) == 0x0C);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, worldPosX) == 0x18);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, velocityX) == 0x24);

/*
 * Per-object extra state for the explosion effect
 * (explosion_getExtraSize == 0xA60). The flame pool (50 x 0x30 records)
 * and the debris pool (6 x 0x24 at 0x964) are walked with raw stride
 * pointers in update/render and stay untyped.
 */

STATIC_ASSERT(sizeof(ExplosionState) == 0xA60);
STATIC_ASSERT(offsetof(ExplosionState, driftYSpeed) == 0xA3C);

extern u32 DAT_803dc070;
extern f32 lbl_803DC074;
extern f32 lbl_803DE7EC;
extern f32 lbl_803DE7F0;
extern f32 lbl_803E55C4;
extern f32 lbl_803E55C8;
extern f32 lbl_803E55D0;
extern f32 lbl_803E55D8;
extern f32 lbl_803E566C;
extern f32 lbl_803E5670;
extern f32 lbl_803E5674;
extern f32 lbl_803E5678;
extern f32 lbl_803E567C;
extern f32 lbl_803E569C;
extern f32 lbl_803E49E8;
extern void* lbl_803DDB78;
extern f32 lbl_803E49F0;
extern f32 timeDelta;
extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern void Obj_SetupObject(int* obj, int a, int b, int c, int d);
extern f32 lbl_803E49EC;
extern f32 lbl_803E49F4;
extern f32 lbl_803E49F8;
extern f32 lbl_803E49FC;

/* Spawn-setup buffer seeded by dll_1CE_update for its child (obj id 0x246):
 * position/color head plus class-specific fields (see the target stb/sth). */
typedef struct Dll1CESpawnSetup
{
    u8 pad0[0x4 - 0x0];
    u8 color[4];             /* 0x04 */
    f32 posX;                /* 0x08 */
    f32 posY;                /* 0x0c */
    f32 posZ;                /* 0x10 */
    u8 pad14[0x1a - 0x14];
    u8 field1A;              /* 0x1a */
    u8 field1B;              /* 0x1b */
    s16 field1C;             /* 0x1c */
    u8 pad1E[0x24 - 0x1e];
    s16 field24;             /* 0x24 */
    u8 pad26[0x2c - 0x26];
    s16 field2C;             /* 0x2c */
} Dll1CESpawnSetup;



void dll_1CE_hitDetect(void)
{
}

void dll_1CE_release(void)
{
}

void dll_1CE_initialise(void)
{
}


int dll_1CE_getExtraSize(void) { return 0xc; }
int dll_1CE_getObjectTypeId(void) { return 0x0; }
int dimmagicbridge_getExtraSize(void);

#pragma peephole off
void dll_1CE_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E49E8);
}


#pragma peephole on
void dll_1CE_free(void)
{
    if (lbl_803DDB78 != NULL)
    {
        Resource_Release(lbl_803DDB78);
    }
    lbl_803DDB78 = NULL;
}

/* dimwooddoor2 variant: trigger-init that loads a different float
 * (lbl_803E49F0) into the extra block's [4]. */

/* dimmagicbridge_update: advance texture phase and bridge vertex wave, then
 * either fire the death VFX (fn_80065574(0x11, 0, 0)) when sub->_5f is set or,
 * when GameBit 0x1ef is on and the player's emission controller is lingering,
 * latch GameBit 0x1e8. */

/* dimwooddoor2 variant: trigger-init writing extra block [4]=[8]=lbl_803E49D4
 * and using mask 0x6000 + initial state byte 3 at +0. */

#pragma scheduling off
#pragma peephole off
void dll_1CE_init(u8* obj, u8* params)
{
    Dll1CEState* sub;
    ObjHitsPriorityState* hitState;
    *(s16*)obj = (s16)(((s16)(s8)params[0x18]) << 8
    )
    ;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | DLL1CE_OBJFLAG_HITDETECT_DISABLED);
    sub = ((GameObject*)obj)->extra;
    sub->igniteCountdown = 1;
    if (GameBit_Get(((Dll1CEPlacement*)params)->gameBitId) != 0)
    {
        sub->igniteCountdown = 0;
        hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        hitState->flags &= ~1;
        ((GameObject*)obj)->anim.alpha = 0;
    }
    sub->openVelocity = lbl_803E49F0;
}


/* dimmagicbridge_scrollTextureChannels: scroll two material channels and keep
 * the bridge wave phases in sub[0x60]/sub[0x62] moving with framesThisStep. */
#pragma dont_inline on
#pragma dont_inline reset

/* dimmagicbridge_flameSeqFn: tick the spawn timer, allocate a free flame slot
 * every 16 frames, and ramp each active slot's alpha toward full; then update
 * the animated bridge mesh. */

/* EN v1.0 0x801B5AA0  size: 496b  dll_1CE_update: hatch-door logic - coast
 * the lid open with clamped velocity while idle, and once a key object is
 * nearby, count down then ring the gamebit and (if the load isn't locked)
 * spawn the contents object seeded from the door's transform. */
#pragma opt_strength_reduction off
void dll_1CE_update(int* obj)
{
    int* q = *(int**)&((GameObject*)obj)->anim.placementData;
    Dll1CEState* sub = ((GameObject*)obj)->extra;
    ObjHitsPriorityState* hitState;
    if (((GameObject*)obj)->anim.alpha == 0) return;
    if ((s8)sub->igniteCountdown <= 0)
    {
        hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        hitState->flags &= ~1;
        if (sub->opened == 1)
        {
            sub->openProgress = sub->openVelocity * timeDelta + sub->openProgress;
            if (sub->openProgress > lbl_803E49EC)
            {
                sub->openProgress = lbl_803E49EC;
                sub->openVelocity = lbl_803E49F0;
            }
            else if (sub->openProgress < lbl_803E49F4)
            {
                sub->openProgress = lbl_803E49F4;
                sub->openVelocity = lbl_803E49F8;
            }
        }
    }
    if (((GameObject*)obj)->anim.seqId == 0x334) return;
    {
        int off;
        int i;
        int* list;
        int n;
        int found = 0;
        off = 0;
        list = *(int**)((char*)obj + 0x58);
        n = (s8) * (s8*)((char*)list + 0x10f);
        for (i = 0; i < n; i++)
        {
            int* o = *(int**)((char*)list + off + 0x100);
            if (*(s16*)((char*)o + 0x46) == 0x18f || *(s16*)((char*)o + 0x46) == 0x1d6)
            {
                found = 1;
                break;
            }
            off += 4;
        }
        if (!found) return;
    }
    {
        if ((s8)(sub->igniteCountdown -= 1) > 0) return;
    }
    GameBit_Set(((Dll1CEPlacement*)q)->gameBitId, 1);
    sub->opened = 1;
    if ((u32)(s16)((Dll1CEPlacement*)q)->spawnGameBitValue != GameBit_Get(0x46d)) return;
    if (Obj_IsLoadingLocked() == 0) return;
    {
        int* no = Obj_AllocObjectSetup(0x30, 0x246);
        ((Dll1CESpawnSetup*)no)->posX = ((Dll1CEPlacement*)q)->posX;
        ((Dll1CESpawnSetup*)no)->posY = lbl_803E49FC + ((Dll1CEPlacement*)q)->posYOffset;
        ((Dll1CESpawnSetup*)no)->posZ = ((Dll1CEPlacement*)q)->posZ;
        ((Dll1CESpawnSetup*)no)->color[0] = ((Dll1CEPlacement*)q)->unk4;
        ((Dll1CESpawnSetup*)no)->color[1] = ((Dll1CEPlacement*)q)->unk5;
        ((Dll1CESpawnSetup*)no)->color[2] = ((Dll1CEPlacement*)q)->unk6;
        ((Dll1CESpawnSetup*)no)->color[3] = ((Dll1CEPlacement*)q)->unk7;
        ((Dll1CESpawnSetup*)no)->field1C = 0x17f;
        ((Dll1CESpawnSetup*)no)->field24 = -1;
        ((Dll1CESpawnSetup*)no)->field2C = -1;
        ((Dll1CESpawnSetup*)no)->field1A = 5;
        ((Dll1CESpawnSetup*)no)->field1B = (u8)((s16)((GameObject*)obj)->anim.rotX >> 8);
        Obj_SetupObject(no, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, 0);
    }
}
#pragma opt_strength_reduction reset

FbWGPipe GXWGFifo : (0xCC008000);
