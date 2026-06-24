/*
 * ccsharpclawpad - Crystal Caves SharpClaw "pressure pad" object (DLL
 * 0x0189). A disguise-gated switch pad. Its placement gameBit (at
 * placementData+0x1A) records whether it has been activated: once set it
 * stays lit (active hitbox bit 8 on) and emits the lit particle burst.
 * While unset it shows help text (gated by an ObjTrigger and a hold timer)
 * and watches for a disguised player to step close - that plays a stomp sfx,
 * sets the gameBit and lights the pad.
 */
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
#include "main/audio/sfx.h"
extern f32 timeDelta;
extern int ObjTrigger_IsSet(int obj);
extern f32 vec3f_distanceSquared(f32* a, f32* b);
extern int playerIsDisguised(int obj);

extern void objfx_spawnArcedBurst(int obj, int enabled, f32 radius, int particleKind,
                                  int particleId, int lifetime, f32 scaleX, f32 scaleY,
                                  f32 scaleZ, void* args, int arg9);

extern f32 lbl_803E46A8; /* particle offset x */
extern f32 lbl_803E46AC; /* particle offset y / alt x */
extern f32 lbl_803E46B0; /* particle offset z / help-text hold floor */
extern f32 lbl_803E46B4; /* burst radius */
extern f32 lbl_803E46B8; /* burst scale */
extern f32 lbl_803E46BC; /* burst scale z */
extern f32 lbl_803E46C0; /* help-text hold reset value */
extern f32 lbl_803E46C4; /* squared activation distance */

typedef struct SharpClawPadParticleArgs
{
    u8 pad00[0xc];   /* 0x00: filled in by objfx_spawnArcedBurst, not written here */
    f32 offset[3];   /* 0x0C: emitter offset x/y/z */
} SharpClawPadParticleArgs;

STATIC_ASSERT(offsetof(SharpClawPadParticleArgs, offset) == 0xC);
STATIC_ASSERT(sizeof(SharpClawPadParticleArgs) == 0x18);

int ccsharpclawpad_getExtraSize(void) { return 0x4; }

#pragma scheduling off
#pragma peephole off
void ccsharpclawpad_init(int* obj, int* placement)
{
    ((GameObject*)obj)->anim.rotX = (s16)((u32) * (u8*)((char*)placement + 24) << 8);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x4000);
}

void ccsharpclawpad_update(int obj)
{
    SharpClawPadParticleArgs particleArgs;
    f32* state;
    int* player;

    if (GameBit_Get(*(s16*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x1a)) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        particleArgs.offset[0] = lbl_803E46A8;
        particleArgs.offset[1] = lbl_803E46AC;
        particleArgs.offset[2] = lbl_803E46B0;
        objfx_spawnArcedBurst(obj, 5, lbl_803E46B4, 2, 2, 0x19, lbl_803E46B8,
                              *(f32*)&lbl_803E46B8, lbl_803E46BC, &particleArgs, 0);
        particleArgs.offset[0] = lbl_803E46AC;
        objfx_spawnArcedBurst(obj, 5, lbl_803E46B4, 2, 2, 0x19, lbl_803E46B8,
                              *(f32*)&lbl_803E46B8, lbl_803E46BC, &particleArgs, 0);
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
        if (GameBit_Get(0x40) == 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
        state = ((GameObject*)obj)->extra;
        if (ObjTrigger_IsSet(obj) != 0 && fn_801334E0() == 0)
        {
            *state = lbl_803E46C0;
        }
        if (*state > lbl_803E46B0)
        {
            if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) == 0)
            {
                *state = lbl_803E46B0;
            }
            else
            {
                *state -= timeDelta;
                showHelpText(((GameObject*)obj)->anim.modelInstance->helpTextIds[0]);
            }
        }
        player = Obj_GetPlayerObject();
        if (vec3f_distanceSquared(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) <
            lbl_803E46C4
            && playerIsDisguised((int)player) != 0)
        {
            Sfx_PlayFromObject(obj, 0x109);
            GameBit_Set(*(s16*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x1a), 1);
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        }
        particleArgs.offset[0] = lbl_803E46A8;
        particleArgs.offset[1] = lbl_803E46AC;
        particleArgs.offset[2] = lbl_803E46B0;
        objfx_spawnArcedBurst(obj, 5, lbl_803E46B4, 5, 2, 0x19, lbl_803E46B8,
                              *(f32*)&lbl_803E46B8, lbl_803E46BC, &particleArgs, 0);
        particleArgs.offset[0] = lbl_803E46AC;
        objfx_spawnArcedBurst(obj, 5, lbl_803E46B4, 5, 2, 0x19, lbl_803E46B8,
                              *(f32*)&lbl_803E46B8, lbl_803E46BC, &particleArgs, 0);
    }
}
