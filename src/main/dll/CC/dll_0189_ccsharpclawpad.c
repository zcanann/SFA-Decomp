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
#include "main/audio/sfx_trigger_ids.h"
#define CCSHARPCLAWPAD_OBJFLAG_HIDDEN 0x4000
extern f32 timeDelta;
extern int ObjTrigger_IsSet(int obj);
extern f32 vec3f_distanceSquared(f32* a, f32* b);
extern int playerIsDisguised(int obj);

extern void objfx_spawnArcedBurst(int obj, int enabled, f32 radius, int particleKind,
                                  int particleId, int lifetime, f32 scaleX, f32 scaleY,
                                  f32 scaleZ, void* args, int arg9);

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
void ccsharpclawpad_update(int obj)
{
    SharpClawPadParticleArgs particleArgs;
    f32* state;
    int* player;

    if (GameBit_Get(*(s16*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x1a)) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        particleArgs.offset[0] = -5.0f;
        particleArgs.offset[1] = 5.0f;
        particleArgs.offset[2] = 0.0f;
        objfx_spawnArcedBurst(obj, 5, 0.75f, 2, 2, 0x19, 2.0f,
                              2.0f, 10.0f, &particleArgs, 0);
        particleArgs.offset[0] = 5.0f;
        objfx_spawnArcedBurst(obj, 5, 0.75f, 2, 2, 0x19, 2.0f,
                              2.0f, 10.0f, &particleArgs, 0);
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
            *state = 600.0f;
        }
        if (*state > 0.0f)
        {
            if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) == 0)
            {
                *state = 0.0f;
            }
            else
            {
                *state -= timeDelta;
                showHelpText(((GameObject*)obj)->anim.modelInstance->helpTextIds[0]);
            }
        }
        player = Obj_GetPlayerObject();
        if (vec3f_distanceSquared(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) <
            100.0f
            && playerIsDisguised((int)player) != 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_menuups16k);
            GameBit_Set(*(s16*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x1a), 1);
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        }
        particleArgs.offset[0] = -5.0f;
        particleArgs.offset[1] = 5.0f;
        particleArgs.offset[2] = 0.0f;
        objfx_spawnArcedBurst(obj, 5, 0.75f, 5, 2, 0x19, 2.0f,
                              2.0f, 10.0f, &particleArgs, 0);
        particleArgs.offset[0] = 5.0f;
        objfx_spawnArcedBurst(obj, 5, 0.75f, 5, 2, 0x19, 2.0f,
                              2.0f, 10.0f, &particleArgs, 0);
    }
}

void ccsharpclawpad_init(int* obj, int* placement)
{
    ((GameObject*)obj)->anim.rotX = (s16)((u32) * (u8*)((char*)placement + 24) << 8);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | CCSHARPCLAWPAD_OBJFLAG_HIDDEN);
}
