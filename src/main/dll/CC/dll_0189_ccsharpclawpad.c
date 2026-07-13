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
#include "main/objfx.h"
#include "main/obj_trigger.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/dll/CC/dll_0189_ccsharpclawpad.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/minimap_api.h"
#include "main/vecmath_distance_api.h"

#define CCSHARPCLAWPAD_OBJFLAG_HIDDEN 0x4000

extern int playerIsDisguised(int obj);

int CCSharpclawPad_getExtraSize(void)
{
    return 0x4;
}

#pragma scheduling off
#pragma peephole off
void CCSharpclawPad_update(GameObject* obj)
{
    SharpClawPadParticleArgs particleArgs;
    f32* state;
    GameObject* player;

    if (mainGetBit(*(s16*)(*(int*)&(obj)->anim.placementData + 0x1a)) != 0)
    {
        *(u8*)&(obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        particleArgs.offset[0] = -5.0f;
        particleArgs.offset[1] = 5.0f;
        particleArgs.offset[2] = 0.0f;
        objfx_spawnArcedBurstLegacy((int)obj, 5, 0.75f, 2, 2, 0x19, 2.0f, 2.0f, 10.0f, &particleArgs, 0);
        particleArgs.offset[0] = 5.0f;
        objfx_spawnArcedBurstLegacy((int)obj, 5, 0.75f, 2, 2, 0x19, 2.0f, 2.0f, 10.0f, &particleArgs, 0);
    }
    else
    {
        *(u8*)&(obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
        if (mainGetBit(GAMEBIT_STAFF_ABILITY_SHARPCLAW_DISGUISE) == 0)
        {
            *(u8*)&(obj)->anim.resetHitboxMode |= INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
        else
        {
            *(u8*)&(obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
        state = (obj)->extra;
        if (ObjTrigger_IsSet((int)obj) != 0 && isAreaNameTextActive() == 0)
        {
            *state = 600.0f;
        }
        if (*state > 0.0f)
        {
            if ((*(u8*)&(obj)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) == 0)
            {
                *state = 0.0f;
            }
            else
            {
                *state -= timeDelta;
                showHelpText((obj)->anim.modelInstance->helpTextIds[0]);
            }
        }
        player = Obj_GetPlayerObject();
        if (vec3f_distanceSquared(&obj->anim.worldPosX, &player->anim.worldPosX) < 100.0f &&
            playerIsDisguised((int)player) != 0)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_menuups16k);
            mainSetBits(*(s16*)(*(int*)&(obj)->anim.placementData + 0x1a), 1);
            *(u8*)&(obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        }
        particleArgs.offset[0] = -5.0f;
        particleArgs.offset[1] = 5.0f;
        particleArgs.offset[2] = 0.0f;
        objfx_spawnArcedBurstLegacy((int)obj, 5, 0.75f, 5, 2, 0x19, 2.0f, 2.0f, 10.0f, &particleArgs, 0);
        particleArgs.offset[0] = 5.0f;
        objfx_spawnArcedBurstLegacy((int)obj, 5, 0.75f, 5, 2, 0x19, 2.0f, 2.0f, 10.0f, &particleArgs, 0);
    }
}

void CCSharpclawPad_init(int* obj, int* placement)
{
    ((GameObject*)obj)->anim.rotX = (s16)((u32) * (u8*)((char*)placement + 24) << 8);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | CCSHARPCLAWPAD_OBJFLAG_HIDDEN);
}
