/*
 * ccsharpclawpad - Crystal Caves SharpClaw "pressure pad" object (DLL
 * 0x0189). A disguise-gated switch pad. Its placement activationGameBit
 * records whether it has been activated: once set it
 * stays lit (active hitbox bit 8 on) and emits the lit particle burst.
 * While unset it shows help text (gated by an ObjTrigger and a hold timer)
 * and watches for a disguised player to step close - that plays a stomp sfx,
 * sets the gameBit and lights the pad.
 */
#include "main/game_object.h"
#include "main/dll/player_api.h"
#include "main/object_api.h"
#include "main/objfx.h"
#include "main/obj_trigger.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/dll/CC/dll_0189_ccsharpclawpad.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/minimap_api.h"
#include "main/vecmath_distance_api.h"
#include "main/object_descriptor.h"

int CCSharpclawPad_getExtraSize(void)
{
    return sizeof(SharpClawPadState);
}

void CCSharpclawPad_update(GameObject* obj)
{
    SharpClawPadParticleArgs particleArgs;
    SharpClawPadState* state;
    GameObject* player;

    if (mainGetBit(((SharpClawPadSetup*)obj->anim.placement)->activationGameBit) != 0)
    {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        particleArgs.offset[0] = -5.0f;
        particleArgs.offset[1] = 5.0f;
        particleArgs.offset[2] = 0.0f;
        objfx_spawnArcedBurst(obj, 5, 0.75f, 2, 2, 0x19, 2.0f, 2.0f, 10.0f, &particleArgs, 0);
        particleArgs.offset[0] = 5.0f;
        objfx_spawnArcedBurst(obj, 5, 0.75f, 2, 2, 0x19, 2.0f, 2.0f, 10.0f, &particleArgs, 0);
    }
    else
    {
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        if (mainGetBit(GAMEBIT_STAFF_ABILITY_SHARPCLAW_DISGUISE) == 0)
        {
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
        else
        {
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
        state = obj->extra;
        if (ObjTrigger_IsSet((int)obj) != 0 && isAreaNameTextActive() == 0)
        {
            state->helpTimer = 600.0f;
        }
        if (state->helpTimer > 0.0f)
        {
            if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) == 0)
            {
                state->helpTimer = 0.0f;
            }
            else
            {
                state->helpTimer -= timeDelta;
                showHelpText(obj->anim.modelInstance->helpTextIds[0]);
            }
        }
        player = Obj_GetPlayerObject();
        if (vec3f_distanceSquared(&obj->anim.worldPosX, &player->anim.worldPosX) < 100.0f &&
            playerIsDisguised(player) != 0)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_menuups16k);
            mainSetBits(((SharpClawPadSetup*)obj->anim.placement)->activationGameBit, 1);
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        }
        particleArgs.offset[0] = -5.0f;
        particleArgs.offset[1] = 5.0f;
        particleArgs.offset[2] = 0.0f;
        objfx_spawnArcedBurst(obj, 5, 0.75f, 5, 2, 0x19, 2.0f, 2.0f, 10.0f, &particleArgs, 0);
        particleArgs.offset[0] = 5.0f;
        objfx_spawnArcedBurst(obj, 5, 0.75f, 5, 2, 0x19, 2.0f, 2.0f, 10.0f, &particleArgs, 0);
    }
}

void CCSharpclawPad_init(GameObject* obj, SharpClawPadSetup* setup)
{
    obj->anim.rotX = (s16)((u32)setup->rotX << 8);
    obj->objectFlags = (u16)(obj->objectFlags | OBJECT_OBJFLAG_HIDDEN);
}

ObjectDescriptor gCCSharpclawPadObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)CCSharpclawPad_init,
    (ObjectDescriptorCallback)CCSharpclawPad_update,
    0,
    0,
    0,
    0,
    CCSharpclawPad_getExtraSize,
};
