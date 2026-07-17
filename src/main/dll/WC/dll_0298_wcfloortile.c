/*
 * wcfloortile (DLL 0x298) - a collapsing floor tile in the Walled City
 * (WC). The tile sits flush until armed: once its arm game bit is set it
 * watches its map block's hit entries for a triggering entry, then enters a
 * shake-and-fall phase (jittering rotY/rotZ, accelerating down velocityY)
 * while fading alpha toward zero with the drop distance. state->phase: 0
 * idle/armed-watch, 1 shaking/falling/fading, 2 fallen (alpha 0, collision
 * off), 3 restored (a second game bit snaps the tile back to its placement
 * Y, fades alpha back in and re-enables collision). On each phase change it
 * reports to the level controller. state->flags: 1|2 bookkeeping, 4 armed.
 */
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/track_dolphin_api.h"
#include "dolphin/mtx.h"
#include "main/camera.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/object_api.h"
#include "main/object_render_legacy.h"
#include "main/objhits.h"
#include "main/obj_path.h"
#include "main/pad.h"
#include "main/vecmath.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/WC/dll_0298_wcfloortile.h"
#include "main/debug.h"
#include "main/object.h"
#include "main/game_object.h"
#include "main/dll/ARW/arwing_state.h"
#include "main/dll/ARW/dll_029A_arwarwing.h"
#include "main/dll/ARW/dll_029C_arwarwingbo.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/object_descriptor.h"


int wcfloortile_getExtraSize(void)
{
    return 8;
}

int wcfloortile_getObjectTypeId(void)
{
    return 0;
}

void wcfloortile_free(void)
{
}

void wcfloortile_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    }
}

void wcfloortile_hitDetect(void)
{
}

void wcfloortile_update(int obj)
{
    ObjAnimComponent* objAnim = &((GameObject*)obj)->anim;
    WcFloorTileState* state = ((GameObject*)obj)->extra;
    int off;
    int i;
    WcFloorTileSetup* setup = (WcFloorTileSetup*)((GameObject*)obj)->anim.placementData;

    if ((u32)mainGetBit(824) != 0)
    {
        ((GameObject*)obj)->anim.localPosY = setup->base.posY;
        state->phase = WCFLOORTILE_PHASE_RESTORE;
    }
    switch (state->phase)
    {
    case WCFLOORTILE_PHASE_IDLE:
    default:
        if (state->flags & 4)
        {
            if (0 < *(s8*)(*(int*)(obj + 0x58) + 0x10f))
            {
                f32 z = 0.0f;
                for (i = 0, off = 0; i < *(s8*)(*(int*)(obj + 0x58) + 0x10f); off += 4, i++)
                {
                    GameObject* e = *(GameObject**)(*(int*)(obj + 0x58) + off + 0x100);
                    if (e->anim.classId == 1)
                    {
                        Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_c6);
                        state->phase = WCFLOORTILE_PHASE_FALLING;
                        state->shakeTime = z;
                        ((GameObject*)obj)->anim.velocityY = z;
                    }
                }
            }
        }
        else if ((u32)mainGetBit(613) != 0)
        {
            state->flags |= 4;
        }
        break;
    case WCFLOORTILE_PHASE_FALLING:
        state->shakeTime = state->shakeTime + timeDelta;
        if (state->shakeTime > 120.0f)
        {
            state->flags |= 3;
            state->shakeTime = 120.0f;
            ((GameObject*)obj)->anim.velocityY = -0.1f * timeDelta + ((GameObject*)obj)->anim.velocityY;
        }
        state->shakeMag = 256.0f * (state->shakeTime / 120.0f);
        ((GameObject*)obj)->anim.rotY = randomGetRange(-state->shakeMag, state->shakeMag);
        ((GameObject*)obj)->anim.rotZ = randomGetRange(-state->shakeMag, state->shakeMag);
        ((GameObject*)obj)->anim.localPosY =
            ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->anim.localPosY;
        {
            f32 d = setup->base.posY - ((GameObject*)obj)->anim.localPosY;
            f32 alpha;
            if (d < 50.0f)
            {
                alpha = 255.0f;
            }
            else if (d > 150.0f)
            {
                alpha = 0.0f;
            }
            else
            {
                alpha = (d - 50.0f) / 100.0f;
                alpha = 1.0f - alpha;
                if (alpha > 1.0f)
                {
                    alpha = 1.0f;
                }
                else if (alpha < 0.0f)
                {
                    alpha = 0.0f;
                }
                alpha *= 255.0f;
            }
            objAnim->alpha = (u8)(int)alpha;
        }
        if (objAnim->alpha == 0)
        {
            state->phase = WCFLOORTILE_PHASE_FALLEN;
        }
        break;
    case WCFLOORTILE_PHASE_FALLEN:
        objAnim->alpha = 0;
        ObjHits_DisableObject(obj);
        state->flags |= 3;
        break;
    case WCFLOORTILE_PHASE_RESTORE:
    {
        f32 a = (f32)(u32)objAnim->alpha;
        a += 8.0f * timeDelta;
        if (a > 255.0f)
        {
            a = 255.0f;
        }
        objAnim->alpha = a;
    }
        ObjHits_EnableObject(obj);
        break;
    }
    {
        setup = (WcFloorTileSetup*)((GameObject*)obj)->anim.placementData;
        if (fn_80065640() != 0)
        {
            state->flags |= 2;
        }
        if (state->flags & 2)
        {
            if (fn_80065640() == 0)
            {
                fn_80065574(setup->eventId, (GameObject*)(*(int*)&((GameObject*)obj)->anim.parent), state->flags & 1);
                state->flags &= ~2;
            }
        }
    }
}

void wcfloortile_init(GameObject* obj)
{
    WcFloorTileState* state = obj->extra;

    obj->anim.rotX = -0x4000;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags |= 0x1800;
    state->flags |= 2;
}

void wcfloortile_release(void)
{
}

void wcfloortile_initialise(void)
{
}

ObjectDescriptor gWCFloorTileObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)wcfloortile_initialise,
    (ObjectDescriptorCallback)wcfloortile_release,
    0,
    (ObjectDescriptorCallback)wcfloortile_init,
    (ObjectDescriptorCallback)wcfloortile_update,
    (ObjectDescriptorCallback)wcfloortile_hitDetect,
    (ObjectDescriptorCallback)wcfloortile_render,
    (ObjectDescriptorCallback)wcfloortile_free,
    (ObjectDescriptorCallback)wcfloortile_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)wcfloortile_getExtraSize,
};
