/* Waterfall spray particle and sound emitter. */
#include "main/dll/partfx_interface.h"
#include "main/dll/MMP/MMP_asteroid.h"
#include "main/object_api.h"
#include "main/audio/sfx_keep_alive_api.h"

#include "main/dll/dll_0132_waterfallspray.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/frame_timing.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/vecmath.h"
#include "main/audio/sfx.h"

int WaterFallSpray_getExtraSize(void)
{
    return sizeof(WaterFallSprayState);
}

int WaterFallSpray_SeqFn(GameObject* obj)
{
    WaterFallSpray_update(obj);
    return 0;
}

void WaterFallSpray_free(GameObject* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void WaterFallSpray_render(void)
{
}

void WaterFallSpray_update(GameObject* obj)
{
    WaterFallSprayState* state;
    WaterFallSpraySetup* setup[1];
    GameObject* playerObj;
    PartFxSpawnParams partfxArgs;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 distance;
    int cooldown;
    s16 i;

    state = obj->extra;
    setup[0] = (WaterFallSpraySetup*)obj->anim.placement;
    playerObj = (GameObject*)Obj_GetPlayerObject();
    if (playerObj != NULL)
    {
        if (setup[0]->gameBit != -1)
        {
            i = mainGetBit(setup[0]->gameBit);
        }
        else
        {
            i = 1;
        }
        if (i != 0)
        {
            if ((setup[0]->flags & WATERFALLSPRAY_FLAG_SFX_DISABLED) == 0)
            {
                Sfx_KeepAliveLoopedObjectSound((int)obj, state->sfxIdA & 0xffff);
                Sfx_KeepAliveLoopedObjectSound((int)obj, state->sfxIdB & 0xffff);
            }

            cooldown = obj->userData1;
            if (cooldown <= 0)
            {
                dx = obj->anim.worldPosX - playerObj->anim.worldPosX;
                dy = obj->anim.worldPosY - playerObj->anim.worldPosY;
                dz = obj->anim.worldPosZ - playerObj->anim.worldPosZ;
                distance = sqrtf(dz * dz + (dx * dx + dy * dy));
                if (((distance <= (f32)(s32)((u32)setup[0]->triggerRadius << 4)) ||
                     (setup[0]->triggerRadius == 0)) &&
                    ((obj->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0))
                {
                    for (i = 0; i < setup[0]->emitCount; i++)
                    {
                        partfxArgs.posX =
                            (f32)(s32)randomGetRange(-setup[0]->randomExtentX, setup[0]->randomExtentX);
                        partfxArgs.posY =
                            (f32)(s32)randomGetRange(-setup[0]->randomExtentY, setup[0]->randomExtentY);
                        partfxArgs.posZ =
                            (f32)(s32)randomGetRange(-setup[0]->randomExtentZ, setup[0]->randomExtentZ);
                        if ((setup[0]->flags & WATERFALLSPRAY_FLAG_EFFECT_320) != 0)
                        {
                            (*gPartfxInterface)->spawnObject(obj, 0x320, &partfxArgs, 4, -1, 0);
                        }
                        if ((setup[0]->flags & WATERFALLSPRAY_FLAG_EFFECT_321) != 0)
                        {
                            (*gPartfxInterface)->spawnObject(obj, 0x321, &partfxArgs, 4, -1, 0);
                        }
                        if ((setup[0]->flags & WATERFALLSPRAY_FLAG_EFFECT_322) != 0)
                        {
                            (*gPartfxInterface)->spawnObject(obj, 0x322, &partfxArgs, 4, -1, 0);
                        }
                        if ((setup[0]->flags & WATERFALLSPRAY_FLAG_EFFECT_351) != 0)
                        {
                            (*gPartfxInterface)->spawnObject(obj, 0x351, &partfxArgs, 4, -1, 0);
                        }
                    }
                }
                obj->userData1 = -setup[0]->emitCount;
            }
            else if (cooldown > 0)
            {
                obj->userData1 = cooldown - framesThisStep;
            }
        }
    }
}

void WaterFallSpray_init(GameObject* obj, WaterFallSpraySetup* setup)
{
    WaterFallSprayState* state = obj->extra;
    s16 rotZ, rotY, rotX;
    int mapId;
    rotZ = (s16)((s32)setup->rotZ << 8);
    obj->anim.rotZ = rotZ;
    rotY = (s16)((s32)setup->rotY << 8);
    obj->anim.rotY = rotY;
    rotX = (s16)((s32)setup->rotX << 8);
    obj->anim.rotX = rotX;
    obj->userData1 = 0;
    obj->animEventCallback = WaterFallSpray_SeqFn;
    mapId = ((WaterFallSpraySetup*)obj->anim.placement)->base.mapId;
    switch (mapId)
    {
    case WATERFALLSPRAY_ALT_SFX_DEF_MIN:
    case WATERFALLSPRAY_ALT_SFX_DEF_END - 1:
        state->sfxIdA = WATERFALLSPRAY_ALT_SFX_A;
        state->sfxIdB = WATERFALLSPRAY_ALT_SFX_B;
        return;
    default:
        state->sfxIdA = WATERFALLSPRAY_DEFAULT_SFX_A;
        state->sfxIdB = WATERFALLSPRAY_DEFAULT_SFX_B;
    }
}
