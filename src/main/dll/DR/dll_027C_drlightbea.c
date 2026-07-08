/*
 * drlightbea (DLL 0x27C) - a lightning-beam effect that arcs from this
 * object to a target while its placement game bit (0x20) is set.
 *
 * The target is either another placed object (resolved by id via
 * dll_2E_func0A when the placement target byte at 0x19 is non-zero) or
 * the player. While active, render keeps the beam's endpoints synced to
 * the live source/target positions, advances its lifetime counter and
 * frees the beam once it expires. The extra state (0xc bytes) holds the
 * lightningCreate handle at offset 0 and the active/free bit flags at
 * offset 4.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/lightningeffect.h"

#include "main/dll/DR/dll_027C_drlightbea.h"

int DR_LightBea_getExtraSize(void)
{
    return 0xc;
}

int DR_LightBea_getObjectTypeId(void)
{
    return 0;
}

void DR_LightBea_free(int obj)
{
    DrLightBeaState* state = *(DrLightBeaState**)&((GameObject*)obj)->extra;
    LightningEffect* buffer = state->handle;

    if (buffer != NULL)
    {
        mm_free(buffer);
        state->handle = NULL;
    }
}

void DR_LightBea_render(int obj, int p2, int p3, int p4, int p5)
{
    DrLightBeaState* state = *(DrLightBeaState**)&((GameObject*)obj)->extra;
    int setup = *(int*)&((GameObject*)obj)->anim.placementData;
    int player;
    f32 targetXform[6];
    f32 sourcePos[3];
    f32 targetPos[3];

    if (state->flags.bit80)
    {
        state->handle->start[0] = ((GameObject*)obj)->anim.localPosX;
        state->handle->start[1] = ((GameObject*)obj)->anim.localPosY;
        state->handle->start[2] = ((GameObject*)obj)->anim.localPosZ;
        if (((DrlightbeaPlacement*)setup)->targetId == 0)
        {
            player = Obj_GetPlayerObject();
            state->handle->end[0] = ((GameObject*)player)->anim.localPosX;
            state->handle->end[1] = lbl_803E6BB8 + ((GameObject*)player)->anim.localPosY;
            state->handle->end[2] = ((GameObject*)player)->anim.localPosZ;
        }
        lightningRender(state->handle);
        state->handle->timer += 1;
        if (state->handle->timer >= state->handle->lifetime)
        {
            mm_free(state->handle);
            state->handle = NULL;
            state->flags.bit80 = 0;
            if (*(u32*)&((ObjPlacement*)setup)->mapId == 0xffffffff)
            {
                state->flags.bit40 = 1;
            }
        }
    }
    else
    {
        if (state->handle != NULL)
        {
            mm_free(state->handle);
            state->handle = NULL;
        }
        state->flags.bit80 = mainGetBit(((DrlightbeaPlacement*)setup)->gameBit);
        if (state->flags.bit80)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_id_30f);
            sourcePos[0] = ((GameObject*)obj)->anim.localPosX;
            sourcePos[1] = ((GameObject*)obj)->anim.localPosY;
            sourcePos[2] = ((GameObject*)obj)->anim.localPosZ;
            if (((DrlightbeaPlacement*)setup)->targetId != 0 &&
                dll_2E_func0A(((DrlightbeaPlacement*)setup)->targetId, targetXform) != 0)
            {
                targetPos[0] = targetXform[3];
                targetPos[1] = targetXform[4];
                targetPos[2] = targetXform[5];
            }
            else
            {
                player = Obj_GetPlayerObject();
                targetPos[0] = ((GameObject*)player)->anim.localPosX;
                targetPos[1] = lbl_803E6BB8 + ((GameObject*)player)->anim.localPosY;
                targetPos[2] = ((GameObject*)player)->anim.localPosZ;
            }
            state->handle = (LightningEffect*)lightningCreate(sourcePos, targetPos, lbl_803E6BBC, lbl_803E6BC0,
                                                              randomGetRange(5, 0xf), 0x60, 0);
        }
    }
}

void DR_LightBea_hitDetect(void)
{
}

void DR_LightBea_update(int obj)
{
    DrLightBeaState* state = *(DrLightBeaState**)&((GameObject*)obj)->extra;
    if (state->flags.bit40)
    {
        Obj_FreeObject(obj);
    }
}

void DR_LightBea_init(int obj)
{
    DrLightBeaState* state = *(DrLightBeaState**)&((GameObject*)obj)->extra;
    state->flags.bit80 = 0;
    state->handle = NULL;
    state->flags.bit40 = 0;
}

void DR_LightBea_release(void)
{
}

void DR_LightBea_initialise(void)
{
}
