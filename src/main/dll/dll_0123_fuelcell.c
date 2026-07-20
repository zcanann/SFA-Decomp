/* DLL 0x0123 - fuelcell (fuel cell collectible). TU: 0x8018C000-0x8018C7D8. */
#include "main/dll/dll_0123_fuelcell.h"
#include "track/intersect_depth_state_api.h"
#include "main/objseq.h"
#include "main/object_render.h"
#include "main/vecmath.h"
#include "main/game_object.h"
#include "main/obj_group.h"
#include "main/obj_message.h"
#include "main/object_api.h"
#include "main/objfx.h"
#include "main/gamebits.h"
#include "main/gamebit_ids.h"
#include "main/gameloop_api.h"
#include "main/audio/sfx_looped_object_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/newclouds.h"
#include "main/model.h"
#include "dolphin/gx/GXLegacyDecls.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

#define FUELCELL_OBJGROUP 0x4f

#define GX_BM_NONE 0
#define GX_BM_BLEND 1
#define GX_BL_ZERO 0
#define GX_BL_ONE 1
#define GX_BL_SRCALPHA 4
#define GX_LO_NOOP 5
#define GX_LEQUAL 3
#define GX_ALWAYS 7
#define GX_AOP_AND 0

#define FUELCELL_MSG_IN_RANGE 0x7000a  /* sent to player when grab is offered */
#define FUELCELL_MSG_RELEASE 0x7000b   /* player dropped/deposited the cell */
#define FUELCELL_GAMEBIT_CARRIED 0xe97 /* global: a fuel cell is currently held */
typedef struct
{
    u16 msg; // 0x0
    u8 pad02[6];
    LightningEffect* lightning[10];
    u8 pad30[4];
    f32 lightningAge[10];
    u8 lit : 1; // 0x5c bit 7
    u8 grabbed : 1; // bit 6
    u8 unkBit5 : 1; // bit 5
    u8 resetPos : 1; // bit 4
    u8 pad5D[3];
} FuelcellState;

typedef struct
{
    ObjPlacement base;
    u8 pad18[6];
    s16 offBit; // 0x1e
    s16 onBit; // 0x20
} FuelcellPlacement;

STATIC_ASSERT(offsetof(FuelcellState, lightning) == 0x8);
STATIC_ASSERT(offsetof(FuelcellState, lightningAge) == 0x34);
STATIC_ASSERT(sizeof(FuelcellState) == 0x60);
STATIC_ASSERT(offsetof(FuelcellPlacement, offBit) == 0x1E);
STATIC_ASSERT(offsetof(FuelcellPlacement, onBit) == 0x20);
STATIC_ASSERT(sizeof(FuelcellPlacement) == 0x24);

int FuelCell_SeqFn(GameObject* obj)
{
    FuelcellState* state = obj->extra;
    state->unkBit5 = 1;
    state->resetPos = 1;
    return 0;
}

void fuelcell_modelMtxFn(GameObject* obj)
{
    if (obj->anim.renderAlpha == 0xff)
    {
        GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
    }
    else
    {
        GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_ONE, GX_LO_NOOP);
    }
    gxSetZMode_(1, GX_LEQUAL, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
}

int FuelCell_getExtraSize(void) { return 0x60; }

void FuelCell_free(GameObject* obj)
{
    FuelcellState* state = obj->extra;
    u8 i;

    for (i = 0; i < 10; i++)
    {
        if (state->lightning[i] != NULL)
        {
            mm_free_(state->lightning[i]);
        }
    }

    if (state->lit)
    {
        ObjGroup_RemoveObject((int)obj, FUELCELL_OBJGROUP);
    }
}

void FuelCell_render(GameObject* obj, int p2, int p3, int p4, int p5)
{
    GameObject** list;
    FuelcellState* state;
    u8 mode;
    u8 i;
    u8 j;
    u8 pickCount;
    u8 spawned;
    f32 angle;
    f32 scale;
    GameObject* candidates[9];
    f32 pos[3];
    f32 dist;
    int objCount;

    state = obj->extra;
    angle = 4.0f;
    objCount = 0;
    mode = 0x40;
    pickCount = 0;
    spawned = 0;
    if (state->lit)
    {
        if (state->unkBit5)
        {
            objfx_spawnDirectionalBurst(obj, 5, 1.0f, 1, 1, 0x14, 3.5f, NULL, 0);
        }
        else
        {
            objfx_spawnDirectionalBurst(obj, 5, 1.0f, 1, 1, 0x14, 4.5f, NULL, 0);
        }
        {
            ModelRenderOp* op = ObjModel_GetRenderOp(Obj_GetActiveModel(obj)->file, 0);
            op->alphaOverride = 0x7f;
        }
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);

        for (i = 0; i < 10; i++)
        {
            if (state->lightning[i] != NULL)
            {
                lightningRender(state->lightning[i]);
                if (getHudHiddenFrameCount() == 0)
                {
                    state->lightningAge[i] += timeDelta;
                    *(u16*)((char*)state->lightning[i] + 0x20) = (int)(0.5f + state->lightningAge[i]);
                    if (*(u16*)((char*)state->lightning[i] + 0x20) > 0x14)
                    {
                        mm_free_(state->lightning[i]);
                        state->lightning[i] = NULL;
                    }
                }
            }
            else if (!spawned && getHudHiddenFrameCount() == 0)
            {
                GameObject* target;
                if ((int)randomGetRange(0, 9) == 0 && !state->unkBit5)
                {
                    list = (GameObject**)ObjGroup_GetObjects(FUELCELL_OBJGROUP, &objCount);
                    for (j = 0; j < objCount; j++)
                    {
                        int ofs = (int)(u16)j * 4;
                        GameObject* other = *(GameObject**)((char*)list + ofs);
                        u8 ok;
                        if (other != obj)
                        {
                            if (other->extra != NULL &&
                                ((FuelcellState*)other->extra)->unkBit5)
                            {
                                ok = 0;
                            }
                            else
                            {
                                ok = 1;
                            }
                            if (ok && vec3f_distanceSquared(&other->anim.worldPosX, &obj->anim.worldPosX) <
                                10000.0f)
                            {
                                candidates[pickCount++] = *(GameObject**)((char*)list + ofs);
                            }
                        }
                    }
                }
                if (pickCount != 0)
                {
                    pickCount--;
                    pickCount = randomGetRange(0, pickCount);
                    dist = Vec_distance(&candidates[pickCount]->anim.worldPosX,
                                     &obj->anim.worldPosX) / 100.0f;
                    angle = 0.1f - 0.07f * dist;
                    mode = 0xff;
                }
                else
                {
                    candidates[0] = obj;
                }
                target = candidates[pickCount];
                pos[0] = target->anim.localPosX;
                pos[1] = target->anim.localPosY;
                pos[2] = target->anim.localPosZ;
                if (target == obj)
                {
                    if (state->unkBit5)
                    {
                        scale = 0.0017f;
                    }
                    else
                    {
                        scale = 0.003f;
                    }
                    pos[0] = scale * (f32)((int)randomGetRange(0, 2000) - 1000) + pos[0];
                    pos[1] = scale * (f32)((int)randomGetRange(0, 2000) - 1000) + pos[1];
                    pos[2] = scale * (f32)((int)randomGetRange(0, 2000) - 1000) + pos[2];
                }
                state->lightning[i] = lightningCreate(
                    &obj->anim.localPos, (const Vec3f*)pos, angle, 0.2f, 0x14, (u8)mode, 0);
                state->lightningAge[i] = 0.0f;
                spawned = 1;
            }
        }
    }
}

void FuelCell_update(GameObject* obj)
{
    FuelcellPlacement* placement = (FuelcellPlacement*)obj->anim.placementData;
    FuelcellState* state = obj->extra;
    GameObject* player;
    int msgId;
    int msgParam;

    player = Obj_GetPlayerObject();
    if (state->grabbed)
    {
        while (ObjMsg_Pop(obj, (u32*)&msgId, (u32*)&msgParam, 0) != 0)
        {
            if (msgId == FUELCELL_MSG_RELEASE)
            {
                state->grabbed = 0;
                mainSetBits(placement->offBit, 1);
                gameBitIncrement(GAMEBIT_ITEM_FuelCell_Count);
                mainSetBits(FUELCELL_GAMEBIT_CARRIED, 0);
            }
        }
    }
    else
    {
        int bit = placement->offBit;
        if (bit != -1 && mainGetBit(bit) == 0)
        {
            bit = placement->onBit;
            if (bit == -1 || mainGetBit(bit) != 0)
            {
                f32 dy;
                if (!state->lit)
                {
                    Sfx_AddLoopedObjectSound((u32)obj, SFXTRIG_pk_fuelcell_fizz);
                    state->lit = 1;
                    ObjGroup_AddObject((int)obj, FUELCELL_OBJGROUP);
                }
                else if (state->resetPos)
                {
                    obj->anim.localPosX = placement->base.posX;
                    obj->anim.localPosY = placement->base.posY;
                    obj->anim.localPosZ = placement->base.posZ;
                    obj->anim.alpha = 0xff;
                    state->resetPos = 0;
                }
                dy = obj->anim.localPosY - player->anim.localPosY;
                if (dy > -5.0f && dy < 40.0f
                    && mainGetBit(FUELCELL_GAMEBIT_CARRIED) == 0
                    && getXZDistance(&obj->anim.worldPosX,
                                     &player->anim.worldPosX) < 81.0f)
                {
                    state->msg = 0xcbe;
                    ObjMsg_SendToObject(player, FUELCELL_MSG_IN_RANGE, obj, (u32)state);
                    state->grabbed = 1;
                    mainSetBits(FUELCELL_GAMEBIT_CARRIED, 1);
                    Sfx_PlayFromObject((u32)obj, SFXTRIG_lockoff22);
                }
            }
        }
        else if (state->lit)
        {
            state->lit = 0;
            Sfx_RemoveLoopedObjectSound((u32)obj, SFXTRIG_pk_fuelcell_fizz);
            ObjGroup_RemoveObject((int)obj, FUELCELL_OBJGROUP);
        }
    }
}

void FuelCell_init(GameObject* obj)
{
    obj->animEventCallback = FuelCell_SeqFn;
    ObjModel_SetPostRenderCallback(Obj_GetActiveModel(obj), fuelcell_modelMtxFn);
    ObjMsg_AllocQueue(obj, 2);
}

ObjectDescriptor gFuelCellObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS, 0, 0, 0,
    (ObjectDescriptorCallback)FuelCell_init, (ObjectDescriptorCallback)FuelCell_update, 0,
    (ObjectDescriptorCallback)FuelCell_render, (ObjectDescriptorCallback)FuelCell_free, 0,
    FuelCell_getExtraSize,
};
