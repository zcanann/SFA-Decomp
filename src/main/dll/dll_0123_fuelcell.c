/* DLL 0x0123 - fuelcell (fuel cell collectible). TU: 0x8018C000-0x8018C7D8. */
#include "main/dll/dll_0123_fuelcell.h"
#include "track/intersect_depth_state_api.h"
#include "main/objseq.h"
#include "main/object_render_legacy.h"
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
#include "main/audio/sfx_play_pointer_legacy_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/newclouds.h"
#include "main/model.h"
#include "dolphin/gx/GXLegacyDecls.h"

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
    u8 pad[0x5a];
    u8 lit : 1; // 0x5c bit 7
    u8 grabbed : 1; // bit 6
    u8 unkBit5 : 1; // bit 5
    u8 resetPos : 1; // bit 4
} FuelcellState;

typedef struct
{
    u8 pad[8];
    f32 homeX; // 0x8
    f32 homeY; // 0xc
    f32 homeZ; // 0x10
    u8 pad2[0xa];
    s16 offBit; // 0x1e
    s16 onBit; // 0x20
} FuelcellSetup;

int FuelCell_SeqFn(int* obj)
{
    FuelcellState* state = ((GameObject*)obj)->extra;
    state->unkBit5 = 1;
    state->resetPos = 1;
    return 0;
}

void fuelcell_modelMtxFn(u8* model)
{
    if (model[0x37] == 0xff)
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
    u8* state = obj->extra;
    u8 i;

    for (i = 0; i < 10; i++)
    {
        void* slot = *(void**)(state + 8 + i * 4);
        if (slot != NULL)
        {
            mm_free_(slot);
        }
    }

    if (((u32)state[0x5c] >> 7) & 1)
    {
        ObjGroup_RemoveObject((int)obj, FUELCELL_OBJGROUP);
    }
}

typedef struct
{
    u8 pad0[0xc];
    f32 pos[3]; // 0xc
    f32 pos2[3]; // 0x18
} GameObjPos;

#pragma opt_loop_invariants off
void FuelCell_render(int* obj, int p2, int p3, int p4, int p5)
{
    int** list;
    u8* slot;
    FuelcellState* state;
    u8 mode;
    u8 i;
    u8 j;
    u8 pickCount;
    u8 spawned;
    f32 angle;
    f32 scale;
    int* candidates[9];
    f32 pos[3];
    f32 dist;
    int objCount;

    state = ((GameObject*)obj)->extra;
    angle = 4.0f;
    objCount = 0;
    mode = 0x40;
    pickCount = 0;
    spawned = 0;
    if (state->lit)
    {
        if (state->unkBit5)
        {
            objfx_spawnDirectionalBurstLegacy(obj, 5, 1.0f, 1, 1, 0x14, 3.5f, 0, 0);
        }
        else
        {
            objfx_spawnDirectionalBurstLegacy(obj, 5, 1.0f, 1, 1, 0x14, 4.5f, 0, 0);
        }
        {
            ModelRenderOp* op = ObjModel_GetRenderOp(Obj_GetActiveModel((GameObject*)obj)->file, 0);
            op->alphaOverride = 0x7f;
        }
        ((void(*)(int*, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, 1.0f);

        for (i = 0; i < 10; i++)
        {
            slot = (u8*)state + i * 4;
            if (*(void**)(slot + 8) != NULL)
            {
                lightningRenderLegacy(*(LightningEffect**)(slot + 8));
                if (getHudHiddenFrameCount() == 0)
                {
                    *(f32*)(slot + 0x34) += timeDelta;
                    *(u16*)(*(char**)(slot + 8) + 0x20) = (int)(0.5f + *(f32*)(slot + 0x34));
                    if (*(u16*)(*(char**)(slot + 8) + 0x20) > 0x14)
                    {
                        mm_free_(*(void**)(slot + 8));
                        *(void**)(slot + 8) = NULL;
                    }
                }
            }
            else if (!spawned && getHudHiddenFrameCount() == 0)
            {
                int* target;
                if ((int)randomGetRange(0, 9) == 0 && !state->unkBit5)
                {
                    list = (int**)ObjGroup_GetObjects(FUELCELL_OBJGROUP, &objCount);
                    for (j = 0; j < objCount; j++)
                    {
                        int ofs = (int)(u16)j * 4;
                        int* other = *(int**)((char*)list + ofs);
                        u8 ok;
                        if (other != obj)
                        {
                            if (((GameObject*)other)->extra != NULL &&
                                ((FuelcellState*)((GameObject*)other)->extra)->unkBit5)
                            {
                                ok = 0;
                            }
                            else
                            {
                                ok = 1;
                            }
                            if (ok && vec3f_distanceSquared(((GameObjPos*)other)->pos2, ((GameObjPos*)obj)->pos2) <
                                10000.0f)
                            {
                                candidates[pickCount++] = *(int**)((char*)list + ofs);
                            }
                        }
                    }
                }
                if (pickCount != 0)
                {
                    pickCount--;
                    pickCount = randomGetRange(0, pickCount);
                    dist = Vec_distance(((GameObjPos*)candidates[pickCount])->pos2,
                                     ((GameObjPos*)obj)->pos2) / 100.0f;
                    angle = 0.1f - 0.07f * dist;
                    mode = 0xff;
                }
                else
                {
                    candidates[0] = obj;
                }
                target = candidates[pickCount];
                pos[0] = ((GameObjPos*)target)->pos[0];
                pos[1] = ((GameObjPos*)target)->pos[1];
                pos[2] = ((GameObjPos*)target)->pos[2];
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
                *(LightningEffect**)(slot + 8) = lightningCreatePromoted(
                    (const Vec3f*)((GameObjPos*)obj)->pos, (const Vec3f*)pos, angle, 0.2f, 0x14, mode, 0);
                *(f32*)(slot + 0x34) = 0.0f;
                spawned = 1;
            }
        }
    }
}
#pragma opt_loop_invariants reset

void FuelCell_update(GameObject* obj)
{
    FuelcellSetup* setup = *(FuelcellSetup**)&obj->anim.placementData;
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
                mainSetBits(setup->offBit, 1);
                gameBitIncrement(GAMEBIT_ITEM_FuelCell_Count);
                mainSetBits(FUELCELL_GAMEBIT_CARRIED, 0);
            }
        }
    }
    else
    {
        int bit = setup->offBit;
        if (bit != -1 && mainGetBit(bit) == 0)
        {
            bit = setup->onBit;
            if (bit == -1 || mainGetBit(bit) != 0)
            {
                f32 dy;
                if (!state->lit)
                {
                    Sfx_AddLoopedObjectSoundPtrIntLegacy(obj, SFXTRIG_pk_fuelcell_fizz);
                    state->lit = 1;
                    ObjGroup_AddObject((int)obj, FUELCELL_OBJGROUP);
                }
                else if (state->resetPos)
                {
                    ((GameObject*)obj)->anim.localPosX = setup->homeX;
                    ((GameObject*)obj)->anim.localPosY = setup->homeY;
                    ((GameObject*)obj)->anim.localPosZ = setup->homeZ;
                    ((GameObject*)obj)->anim.alpha = 0xff;
                    state->resetPos = 0;
                }
                dy = ((GameObject*)obj)->anim.localPosY - player->anim.localPosY;
                if (dy > -5.0f && dy < 40.0f
                    && mainGetBit(FUELCELL_GAMEBIT_CARRIED) == 0
                    && getXZDistance(&((GameObject*)obj)->anim.worldPosX,
                                     &player->anim.worldPosX) < 81.0f)
                {
                    state->msg = 0xcbe;
                    ObjMsg_SendToObject(player, FUELCELL_MSG_IN_RANGE, obj, (u32)state);
                    state->grabbed = 1;
                    mainSetBits(FUELCELL_GAMEBIT_CARRIED, 1);
                    Sfx_PlayFromObject(obj, SFXTRIG_lockoff22);
                }
            }
        }
        else if (state->lit)
        {
            state->lit = 0;
            Sfx_RemoveLoopedObjectSoundPtrIntLegacy(obj, SFXTRIG_pk_fuelcell_fizz);
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
