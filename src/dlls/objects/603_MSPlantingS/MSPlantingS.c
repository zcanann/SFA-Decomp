/*
 * MSPlantingS (DLL 0x25B) - moon-seed planting spots.
 *
 * Each spot is a placeable object identified by its placement ident; init maps
 * that id to a pair of game bits: one tracking whether a seed has been planted
 * here (inner+8), the other whether the grown plant has been harvested (inner+0xa).
 * The object walks a small state machine in update (phase byte at extra+0):
 * INIT -> EMPTY (alpha fades in, posY raised) -> GROWN/idle (pulses colour,
 * spawns directional fx, accepts a priority hit of type 0x1a to be cut) -> CUT
 * -> HARVESTED. The shared "seeds carried" counter is game bit 0x86A; planting
 * decrements it and runs object sequence 0. render tints the model per phase;
 * MoonSeedPlantingSpot_cutOrHarvest is the trigger-volume callback that cuts/harvests.
 */
#include "main/audio/sfx_play_api.h"
#include "main/dll/dll_00C4_tricky.h"
#include "main/dll/partfx_interface.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/object_render.h"
#include "main/objhits.h"
#include "main/objprint_api.h"
#include "main/objtype.h"
#include "sys/objects/lifecycle.h"
#include "main/vecmath.h"
#include "main/game_ui_interface.h"
#include "sys/objects.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/objfx.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_025B_msplantings.h"
#include "main/frame_timing.h"
#include "dlls/object_descriptor.h"

/* shared "moon seeds carried" counter game bit */
#define GAMEBIT_MOONSEED_COUNT 0x86A
/* object-group id the planting spots register into */
#define MSPLANTING_OBJ_GROUP 0x2E
#define MSPLANTING_PARTFX    0x70f

/* phase byte values (state byte at extra[0]) */
#define MSPLANTING_PHASE_INIT      0
#define MSPLANTING_PHASE_EMPTY     1
#define MSPLANTING_PHASE_GROWN     2
#define MSPLANTING_PHASE_CUT       3
#define MSPLANTING_PHASE_HARVESTED 4

/* state->flags bits */
#define MSPLANTING_FLAG_PLANTED 1
#define MSPLANTING_FLAG_VISIBLE 2
#define MSPLANTING_FLAG_BURST   4

/* ObjHits priority-hit result that cuts the plant */
#define MSPLANTING_HIT_CUT 0x1A

#define MSPLANTING_TRICKY_COMMAND_KIND 1
#define MSPLANTING_TRICKY_COMMAND_TYPE 4

int MoonSeedPlantingSpot_SeqFn(GameObject* obj)
{
    MoonSeedPlantingSpotState* state = obj->extra;
    state->flags = (u8)((u32)state->flags | MSPLANTING_FLAG_PLANTED);
    return 0;
}

int MoonSeedPlantingSpot_render2(void)
{
    return 0x2;
}
int MoonSeedPlantingSpot_modelMtxFn(void)
{
    return 0x0;
}
int MoonSeedPlantingSpot_func0B(void)
{
    return 0x0;
}

int MoonSeedPlantingSpot_cutOrHarvest(GameObject* obj, int arg)
{
    ObjPlacement* placement;
    MoonSeedPlantingSpotState* held;
    MoonSeedPlantingSpotState* inner;
    int ret;

    inner = obj->extra;
    ret = 0;
    if (arg == 0)
    {
        if ((inner->flags & MSPLANTING_FLAG_VISIBLE) != 0)
        {
            inner->phase = MSPLANTING_PHASE_CUT;
            inner->colorPhase = 0;
        }
        ret = 1;
    }
    else if (arg == 1)
    {
        if (inner->phase == MSPLANTING_PHASE_CUT)
        {
            ret = 1;
            if (mainGetBit(inner->plantedGameBit) != 0 &&
                mainGetBit(inner->harvestedGameBit) == 0)
            {
                held = obj->extra;
                placement = (ObjPlacement*)obj->anim.placementData;
                if (mainGetBit(held->plantedGameBit) != 0)
                {
                    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                    mainSetBits(held->harvestedGameBit, 1);
                    held->phase = MSPLANTING_PHASE_HARVESTED;
                    obj->anim.localPosY = placement->posY;
                }
            }
        }
    }
    return ret;
}

int MoonSeedPlantingSpot_getExtraSize(void)
{
    return sizeof(MoonSeedPlantingSpotState);
}
int MoonSeedPlantingSpot_getObjectTypeId(void)
{
    return 0x1;
}

void MoonSeedPlantingSpot_free(GameObject* obj)
{
    objFreeObjectType(obj, MSPLANTING_OBJ_GROUP);
}

void MoonSeedPlantingSpot_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    MoonSeedPlantingSpotState* inner = obj->extra;
    s32 v = visible;
    if (v != 0)
    {
        if (inner->phase == MSPLANTING_PHASE_GROWN)
        {
            if ((inner->flags & MSPLANTING_FLAG_VISIBLE) != 0)
            {
                int iv;
                inner->colorPhase += 0x1000;
                iv = (int)(63.0f * (1.0f + mathSinf(3.1415927f * (f32)inner->colorPhase /
                                                    32768.0f)));
                objSetColorFilter((u8)(iv + 0x7f), 0xff, 0xff);
            }
        }
        else if (inner->phase == MSPLANTING_PHASE_CUT)
        {
            if (inner->colorPhase < 0x7d00)
            {
                inner->colorPhase += 0xff;
            }
            objSetColorFilter((s16)(inner->colorPhase >> 7), 0xff, 0xff);
        }
        else
        {
            objSetColorFilter(0xff, 0xff, 0xff);
        }
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    }
}

void MoonSeedPlantingSpot_hitDetect(void)
{
}

void MoonSeedPlantingSpot_update(GameObject* obj)
{
    MoonSeedPlantingSpotState* ex = obj->extra;
    ObjPlacement* setup = (ObjPlacement*)obj->anim.placementData;
    if (ex->flags & MSPLANTING_FLAG_PLANTED)
    {
        ex->phase = MSPLANTING_PHASE_GROWN;
        mainSetBits(ex->plantedGameBit, 1);
        ex->flags = ex->flags & ~MSPLANTING_FLAG_PLANTED;
        obj->anim.alpha = 0xff;
    }
    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) &&
        !(obj->anim.resetHitboxFlags & INTERACT_FLAG_DISABLED))
    {
        if (mainGetBit(GAMEBIT_MOONSEED_COUNT) != 0)
        {
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
        else
        {
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
    }
    ex->flags |= MSPLANTING_FLAG_VISIBLE;
    switch (ex->phase)
    {
    case MSPLANTING_PHASE_INIT:
        ex->phase = MSPLANTING_PHASE_EMPTY;
        obj->anim.localPosY = setup->posY - 10.0f;
        if (mainGetBit(ex->plantedGameBit) != 0)
        {
            ex->phase = MSPLANTING_PHASE_GROWN;
            obj->anim.localPosY = setup->posY;
            obj->anim.alpha = 0xff;
        }
        if (mainGetBit(ex->harvestedGameBit) != 0)
        {
            MoonSeedPlantingSpotPlacement* setup2;
            MoonSeedPlantingSpotState* ex2;
            ex2 = obj->extra;
            setup2 = (MoonSeedPlantingSpotPlacement*)obj->anim.placementData;
            if (mainGetBit(ex2->plantedGameBit) != 0)
            {
                obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                mainSetBits(ex2->harvestedGameBit, 1);
                ex2->phase = MSPLANTING_PHASE_HARVESTED;
                obj->anim.localPosY = setup2->posY;
            }
        }
        break;
    case MSPLANTING_PHASE_EMPTY:
        if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) &&
            (*gGameUIInterface)->isItemBeingUsed(GAMEBIT_MOONSEED_COUNT) != 0)
        {
            int cnt = mainGetBit(GAMEBIT_MOONSEED_COUNT);
            if (cnt != 0)
            {
                obj->anim.localPosY = setup->posY;
                obj->anim.alpha = 0;
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                mainSetBits(GAMEBIT_MOONSEED_COUNT, cnt - 1);
                obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            }
        }
        break;
    case MSPLANTING_PHASE_GROWN:
    {
        int tricky = (int)getTrickyObject();
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        if (ex->flags & MSPLANTING_FLAG_VISIBLE)
        {
            GameObject* player;
            if (ex->flags & MSPLANTING_FLAG_BURST)
            {
                obj->anim.localPosY = setup->posY + (f32)randomGetRange(-1, 1);
                (*gPartfxInterface)->spawnObject((void*)obj, MSPLANTING_PARTFX, NULL, 2, -1, NULL);
            }
            ex->burstTimer = ex->burstTimer - timeDelta;
            if (ex->burstTimer <= 0.0f)
            {
                if (randomGetRange(0, 1) != 0)
                {
                    ex->burstTimer = 45.0f;
                    ex->flags |= MSPLANTING_FLAG_BURST;
                    Sfx_PlayFromObject(obj, SFXTRIG_pk_moonseed_rattle);
                }
                else
                {
                    ex->burstTimer = (f32)randomGetRange(0x32, 200);
                    ex->flags &= ~MSPLANTING_FLAG_BURST;
                }
            }
            player = Obj_GetPlayerObject();
            if (player != NULL &&
                getXZDistanceSquared(&player->anim.worldPosX, &obj->anim.worldPosX) <= 10000.0f)
            {
                objfx_spawnDirectionalBurst((void*)obj, 5, 1.0f, 5, 1, 0x28, 7.0f, NULL, 0);
                TRICKY_INTERFACE(tricky)->sideCommandEnable((GameObject*)tricky, obj, MSPLANTING_TRICKY_COMMAND_KIND,
                                                           MSPLANTING_TRICKY_COMMAND_TYPE);
            }
            else
            {
                objfx_spawnDirectionalBurst((void*)obj, 5, 1.0f, 6, 1, 0x28, 5.0f, NULL, 0);
            }
            if (ObjHits_GetPriorityHit(obj, 0, 0, 0) == MSPLANTING_HIT_CUT)
            {
                ex->phase = MSPLANTING_PHASE_CUT;
                ex->colorPhase = 0;
                ex->growthTimer = 30.0f;
            }
        }
        break;
    }
    case MSPLANTING_PHASE_CUT:
    {
        GameObject* tricky = getTrickyObject();
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        obj->anim.localPosY = setup->posY;
        if (getXZDistanceSquared(&tricky->anim.worldPosX, &obj->anim.worldPosX) <= 10000.0f)
        {
            objfx_spawnDirectionalBurst((void*)obj, 5, 1.0f, 5, 1, 0x28, 7.0f, NULL, 0);
        }
        else
        {
            objfx_spawnDirectionalBurst((void*)obj, 5, 1.0f, 6, 1, 0x28, 5.0f, NULL, 0);
        }
        if (ex->growthTimer <= 0.0f &&
            mainGetBit(ex->plantedGameBit) != 0 &&
            mainGetBit(ex->harvestedGameBit) == 0)
        {
            MoonSeedPlantingSpotPlacement* setup2;
            MoonSeedPlantingSpotState* ex2;
            ex2 = obj->extra;
            setup2 = (MoonSeedPlantingSpotPlacement*)obj->anim.placementData;
            if (mainGetBit(ex2->plantedGameBit) != 0)
            {
                obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                mainSetBits(ex2->harvestedGameBit, 1);
                ex2->phase = MSPLANTING_PHASE_HARVESTED;
                obj->anim.localPosY = setup2->posY;
            }
        }
        ex->growthTimer = ex->growthTimer - timeDelta;
        if (ex->growthTimer < 0.0f)
        {
            ex->growthTimer = 0.0f;
        }
        break;
    }
    }
}

void MoonSeedPlantingSpot_init(GameObject* obj, MoonSeedPlantingSpotPlacement* init)
{
    MoonSeedPlantingSpotState* inner;
    int ident;

    inner = obj->extra;
    obj->animEventCallback = MoonSeedPlantingSpot_SeqFn;
    obj->anim.rotX = (s16)(init->rotByte << 8);
    inner->phase = MSPLANTING_PHASE_INIT;
    objAddObjectType(obj, MSPLANTING_OBJ_GROUP);
    ident = init->ident;
    switch (ident)
    {
    case 0x41a5b:
        inner->plantedGameBit = 0x866;
        inner->harvestedGameBit = 0x856;
        break;
    case 0x41a59:
        inner->plantedGameBit = 0x867;
        inner->harvestedGameBit = 0x858;
        break;
    case 0x41a5c:
        inner->plantedGameBit = 0x868;
        inner->harvestedGameBit = 0x85a;
        break;
    case 0x41a5d:
        inner->plantedGameBit = 0x869;
        inner->harvestedGameBit = 0x864;
        break;
    case 0x43e04:
        inner->plantedGameBit = 0x9a2;
        inner->harvestedGameBit = 0x99a;
        break;
    case 0x43e1f:
        inner->plantedGameBit = 0x9a3;
        inner->harvestedGameBit = 0x99c;
        break;
    case 0x43e20:
        inner->plantedGameBit = 0x9a4;
        inner->harvestedGameBit = 0x99e;
        break;
    case 0x43e21:
        inner->plantedGameBit = 0x9a5;
        inner->harvestedGameBit = 0x9a0;
        break;
    case 0x476ae:
        inner->plantedGameBit = 0x3d5;
        inner->harvestedGameBit = 0x3d2;
        break;
    case 0x4b26e:
        inner->plantedGameBit = 0xd4d;
        inner->harvestedGameBit = 0xd4b;
        break;
    case 0x4bea3:
        inner->plantedGameBit = 0xe21;
        inner->harvestedGameBit = 0xe10;
        break;
    }
    inner->flags = 0;
}

void MoonSeedPlantingSpot_release(void)
{
}

void MoonSeedPlantingSpot_initialise(void)
{
}

ObjectDescriptor14 gMoonSeedPlantingSpotObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_14_SLOTS,
    (ObjectDescriptorCallback)MoonSeedPlantingSpot_initialise,
    (ObjectDescriptorCallback)MoonSeedPlantingSpot_release,
    0,
    (ObjectDescriptorCallback)MoonSeedPlantingSpot_init,
    (ObjectDescriptorCallback)MoonSeedPlantingSpot_update,
    (ObjectDescriptorCallback)MoonSeedPlantingSpot_hitDetect,
    (ObjectDescriptorCallback)MoonSeedPlantingSpot_render,
    (ObjectDescriptorCallback)MoonSeedPlantingSpot_free,
    (ObjectDescriptorCallback)MoonSeedPlantingSpot_getObjectTypeId,
    MoonSeedPlantingSpot_getExtraSize,
    (ObjectDescriptorCallback)MoonSeedPlantingSpot_cutOrHarvest,
    (ObjectDescriptorCallback)MoonSeedPlantingSpot_func0B,
    (ObjectDescriptorCallback)MoonSeedPlantingSpot_modelMtxFn,
    (ObjectDescriptorCallback)MoonSeedPlantingSpot_render2,
};
