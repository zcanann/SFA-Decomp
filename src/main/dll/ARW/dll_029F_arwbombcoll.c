#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

#include "main/audio/sfx_ids.h"

typedef struct ArwbombcollHandleArwingHitPlacement
{
    u8 pad0[0x1E - 0x0];
    s16 eventId;
} ArwbombcollHandleArwingHitPlacement;

typedef struct ARWBombCollSetup
{
    ObjPlacement base;
    s8 rotX;
    u8 pad19[0x24 - 0x19];
} ARWBombCollSetup;

STATIC_ASSERT(sizeof(ARWBombCollSetup) == 0x24);
STATIC_ASSERT(offsetof(ARWBombCollSetup, rotX) == 0x18);

int arwbombcoll_getExtraSize(void) { return 8; }

int arwbombcoll_getObjectTypeId(void) { return 0; }

void arwbombcoll_free(void)
{
}

void arwbombcoll_hitDetect(void)
{
}

void arwbombcoll_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7078);
}

void arwbombcoll_init(int obj, int setup)
{
    ObjAnimComponent* objAnim = &((GameObject*)obj)->anim;
    ARWBombCollSetup* mapData = (ARWBombCollSetup*)setup;

    ((GameObject*)obj)->anim.rotX = (s16)(mapData->rotX << 8);
    objAnim->alpha = 0;
}

void arwbombcoll_release(void)
{
}

void arwbombcoll_initialise(void)
{
}

void arwbombcoll_updateMovingAxis(int obj, RingState* state)
{
    u8 mode = state->route;
    if (mode == 1 || mode == 3)
    {
        f32 edge, cur, lim;
        ((GameObject*)obj)->anim.localPosX = state->pullHeight * timeDelta + ((GameObject*)obj)->anim.localPosX;
        cur = ((GameObject*)obj)->anim.localPosX;
        lim = state->origX;
        edge = lim + (f32)(u32)
        state->linkId;
        if (cur > edge)
        {
            ((GameObject*)obj)->anim.localPosX = edge - (cur - edge);
            state->pullHeight = -state->pullHeight;
        }
        else
        {
            edge = lim - (f32)(u32)
            state->linkId;
            if (cur < edge)
            {
                ((GameObject*)obj)->anim.localPosX = edge - (cur - edge);
                state->pullHeight = -state->pullHeight;
            }
        }
    }
    else if (mode == 4 || mode == 5)
    {
        f32 edge, cur, lim;
        ((GameObject*)obj)->anim.localPosY = state->pullHeight * timeDelta + ((GameObject*)obj)->anim.localPosY;
        cur = ((GameObject*)obj)->anim.localPosY;
        lim = state->origY;
        edge = lim + (f32)(u32)
        state->linkId;
        if (cur > edge)
        {
            ((GameObject*)obj)->anim.localPosY = edge - (cur - edge);
            state->pullHeight = -state->pullHeight;
        }
        else
        {
            edge = lim - (f32)(u32)
            state->linkId;
            if (cur < edge)
            {
                ((GameObject*)obj)->anim.localPosY = edge - (cur - edge);
                state->pullHeight = -state->pullHeight;
            }
        }
    }
}

#pragma peephole off
void arwbombcoll_handleArwingHit(int obj, RingState* state, int arwing)
{
    GameObject* arwingObj = (GameObject*)arwing;
    int setup = *(int*)&((GameObject*)obj)->anim.placementData;
    u8 mode = state->mode;
    if (mode == 0)
    {
        Sfx_PlayFromObject(arwing, SFXbaddie_eba_pollenspin);
        if (arwingObj->anim.seqId == 0x601)
        {
            arwarwing_addShield(arwing, 1);
            arwarwing_addScore(arwing, 0xa);
        }
    }
    else if (mode == 1)
    {
        Sfx_PlayFromObject(arwing, SFXbaddie_eba_pollenspin);
        if (arwingObj->anim.seqId == 0x601)
        {
            arwarwing_addMaxShield(arwing, 1);
            arwarwing_addShield(arwing, arwarwing_getMaxShield(arwing));
        }
    }
    else if (mode == 3 || mode == 4)
    {
        Sfx_PlayFromObject(arwing, SFXbaddie_eba_pollenspin);
        gameBitIncrement(((ArwbombcollHandleArwingHitPlacement*)setup)->eventId);
    }
    else
    {
        Sfx_PlayFromObject(arwing, SFXbaddie_vambat_attack);
        if (arwingObj->anim.seqId == 0x601)
        {
            int seg;
            int got;
            arwarwing_incrementCollectedRingCount(arwing);
            arwarwing_addShield(arwing, 1);
            arwarwing_addScore(arwing, 0x14);
            seg = arwarwing_getRequiredRingCount(arwing);
            got = arwarwing_getCollectedRingCount(arwing);
            if (got == seg)
            {
                if (state->flags.bit20)
                    gameTextFn_80125ba4(7);
            }
            else
            {
                if (state->flags.bit20)
                    gameTextFn_80125ba4(9);
            }
        }
    }
    state->phase = 2;
}

#pragma peephole off
int arwbombcoll_checkArwingCollision(int obj, RingState* state, int arwing)
{
    ObjAnimComponent* objAnim = &((GameObject*)obj)->anim;
    ObjAnimComponent* arwingAnim = &((GameObject*)arwing)->anim;
    RingFlags* f = &state->flags;
    if (f->bit10)
    {
        f32 dx = objAnim->localPosX - arwingAnim->localPosX;
        f32 dy = objAnim->localPosY - arwingAnim->localPosY;
        f32 dz;
        if (dy < lbl_803E70A0)
            dy = -dy;
        dz = objAnim->localPosZ - arwingAnim->localPosZ;
        if (dy <= lbl_803E70A4)
        {
            if (dx * dx + dz * dz < lbl_803E70A8)
                return 1;
        }
    }
    else
    {
        f32 objZ = objAnim->localPosZ;
        f32 currentZDelta = objZ - arwingAnim->localPosZ;
        f32 previousZDelta = objZ - arwingAnim->previousLocalPosZ;
        if (currentZDelta <= lbl_803E70A0 && previousZDelta >= lbl_803E70A0)
        {
            f32 dx = objAnim->localPosX - arwingAnim->localPosX;
            f32 dy = objAnim->localPosY - arwingAnim->localPosY;
            if (sqrtf(dx * dx + dy * dy) < lbl_803E70AC)
                return 1;
            if (state->mode == 2 && f->bit20)
                gameTextFn_80125ba4(0xa);
        }
    }
    return 0;
}

void arwbombcoll_update(int obj)
{
    ObjAnimComponent* objAnim;
    ArwBombFlags* flags;
    int arw;
    ARWBombCollState* state;
    int a2;
    f32 thr;

    arw = getArwing();
    objAnim = &((GameObject*)obj)->anim;
    state = ((GameObject*)obj)->extra;
    flags = &state->flags;

    if (state->lifetime > (thr = lbl_803E707C))
    {
        state->lifetime -= timeDelta;
        if (state->lifetime <= thr)
        {
            Obj_FreeObject(obj);
            return;
        }
    }

    if ((u32)arw != 0 && arwarwing_isExplodingOrWarping(arw) != 0)
    {
        flags->b80 = 0;
        ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        ObjHits_EnableObject(obj);
        return;
    }

    if (flags->b80 == 0)
    {
        a2 = getArwing();
        if ((((u32)a2 != 0) ? (((GameObject*)obj)->anim.localPosZ - ((GameObject*)a2)->anim.localPosZ < lbl_803E7080) : 0) != 0)
        {
            goto active;
        }
    }
    ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    objAnim->alpha = 0;
    return;
active :
    {
        int v;

        v = (int)
        (lbl_803E7084 * timeDelta + (f32)(u32)
        objAnim->alpha
        )
        ;
        if (v > 0xff)
        {
            v = 0xff;
        }
        objAnim->alpha = v;
        ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        ((GameObject*)obj)->anim.rotX = lbl_803E7088 * timeDelta + (f32) * &((GameObject*)obj)->anim.rotX;
        ObjHits_SetHitVolumeSlot(obj, 0x13, 0, 0);
        if (flags->b40 != 0)
        {
            if ((u32)((ObjHitsPriorityState*)objAnim->hitReactState)->lastHitObject != 0 &&
                (u32)((ObjHitsPriorityState*)objAnim->hitReactState)->lastHitObject == (u32)getArwing())
            {
                arwarwing_addScore(arw, 0x19);
                flags->b80 = 1;
                ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                ObjHits_DisableObject(obj);
            }
        }
        else
        {
            int hit;
            if (ObjHits_GetPriorityHit(obj, &hit, 0, 0) != 0 && (u32)hit != 0 &&
                (((GameObject*)hit)->anim.seqId == 0x604 || ((GameObject*)hit)->anim.seqId == 0x605))
            {
                arwarwing_addScore(arw, 0xf);
                flags->b40 = 1;
                Obj_SetActiveModelIndex(obj, 1);
                spawnExplosion(obj, lbl_803E708C, 1, 0, 0, 0, 0, 0, 2);
            }
            if ((u32)((ObjHitsPriorityState*)objAnim->hitReactState)->lastHitObject != 0 &&
                (u32)((ObjHitsPriorityState*)objAnim->hitReactState)->lastHitObject == (u32)getArwing())
            {
                ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                ObjHits_DisableObject(obj);
                spawnExplosion(obj, lbl_803E708C, 1, 0, 0, 0, 0, 0, 2);
            }
        }
        if ((u32)arw != 0 && flags->b80 != 0)
        {
            switch (((GameObject*)obj)->anim.seqId)
            {
            case 0x609:
                Sfx_PlayFromObject(obj, SFXbaddie_eba_hit);
                arwarwing_upgradeLaserLevel(arw);
                break;
            case 0x608:
                Sfx_PlayFromObject(obj, SFXbaddie_eba_leavesclose);
                arwarwing_addBomb(arw);
                break;
            case 0x60a:
                break;
            case 0x6d8:
                Sfx_PlayFromObject(obj, SFXbaddie_eba_leavesopen);
                arwarwing_incrementPickup6D8Count(arw);
                break;
            case 0x6d9:
                Sfx_PlayFromObject(obj, SFXbaddie_eba_leavesopen);
                arwarwing_incrementPickup6D9Count(arw);
                break;
            case 0x6db:
                Sfx_PlayFromObject(obj, SFXbaddie_eba_leavesopen);
                arwarwing_incrementPickup6DBCount(arw);
                break;
            case 0x6da:
                Sfx_PlayFromObject(obj, SFXbaddie_eba_leavesopen);
                arwarwing_incrementPickup6DACount(arw);
                break;
            }
        }
    }
}
