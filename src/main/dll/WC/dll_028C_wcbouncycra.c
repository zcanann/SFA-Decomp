#include "main/dll/WC/dll_028C_wcbouncycra.h"
#include "main/frame_timing.h"
#include "main/game_object.h"
#include "main/obj_group.h"
#include "main/object_render_legacy.h"
#include "main/object_descriptor.h"

#define WCBLOCK_VARIANT_A          1

#define WCBLOCK_GRID_IFACE(state) (*(WCBlockGridInterface**)((state)->controller->anim.dll))

#define WBOUNCY_EXTRA_SIZE         0xc
#define WBOUNCY_FLAG_ACTIVE        1
#define WBOUNCY_TRIGGER_GROUP      3
#define WBOUNCY_RESET_COOLDOWN     0x28
#define WBOUNCY_MAX_BOUNCES        0xa

int WCBouncyCra_getExtraSize(void)
{
    return WBOUNCY_EXTRA_SIZE;
}

int WCBouncyCra_getObjectTypeId(void)
{
    return 0;
}

void WCBouncyCra_free(void)
{
}

void WCBouncyCra_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E6D38);
    }
}

void WCBouncyCra_hitDetect(void)
{
}

void WCBouncyCra_update(GameObject* obj)
{
    WCBouncyCrateState* state = (obj)->extra;

    if ((state->flags & WBOUNCY_FLAG_ACTIVE) == 0)
    {
        s16 n = (s16)((f32)state->cooldown - timeDelta);
        state->cooldown = n;
        if (n <= 0)
        {
            f32 dist;
            f32 v = gBouncyCrateTriggerSearchRadius;

            if ((void*)ObjGroup_FindNearestObject(WBOUNCY_TRIGGER_GROUP, (int)obj, &v) == NULL)
            {
                dist = lbl_803E6D24;
            }
            else
            {
                f32 vv = v;
                dist = gBouncyCrateNearDistance;
                if (vv < dist)
                {
                    dist = lbl_803E6D2C;
                }
                else if (vv > gBouncyCrateFarDistance)
                {
                    dist = lbl_803E6D24;
                }
                else
                {
                    dist = (vv - dist) / lbl_803E6D34;
                    dist = lbl_803E6D38 - dist;
                    dist = dist * lbl_803E6D2C;
                }
            }
            (obj)->anim.velocityY = dist;
            state->flags |= WBOUNCY_FLAG_ACTIVE;
            state->bounceCount = 0;
        }
    }
    else
    {
        (obj)->anim.velocityY = gBouncyCrateGravity * timeDelta + (obj)->anim.velocityY;
        (obj)->anim.localPosY = (obj)->anim.velocityY * timeDelta + (obj)->anim.localPosY;
        if ((obj)->anim.localPosY <= state->homeY)
        {
            (obj)->anim.localPosY = (obj)->anim.localPosY + (state->homeY - (obj)->anim.localPosY);
            (obj)->anim.velocityY = gBouncyCrateRestitution * -(obj)->anim.velocityY;
            state->bounceCount += 1;
            if (state->bounceCount > WBOUNCY_MAX_BOUNCES)
            {
                state->flags &= ~WBOUNCY_FLAG_ACTIVE;
                state->cooldown = WBOUNCY_RESET_COOLDOWN;
                (obj)->anim.localPosY = state->homeY;
                (obj)->anim.velocityY = lbl_803E6D24;
            }
        }
    }
}

void WCBouncyCra_init(GameObject* obj, ObjPlacement* setup)
{
    WCBouncyCrateState* state = obj->extra;

    state->homeY = setup->posY;
    state->cooldown = WBOUNCY_RESET_COOLDOWN;
}

void WCBouncyCra_release(void)
{
}

void WCBouncyCra_initialise(void)
{
}

int wcblock_isPlayerAwayFromStoredCell(GameObject* obj, WCBlockState* state, GameObject* player)
{
    ObjAnimComponent* objAnim;
    GameObject* playerObj;
    f32 cellX;
    f32 cellZ;
    f32 pos;
    f32 min;
    f32 max;
    WCBlockGridInterface* iface;

    objAnim = &obj->anim;
    if (objAnim->bankIndex == WCBLOCK_VARIANT_A)
    {
        iface->getCellXYA(state->tileIndex, &state->cellX, &state->cellZ, (iface = WCBLOCK_GRID_IFACE(state)));
        iface->getCellWorldA((int)obj, state->cellX, state->cellZ, &cellX, &cellZ,
                             (iface = WCBLOCK_GRID_IFACE(state)));
    }
    else
    {
        iface->getCellXYB(state->tileIndex, &state->cellX, &state->cellZ, (iface = WCBLOCK_GRID_IFACE(state)));
        iface->getCellWorldB((int)obj, state->cellX, state->cellZ, &cellX, &cellZ,
                             (iface = WCBLOCK_GRID_IFACE(state)));
    }

    min = cellX - WCBLOCK_PLAYER_CELL_MARGIN;
    playerObj = (GameObject*)player;
    pos = playerObj->anim.localPosX;
    max = WCBLOCK_PLAYER_CELL_MARGIN + cellX;
    if (pos > max || pos < min)
    {
        return 1;
    }

    {
        f32 posZ;
        f32 minZ;
        f32 maxZ;

        minZ = cellZ - WCBLOCK_PLAYER_CELL_MARGIN;
        posZ = playerObj->anim.localPosZ;
        maxZ = WCBLOCK_PLAYER_CELL_MARGIN + cellZ;
        if (posZ > maxZ || posZ < minZ)
        {
            return 1;
        }
    }

    return 0;
}

#undef WCBLOCK_GRID_IFACE

ObjectDescriptor gWCBouncyCraObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)WCBouncyCra_initialise,
    (ObjectDescriptorCallback)WCBouncyCra_release,
    0,
    (ObjectDescriptorCallback)WCBouncyCra_init,
    (ObjectDescriptorCallback)WCBouncyCra_update,
    (ObjectDescriptorCallback)WCBouncyCra_hitDetect,
    (ObjectDescriptorCallback)WCBouncyCra_render,
    (ObjectDescriptorCallback)WCBouncyCra_free,
    (ObjectDescriptorCallback)WCBouncyCra_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)WCBouncyCra_getExtraSize,
};
