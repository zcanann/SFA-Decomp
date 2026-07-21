/*
 * magicmaker (DLL 0x1E4) - a magic-creature spawner object placed in
 * the world.  Each frame that game bit 0x26B is set it clears the bit,
 * scans object group 4 for objects whose anim.seqId (obj+0x46) matches one
 * of the six spawn object IDs in gMagicMakerSpawnObjectIds, and if fewer than 10
 * such creatures exist it spawns a new one at a random XZ offset around
 * the placer's position.  The spawned creature inherits the four
 * per-instance spawn params from the placer's placement record.
 * Three hitDetect registrations are applied to the new creature
 * immediately after spawn.
 */
#include "main/obj_placement.h"
#include "main/object_render.h"
#include "main/vecmath.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/object.h"
#include "main/obj_group.h"
#include "main/objfx.h"
#include "main/object_api.h"
#include "main/gamebits_api.h"
#include "main/dll/dll_01E4_magicmaker.h"

#define MAGICMAKER_SPAWN_GAMEBIT       0x26b /* set-by-others trigger; cleared each spawn attempt */
#define MAGICMAKER_CREATURE_GROUP      4     /* object group scanned for existing creatures */
#define MAGICMAKER_SPAWN_OBJECT_COUNT  6
#define MAGICMAKER_MAX_CREATURES       10    /* spawn only while fewer than this many exist */
#define MAGICMAKER_SPAWN_RADIUS        350
#define MAGICMAKER_HIT_BURST_COUNT     3

enum MagicMakerSpawnObjectId
{
    MAGICMAKER_OBJ_MAGIC_DUST_SMALL = 0x2C4,
    MAGICMAKER_OBJ_MAGIC_DUST_MID = 0x2CD,
    MAGICMAKER_OBJ_MAGIC_DUST_LARGE = 0x2CE,
    MAGICMAKER_OBJ_MAGIC_DUST_HUGE = 0x2CF,
    MAGICMAKER_OBJ_ENERGY_EGG = 0xB
};

u16 gMagicMakerSpawnObjectIds[MAGICMAKER_SPAWN_OBJECT_COUNT] = {
    MAGICMAKER_OBJ_MAGIC_DUST_SMALL,
    MAGICMAKER_OBJ_MAGIC_DUST_MID,
    MAGICMAKER_OBJ_MAGIC_DUST_LARGE,
    MAGICMAKER_OBJ_MAGIC_DUST_HUGE,
    MAGICMAKER_OBJ_ENERGY_EGG,
    MAGICMAKER_OBJ_ENERGY_EGG,
};

int magicmaker_getExtraSize(void)
{
    return 0x0;
}
int magicmaker_getObjectTypeId(void)
{
    return 0x0;
}

void magicmaker_free(void)
{
}

void magicmaker_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, gMagicMakerRenderScale);
}

void magicmaker_hitDetect(void)
{
}

void magicmaker_update(GameObject* obj)
{
    MagicmakerPlacement* placement;
    GameObject* spawnedObj;
    int matchCount;
    int groupCount;
    GameObject** objList;
    int i;
    int j;
    MagicmakerSetup* objSetup;
    GameObject* groupObj;

    placement = (MagicmakerPlacement*)obj->anim.placementData;
    if (Obj_IsLoadingLocked() != 0)
    {
        if ((u32)mainGetBit(MAGICMAKER_SPAWN_GAMEBIT) != 0u)
        {
            mainSetBits(MAGICMAKER_SPAWN_GAMEBIT, 0);
            objList = (GameObject**)ObjGroup_GetObjects(MAGICMAKER_CREATURE_GROUP, &groupCount);
            matchCount = 0;
            for (i = 0; i < groupCount; i++)
            {
                groupObj = *objList;
                for (j = 0; j < MAGICMAKER_SPAWN_OBJECT_COUNT; j++)
                {
                    if (groupObj->anim.seqId == gMagicMakerSpawnObjectIds[j])
                    {
                        matchCount++;
                    }
                }
                objList++;
            }
            if (matchCount < MAGICMAKER_MAX_CREATURES)
            {
                objSetup = (MagicmakerSetup*)Obj_AllocObjectSetup(
                    sizeof(MagicmakerSetup),
                    gMagicMakerSpawnObjectIds[randomGetRange(0, MAGICMAKER_SPAWN_OBJECT_COUNT - 1)]);
                if (objSetup != NULL)
                {
                    objSetup->unk1A = 0x14;
                    objSetup->unk2C = -1;
                    objSetup->unk1C = -1;
                    objSetup->base.posX = obj->anim.localPosX +
                                          (f32)(int)randomGetRange(-MAGICMAKER_SPAWN_RADIUS,
                                                                   MAGICMAKER_SPAWN_RADIUS);
                    objSetup->base.posY = gMagicMakerSpawnHeightOffset + obj->anim.localPosY;
                    objSetup->base.posZ = obj->anim.localPosZ +
                                          (f32)(int)randomGetRange(-MAGICMAKER_SPAWN_RADIUS,
                                                                   MAGICMAKER_SPAWN_RADIUS);
                    objSetup->gameBit = -1;
                    objSetup->base.color[0] = placement->base.color[0];
                    objSetup->base.color[2] = placement->base.color[2];
                    objSetup->base.color[1] = placement->base.color[1];
                    objSetup->base.color[3] = placement->base.color[3];
                    objSetup->unk2E = 3;
                    spawnedObj = Obj_SetupObject(&objSetup->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                    if (spawnedObj != NULL)
                    {
                        i = MAGICMAKER_HIT_BURST_COUNT;
                        do
                        {
                            objfx_spawnHitEffectBurst((char*)spawnedObj, gMagicMakerRenderScale, 2, 2, 0x64, NULL);
                            i--;
                        } while (i != 0);
                    }
                }
            }
        }
    }
}

void magicmaker_init(void)
{
}

void magicmaker_release(void)
{
}

void magicmaker_initialise(void)
{
}

ObjectDescriptor10WithPadding gMAGICMakerObjDescriptor = {
    {
        0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        (ObjectDescriptorCallback)magicmaker_initialise,
        (ObjectDescriptorCallback)magicmaker_release,
        0,
        (ObjectDescriptorCallback)magicmaker_init,
        (ObjectDescriptorCallback)magicmaker_update,
        (ObjectDescriptorCallback)magicmaker_hitDetect,
        (ObjectDescriptorCallback)magicmaker_render,
        (ObjectDescriptorCallback)magicmaker_free,
        (ObjectDescriptorCallback)magicmaker_getObjectTypeId,
        magicmaker_getExtraSize,
    },
    0,
};
