/*
 * magicmaker (DLL 0x1E4) - a magic-creature spawner object placed in
 * the world.  Each frame that game bit 0x26B is set it clears the bit,
 * scans object group 4 for objects whose anim.seqId (obj+0x46) matches one
 * of the six creature type IDs in lbl_80325CE8, and if fewer than 10
 * such creatures exist it spawns a new one at a random XZ offset around
 * the placer's position.  The spawned creature inherits the four
 * per-instance spawn params from the placer's placement record.
 * Three hitDetect registrations are applied to the new creature
 * immediately after spawn.
 */
#include "main/obj_placement.h"
#include "main/vecmath.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/dll/dll_01E4_magicmaker.h"

#define MAGICMAKER_SPAWN_GAMEBIT       0x26b /* set-by-others trigger; cleared each spawn attempt */
#define MAGICMAKER_CREATURE_GROUP      4     /* object group scanned for existing creatures */
#define MAGICMAKER_CREATURE_TYPE_COUNT 6     /* number of creature type IDs in lbl_80325CE8 */
#define MAGICMAKER_MAX_CREATURES       10    /* spawn only while fewer than this many exist */

extern u16 lbl_80325CE8[];
extern f32 lbl_803E4D8C;
extern f32 lbl_803E4D88;

extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern void mainSetBits(int eventId, int value);
extern int* ObjGroup_GetObjects(int group, int* countOut);
extern void* Obj_AllocObjectSetup(int size, int b);
extern char* Obj_SetupObject(char* setup, int a, int b, int c, int d);
extern void hitDetectFn_80097070(char* obj, f32 f, int a, int b, int c, int d);

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

void magicmaker_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E4D88);
}

void magicmaker_hitDetect(void)
{
}

void magicmaker_update(GameObject* obj)
{
    int placement;
    char* spawnedObj;
    int matchCount;
    int groupCount;
    int* objList;
    int i;
    int j;
    char* objSetup;
    int groupObj;

    placement = *(int*)&obj->anim.placementData;
    if (Obj_IsLoadingLocked() != 0)
    {
        if ((u32)mainGetBit(MAGICMAKER_SPAWN_GAMEBIT) != 0u)
        {
            mainSetBits(MAGICMAKER_SPAWN_GAMEBIT, 0);
            objList = ObjGroup_GetObjects(MAGICMAKER_CREATURE_GROUP, &groupCount);
            matchCount = 0;
            for (i = 0; i < groupCount; i++)
            {
                groupObj = *objList;
                for (j = 0; j < MAGICMAKER_CREATURE_TYPE_COUNT; j++)
                {
                    if (*(s16*)(groupObj + 0x46) == lbl_80325CE8[j])
                    {
                        matchCount++;
                    }
                }
                objList++;
            }
            if (matchCount < MAGICMAKER_MAX_CREATURES)
            {
                objSetup = Obj_AllocObjectSetup(0x30, lbl_80325CE8[randomGetRange(0, 5)]);
                if (objSetup != NULL)
                {
                    ((MagicmakerSetup*)objSetup)->unk1A = 0x14;
                    ((MagicmakerSetup*)objSetup)->unk2C = -1;
                    ((MagicmakerSetup*)objSetup)->unk1C = -1;
                    ((ObjPlacement*)objSetup)->posX = obj->anim.localPosX + (f32)(int)randomGetRange(-0x15e, 0x15e);
                    ((ObjPlacement*)objSetup)->posY = lbl_803E4D8C + obj->anim.localPosY;
                    ((ObjPlacement*)objSetup)->posZ = obj->anim.localPosZ + (f32)(int)randomGetRange(-0x15e, 0x15e);
                    ((MagicmakerSetup*)objSetup)->gameBit = -1;
                    ((ObjPlacement*)objSetup)->color[0] = ((MagicmakerPlacement*)placement)->colorR;
                    ((ObjPlacement*)objSetup)->color[2] = ((MagicmakerPlacement*)placement)->colorB;
                    ((ObjPlacement*)objSetup)->color[1] = ((MagicmakerPlacement*)placement)->colorG;
                    ((ObjPlacement*)objSetup)->color[3] = ((MagicmakerPlacement*)placement)->colorA;
                    ((MagicmakerSetup*)objSetup)->unk2E = 3;
                    spawnedObj = Obj_SetupObject(objSetup, 5, obj->anim.mapEventSlot, -1, *(int*)&obj->anim.parent);
                    if (spawnedObj != NULL)
                    {
                        i = 3;
                        do
                        {
                            hitDetectFn_80097070(spawnedObj, lbl_803E4D88, 2, 2, 0x64, 0);
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
