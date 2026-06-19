/*
 * magicmaker (DLL 0x1E4) - a magic-creature spawner object placed in
 * the world.  Each frame that game bit 0x26B is set it clears the bit,
 * scans object group 4 for objects whose classId (obj+0x46) matches one
 * of the six creature type IDs in lbl_80325CE8, and if fewer than 10
 * such creatures exist it spawns a new one at a random XZ offset around
 * the placer's position.  The spawned creature inherits the four
 * per-instance spawn params from the placer's placement record.
 * Three hitDetect registrations are applied to the new creature
 * immediately after spawn.
 */
#include "main/obj_placement.h"
#include "main/game_object.h"

typedef struct MagicmakerPlacement
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
} MagicmakerPlacement;

extern int randomGetRange(int lo, int hi);
extern void objRenderFn_8003b8f4(f32 scale);
extern u8 Obj_IsLoadingLocked(void);
extern void GameBit_Set(int eventId, int value);
extern int* ObjGroup_GetObjects(int group, int* countOut);
extern void* Obj_AllocObjectSetup(int size, int b);
extern char* Obj_SetupObject(char* setup, int a, int b, int c, int d);
extern void hitDetectFn_80097070(char* obj, f32 f, int a, int b, int c, int d);
extern u16 lbl_80325CE8[];
extern f32 lbl_803E4D8C;
extern f32 lbl_803E4D88;

void magicmaker_free(void)
{
}

void magicmaker_hitDetect(void)
{
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

void magicmaker_update(int obj)
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

    placement = *(int*)&((GameObject*)obj)->anim.placementData;
    if (Obj_IsLoadingLocked() != 0)
    {
        if ((u32)GameBit_Get(0x26b) != 0u)
        {
            GameBit_Set(0x26b, 0);
            objList = ObjGroup_GetObjects(4, &groupCount);
            matchCount = 0;
            for (i = 0; i < groupCount; i++)
            {
                groupObj = *objList;
                for (j = 0; j < 6; j++)
                {
                    if (*(s16*)(groupObj + 0x46) == lbl_80325CE8[j])
                    {
                        matchCount++;
                    }
                }
                objList++;
            }
            if (matchCount < 10)
            {
                objSetup = Obj_AllocObjectSetup(0x30, lbl_80325CE8[randomGetRange(0, 5)]);
                if (objSetup != NULL)
                {
                    *(u8*)(objSetup + 0x1a) = 0x14;
                    *(s16*)(objSetup + 0x2c) = -1;
                    *(s16*)(objSetup + 0x1c) = -1;
                    ((ObjPlacement*)objSetup)->posX = ((GameObject*)obj)->anim.localPosX + (f32)(int)
                    randomGetRange(-0x15e, 0x15e);
                    ((ObjPlacement*)objSetup)->posY = lbl_803E4D8C + ((GameObject*)obj)->anim.localPosY;
                    ((ObjPlacement*)objSetup)->posZ = ((GameObject*)obj)->anim.localPosZ + (f32)(int)
                    randomGetRange(-0x15e, 0x15e);
                    *(s16*)(objSetup + 0x24) = -1;
                    *(u8*)(objSetup + 0x4) = ((MagicmakerPlacement*)placement)->unk4;
                    *(u8*)(objSetup + 0x6) = ((MagicmakerPlacement*)placement)->unk6;
                    *(u8*)(objSetup + 0x5) = ((MagicmakerPlacement*)placement)->unk5;
                    *(u8*)(objSetup + 0x7) = ((MagicmakerPlacement*)placement)->unk7;
                    *(s16*)(objSetup + 0x2e) = 3;
                    spawnedObj = Obj_SetupObject(objSetup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                             *(int*)&((GameObject*)obj)->anim.parent);
                    if (spawnedObj != NULL)
                    {
                        i = 3;
                        do
                        {
                            hitDetectFn_80097070(spawnedObj, lbl_803E4D88, 2, 2, 0x64, 0);
                            i--;
                        }
                        while (i != 0);
                    }
                }
            }
        }
    }
}

int magicmaker_getExtraSize(void) { return 0x0; }
int magicmaker_getObjectTypeId(void) { return 0x0; }

void magicmaker_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4D88);
}
