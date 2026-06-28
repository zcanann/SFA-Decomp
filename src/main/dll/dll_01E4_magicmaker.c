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
#include "main/game_object.h"

typedef struct MagicmakerPlacement
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
} MagicmakerPlacement;

/*
 * The 0x30-byte spawn descriptor handed back by Obj_AllocObjectSetup.
 * The head (0x00..0x17) is the common ObjPlacement record; the fields
 * past it are this creature class's per-spawn setup slots.
 */
typedef struct MagicmakerSetup
{
    ObjPlacement head;
    u8 pad18[0x1A - 0x18];
    u8 unk1A;
    u8 pad1B[0x1C - 0x1B];
    s16 unk1C;
    u8 pad1E[0x24 - 0x1E];
    s16 unk24;
    u8 pad26[0x2C - 0x26];
    s16 unk2C;
    s16 unk2E;
} MagicmakerSetup;

STATIC_ASSERT(offsetof(MagicmakerSetup, unk1A) == 0x1A);
STATIC_ASSERT(offsetof(MagicmakerSetup, unk1C) == 0x1C);
STATIC_ASSERT(offsetof(MagicmakerSetup, unk24) == 0x24);
STATIC_ASSERT(offsetof(MagicmakerSetup, unk2C) == 0x2C);
STATIC_ASSERT(offsetof(MagicmakerSetup, unk2E) == 0x2E);
STATIC_ASSERT(sizeof(MagicmakerSetup) == 0x30);

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
                    ((MagicmakerSetup*)objSetup)->unk1A = 0x14;
                    ((MagicmakerSetup*)objSetup)->unk2C = -1;
                    ((MagicmakerSetup*)objSetup)->unk1C = -1;
                    ((ObjPlacement*)objSetup)->posX = ((GameObject*)obj)->anim.localPosX + (f32)(int)
                    randomGetRange(-0x15e, 0x15e);
                    ((ObjPlacement*)objSetup)->posY = lbl_803E4D8C + ((GameObject*)obj)->anim.localPosY;
                    ((ObjPlacement*)objSetup)->posZ = ((GameObject*)obj)->anim.localPosZ + (f32)(int)
                    randomGetRange(-0x15e, 0x15e);
                    ((MagicmakerSetup*)objSetup)->unk24 = -1;
                    ((ObjPlacement*)objSetup)->color[0] = ((MagicmakerPlacement*)placement)->unk4;
                    ((ObjPlacement*)objSetup)->color[2] = ((MagicmakerPlacement*)placement)->unk6;
                    ((ObjPlacement*)objSetup)->color[1] = ((MagicmakerPlacement*)placement)->unk5;
                    ((ObjPlacement*)objSetup)->color[3] = ((MagicmakerPlacement*)placement)->unk7;
                    ((MagicmakerSetup*)objSetup)->unk2E = 3;
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
