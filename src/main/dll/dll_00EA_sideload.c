/*
 * sideload (DLL 0x00EA) [0x80171BAC-0x80171C78).
 *
 * The only function this object contributes is sideload_update: a deferred
 * spawner placed in a map. Each tick, once the level has finished loading
 * (Obj_IsLoadingLocked), the player object exists, Tricky is absent, and the
 * placement's arming game bit (placement+0x18) is set, it allocates an object
 * setup (type 0x24), copies the spawner's position into it, hands it to
 * Obj_SetupObject, and seeds the new object's first field from placement
 * field yawByte (<< 8).
 *
 * Foreign ObjectDescriptor tables are not present in this translation unit;
 * each descriptor is defined by its own DLL.
 */
#include "main/game_object.h"
#include "main/objlib.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"

/* object id sideload_update defers into existence once its arming game bit is set */
#define SIDELOAD_CHILD_OBJ 0x24

typedef struct SideloadPlacement
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    f32 posX; /* 0x08 */
    f32 posY; /* 0x0C */
    f32 posZ; /* 0x10 */
    u8 pad14[0x18 - 0x14];
    s16 armGameBit; /* 0x18: arming game bit */
    u8 yawByte;     /* 0x1A: spawn yaw, shifted << 8 into the child's s16 rotation */
    u8 pad1B[0x3C - 0x1B];
    s16 unk3C;
    u8 pad3E[0x48 - 0x3E];
    void* unk48;
    u8 pad4C[0x50 - 0x4C];
    f32 unk50;
    u8 pad54[0x70 - 0x54];
    u8 unk70;
    u8 pad71[0x98 - 0x71];
    f32 unk98;
    u8 pad9C[0xAA - 0x9C];
    u8 unkAA;
    u8 padAB[0xB0 - 0xAB];
    s16 unkB0;
    u8 padB2[0xB8 - 0xB2];
    f32 unkB8;
    f32 unkBC;
    f32 unkC0;
    u8 padC4[0x2B1 - 0xC4];
    s8 unk2B1;
    u8 pad2B2[0x2B8 - 0x2B2];
} SideloadPlacement;

extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern int* Obj_SetupObject(void* setup, int a, int b, int c, void* d);

void sideload_update(int self)
{
    int state;
    void* obj;
    short* p;

    state = *(int*)&((GameObject*)self)->anim.placementData;
    if ((Obj_IsLoadingLocked() != 0) && (Obj_GetPlayerObject() != 0) && (getTrickyObject() == 0) &&
        (mainGetBit((int)((SideloadPlacement*)state)->armGameBit) != 0))
    {
        obj = Obj_AllocObjectSetup(0x18, SIDELOAD_CHILD_OBJ);
        *(u8*)((char*)obj + 4) = 2;
        *(u8*)((char*)obj + 5) = 4;
        *(u8*)((char*)obj + 7) = 0xff;
        ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)self)->anim.localPosX;
        ((GameObject*)obj)->anim.localPosX = ((GameObject*)self)->anim.localPosY;
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)self)->anim.localPosZ;
        p = (short*)Obj_SetupObject(obj, 5, -1, -1, NULL);
        *p = (short)((u8)((SideloadPlacement*)state)->yawByte << 8);
    }
}
