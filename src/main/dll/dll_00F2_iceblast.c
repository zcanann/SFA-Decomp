/*
 * iceblast (DLL 0xF2) - a path-following ice projectile in the
 * pushable/transporter object family (shares the dll_00EF pushable
 * descriptor; sibling of flameblast/invhit/warppoint).
 *
 * The blast rides the player's first child path object: iceblast_update
 * copies that path object's heading into the blast's rotation, runs a
 * per-frame countdown timer and, each time the timer expires, re-seeds
 * the launch position from the rotated heading and the path's world
 * point, then integrates localPos by velocity*timeDelta every frame.
 * The placement's useAltHitVolume byte selects the hit-volume slot (3 when set,
 * else 1). The 4-byte extra holds only the countdown timer.
 */
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/gameplay_runtime.h"
#include "main/objlib.h"

typedef struct IceblastPlacement
{
    u8 pad0[0x19 - 0x0];
    s8 useAltHitVolume;
    s16 initialTimer;
    u8 pad1C[4];
} IceblastPlacement;

extern void vecRotateZXY(void* in, void* out);
extern f32 timeDelta;
extern f32 lbl_803E3600;
extern f32 lbl_803E3604;
extern f32 lbl_803E3608;
extern f32 lbl_803E360C;

void iceblast_free(void)
{
}

void iceblast_hitDetect(void)
{
}

void iceblast_release(void)
{
}

void iceblast_initialise(void)
{
}

int iceblast_getExtraSize(void) { return 0x4; }
int iceblast_getObjectTypeId(void) { return 0x0; }

void iceblast_render(int* obj, int a, int b, int c, int d) { objRenderFn_8003b8f4((int)obj, a, b, c, d, lbl_803E3600); }

#pragma scheduling off
void iceblast_init(int obj, IceblastPlacement* p)
{
    *(f32*)((GameObject*)obj)->extra = p->initialTimer;
    ObjHits_SetTargetMask(obj, 1);
}
#pragma reset

void iceblast_update(int* obj)
{
    int* path;
    f32* state;
    int* player;
    IceblastPlacement* def;
    struct
    {
        s16 dir[3];
        s16 pad;
        f32 pos[4];
    } vec;
    player = Obj_GetPlayerObject();
    state = ((GameObject*)obj)->extra;
    def = *(IceblastPlacement**)&((GameObject*)obj)->anim.placementData;
    if (player != NULL && (path = ((GameObject*)player)->childObjs[0]) != NULL)
    {
        ((GameObject*)obj)->anim.rotZ = *(s16*)((char*)path + 4);
        ((GameObject*)obj)->anim.rotY = *(s16*)((char*)path + 2);
        ((GameObject*)obj)->anim.rotX = *(s16*)path;
    }
    else
    {
        return;
    }
    {
        int slot = def->useAltHitVolume != 0 ? 3 : 1;
        ObjHits_SetHitVolumeSlot((u32)obj, 0x10, slot, 0);
    }
    state[0] = state[0] - timeDelta;
    {
        f32 zero;
        f32 cur = state[0];
        if (cur <= (zero = lbl_803E3604))
        {
            state[0] = cur + lbl_803E3608;
            ((f32*)(int)obj)[9] = zero;
            ((f32*)obj)[11] = zero;
            ((f32*)obj)[10] = lbl_803E360C;
            vec.pos[1] = zero;
            vec.pos[2] = zero;
            vec.pos[3] = zero;
            vec.pos[0] = lbl_803E3600;
            vec.dir[2] = *(s16*)((char*)path + 4);
            vec.dir[1] = *(s16*)((char*)path + 2);
            vec.dir[0] = *(s16*)path;
            vecRotateZXY(&vec, (f32*)((char*)obj + 0x24));
            ObjPath_GetPointWorldPosition((int)path, 0, &((GameObject*)obj)->anim.localPosX,
                                          &((GameObject*)obj)->anim.localPosY, &((GameObject*)obj)->anim.localPosZ, 0);
            ObjHits_EnableObject((u32)obj);
        }
    }
    ((GameObject*)obj)->anim.previousLocalPosX = ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.previousLocalPosY = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.previousLocalPosZ = ((GameObject*)obj)->anim.localPosZ;
    ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.velocityX * timeDelta + ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.velocityZ * timeDelta + ((GameObject*)obj)->anim.localPosZ;
}
