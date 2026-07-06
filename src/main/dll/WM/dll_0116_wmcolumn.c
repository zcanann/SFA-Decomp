/*
 * wmcolumn (DLL 0x0116) - the carryable puzzle column at Krazoa Palace
 * (retail type 500 'GPSHpickobj'; its drop spots are type 499
 * 'GPSH_Scene' objects). TU: 0x8017D37C-0x8017D818, .text only - the
 * descriptor lives in the auto data unit.
 *
 * The column is a groundAnimator carryable. While held it clears the
 * game bit of any scene spot it is taken from; while down it snaps to
 * the nearest scene spot in range and sets/clears that spot's bit by
 * whether the column variant (seqId 500 + modelIndex) belongs there.
 * The unkF4 bits carry the held/down handshake between frames, and the
 * carryable is hidden + the pickup icon raised while the player stands
 * close holding nothing.
 */
#include "main/carryable_interface.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/objlib.h"

/* object group this column joins */
#define WMCOLUMN_OBJGROUP 4

#define WMCOLUMN_OBJFLAG_HITDETECT_DISABLED 0x2000

typedef struct WmColumnPlacement
{
    u8 pad0[0x18 - 0x0];
    u8 rotXByte;    /* 0x18: rotX in 1/256 turns */
    u8 modelIndex;  /* 0x19: bank index; the column variant's seqId is
                       500 + modelIndex (500 = retail type 'GPSHpickobj',
                       this DLL; 499 = its 'GPSH_Scene' spot object) */
    u8 pad1A[0x1E - 0x1A];
    s16 gameBit;    /* 0x1E: set while this column sits on its scene
                       spot, -1 = none */
} WmColumnPlacement;

STATIC_ASSERT(offsetof(WmColumnPlacement, gameBit) == 0x1E);





extern f32 Vec_distance(f32* a, f32* b);
extern int Obj_GetPlayerObject(void);
extern u32 playerGetStateFlag310(int obj);
extern void setAButtonIcon(int x);
extern f32 lbl_803E37B8; /* 1.0: render scale */
extern f32 lbl_803E37BC; /* 10000.0: nearest-object sentinel */
extern f32 lbl_803E37C0; /* 35.0: scene-spot snap radius */
extern f32 lbl_803E37C4; /* 60.0: pickup prompt distance */

int wm_column_getExtraSize(void)
{
    return 0xa;
}

int wm_column_getObjectTypeId(void)
{
    return 0;
}

void wm_column_free(int obj)
{
    ObjGroup_RemoveObject(obj, WMCOLUMN_OBJGROUP);
    (*gCarryableInterface)->free(obj);
}

void wm_column_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale); /* #57 */
    if ((*gCarryableInterface)->isVisible(obj, visible) != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E37B8);
    }
}

void wm_column_hitDetect(void)
{
}

void wm_column_update(int obj)
{
    int* objects;
    u32 playerFlags;
    f32 nearest;
    int i;
    int count;
    int other;
    int state;

    state = *(int*)&((GameObject*)obj)->extra;
    nearest = lbl_803E37BC;
    if ((*gCarryableInterface)->getAnimState(obj, *(int*)&((GameObject*)obj)->extra) != 0)
    {
        if ((((GameObject*)obj)->unkF4 & 2) != 0)
        {
            objects = ObjList_GetObjects(&i, &count);
            for (; i < count; i++)
            {
                other = objects[i];
                if (((u32)other != obj) && (((GameObject*)other)->anim.seqId == 499) &&
                    (Vec_distance((float*)(obj + 0x18), (float*)(other + 0x18)) < lbl_803E37C0))
                {
                    other = ((WmColumnPlacement*)((GameObject*)objects[i])->anim.placement)->gameBit;
                    if (other != -1)
                    {
                        GameBit_Set(other, 0);
                    }
                }
            }
        }
        playerFlags = Obj_GetPlayerObject();
        ObjGroup_FindNearestObject(0x10, obj, &nearest);
        playerFlags = playerGetStateFlag310(playerFlags);
        if (((playerFlags & 0x4000) != 0) && (nearest > lbl_803E37C4))
        {
            (*gCarryableInterface)->setVisible(state, 0);
            setAButtonIcon(5);
            *(u32*)&((GameObject*)obj)->unkF4 |= 1;
        }
        else
        {
            (*gCarryableInterface)->setVisible(state, 1);
        }
        *(u32*)&((GameObject*)obj)->unkF4 &= ~2;
    }
    else
    {
        /* just put down: snap to the nearest scene spot and set/clear
           its bit by whether this column variant belongs there */
        if ((((GameObject*)obj)->unkF4 & 1) != 0)
        {
            objects = ObjList_GetObjects(&i, &count);
            for (; i < count; i++)
            {
                other = objects[i];
                if (((u32)other != obj) && (((GameObject*)other)->anim.seqId == 499) &&
                    (Vec_distance((float*)(obj + 0x18), (float*)(other + 0x18)) < lbl_803E37C0))
                {
                    int mapData = *(int*)&((GameObject*)objects[i])->anim.placementData;
                    if (((GameObject*)obj)->anim.seqId == (s8)((WmColumnPlacement*)mapData)->modelIndex + 500)
                    {
                        if (((WmColumnPlacement*)mapData)->gameBit != -1)
                        {
                            GameBit_Set(((WmColumnPlacement*)mapData)->gameBit, 1);
                        }
                    }
                    else if (((WmColumnPlacement*)mapData)->gameBit != -1)
                    {
                        GameBit_Set(((WmColumnPlacement*)mapData)->gameBit, 0);
                    }
                    ((GameObject*)obj)->anim.localPosX = ((GameObject*)objects[i])->anim.localPosX;
                    ((GameObject*)obj)->anim.localPosY = ((GameObject*)objects[i])->anim.localPosY;
                    ((GameObject*)obj)->anim.localPosZ = ((GameObject*)objects[i])->anim.localPosZ;
                }
            }
        }
        playerFlags = playerGetStateFlag310(Obj_GetPlayerObject());
        if ((playerFlags & 0x4000) != 0)
        {
            (*gCarryableInterface)->setVisible(state, 0);
            *(u32*)&((GameObject*)obj)->unkF4 |= 2;
        }
        else
        {
            (*gCarryableInterface)->setVisible(state, 1);
            *(u32*)&((GameObject*)obj)->unkF4 &= ~2;
        }
        *(u32*)&((GameObject*)obj)->unkF4 &= ~1;
    }
}

void wm_column_init(GameObject* obj, WmColumnPlacement* mapData)
{
    int state = *(int*)&obj->extra;
    obj->anim.rotX = (s16)(mapData->rotXByte << 8);
    obj->objectFlags |= WMCOLUMN_OBJFLAG_HITDETECT_DISABLED;
    obj->unkF4 = 0;
    obj->anim.bankIndex = mapData->modelIndex;
    if (obj->anim.bankIndex >= obj->anim.modelInstance->modelCount)
    {
        obj->anim.bankIndex = 0;
    }
    (*gCarryableInterface)->initAnim(obj, state, 0x32);
    ObjGroup_AddObject((int)obj, WMCOLUMN_OBJGROUP);
}

void wm_column_release(void)
{
}

void wm_column_initialise(void)
{
}
