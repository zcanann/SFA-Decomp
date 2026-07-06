/*
 * dll_16C - map-event boulder proxy object (object type id 0x3, extra size 0x24).
 *
 * Drives a "boulder" GameObject that mirrors a separately-spawned map-event
 * sub-object: on update it relinks to a member of object group 10 chosen by
 * seqId (364 normally, 367 for seqId 368), advances its 0x100 move, and fades
 * its render opacity by the player's distance to the linked object. Render is
 * gated by GameBit 0x3A2 / seqId 883 and suppressed when GameBit 110 is set
 * unless GameBit 898 is also set. The sequence callback (dll_16C_SeqFn) spawns
 * /frees a child object from a small id table (Blob10 @ lbl_802C2308) keyed by
 * subObjIndex, and forwards trigger commands (1/2/3) to the linked object's
 * vtable.
 *
 * This TU shares the DIM/magiclight extra-state family; the IMIceMountain,
 * MagicLight and CrRockfall layouts are size-asserted here as a build guard.
 */
#include "main/dll/blob10_struct.h"
#include "main/dll/dll16cstate_struct.h"
#include "main/dll/magiclightstate_struct.h"
#include "main/dll/crrockfall_types.h"
#include "main/game_object.h"
#include "main/dll/DIM/DIMboulder.h"
#include "main/gamebits.h"

/*
 * Per-object extra state for the IM ice-mountain event controller
 * (imicemountain_getExtraSize == 0x14).
 */
typedef struct IMIceMountainState
{
    u8 eventState; /* 0..7 event machine (imicemountain_updateEventState) */
    u8 pad01[3];
    s32 latchFlags; /* SCGameBitLatch record; bit 1 = latch fired this frame */
    s8 warpCountdown; /* state 6: frames until warpToMap(0x1A) */
    u8 pad09;
    s16 musicTrack; /* -1 or 26; Music_Trigger edge latch */
    u8 mapEventState; /* MEVT_QUERY result at init (1/2/5) */
    u8 pad0D[3];
    f32 warningTextTimer; /* shows text 0x351 while above the floor value */
} IMIceMountainState;

STATIC_ASSERT(sizeof(IMIceMountainState) == 0x14);

/*
 * Per-object extra state for the magiclight proximity light
 * (magiclight_getExtraSize == 0x14 for non-0x172 types).
 */

STATIC_ASSERT(sizeof(MagicLightState) == 0x14);

/*
 * Per-object extra state for the dll_16C map-event boulder proxy
 * (dll_16C_getExtraSize == 0x24).
 */

STATIC_ASSERT(sizeof(Dll16CState) == 0x24);

/*
 * Per-object extra state for the crrockfall falling rock
 * (crrockfall_getExtraSize == 0x14).
 */

STATIC_ASSERT(sizeof(CrRockfallState) == 0x14);

extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern void Obj_FreeObject(int*);
void dll_16C_syncSubObjectTransform(void* dst, void* src, int p1, int p2, int p3, int p4, int visible,
                                    int opacity, int reissueMove);
extern int objUpdateOpacity(int* obj);
extern void ObjPath_GetPointWorldPosition(int* obj, int idx, f32* x, f32* y, f32* z, int e);
extern f32 Vec_distance(f32* a, f32* b);
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int kind, int id);
extern int Obj_SetupObject(int handle, int a, int b, int c, int d);
extern u8 lbl_802C2308[];
extern int* ObjGroup_GetObjects(int group, int* countOut);
extern u8 framesThisStep;
extern f32 lbl_803E4748;
extern f32 lbl_803E474C;
extern f32 lbl_803E4758;
extern f32 lbl_803E475C;
extern f32 lbl_803E4760;
extern f32 lbl_803E4764;

void dll_16C_release(void)
{
}

void dll_16C_initialise(void)
{
}

int dll_16C_getExtraSize(void) { return 0x24; }
int dll_16C_getObjectTypeId(void) { return 0x3; }

void dll_16C_free(int* obj)
{
    int* p = (int*)((GameObject*)obj)->childObjs[0];
    if (p != NULL) Obj_FreeObject(p);
}

#pragma scheduling off
#pragma peephole off
void dll_16C_hitDetect(void* obj)
{
    Dll16CState* extra = ((GameObject*)obj)->extra;
    void* p = extra->linkedObj;
    if (p != NULL)
    {
        if ((*(int (**)(void*))(**(int**)((char*)p + 0x68) + 0x38))(p) == 2)
        {
            dll_16C_syncSubObjectTransform(obj, extra->linkedObj, 0, 0, 0, 0, 0, 0, 0);
        }
    }
}

void dll_16C_render(int* obj, int p1, int p2, int p3, int p4, s8 visible)
{
    Dll16CState* extra;
    int* p;
    int hit;

    if (((GameObject*)obj)->anim.seqId != 883)
    {
        if (GameBit_Get(110) != 0)
        {
            if (GameBit_Get(898) == 0) return;
        }
        extra = ((GameObject*)obj)->extra;
        p = extra->linkedObj;
        hit = 0;
        if (p != NULL)
        {
            if ((*(int (**)(int*))(**(int**)((char*)p + 0x68) + 0x38))(p) == 2)
            {
                hit = 1;
            }
        }
        if (hit != 0)
        {
            ((GameObject*)obj)->anim.flags |= 8;
            visible = objUpdateOpacity(p);
            dll_16C_syncSubObjectTransform(obj, p, p1, p2, p3, p4, visible, extra->opacity, 1);
        }
        else
        {
            ((GameObject*)obj)->anim.flags &= ~8;
        }
        if (visible != 0 && extra->opacity != 0)
        {
            u8 saved = *(u8*)((char*)obj + 0x37);
            if (hit != 0)
            {
                *(u8*)((char*)obj + 0x37) = extra->opacity;
            }
            ((void (*)(int*, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p1, p2, p3, p4, lbl_803E4758);
            ObjPath_GetPointWorldPosition(obj, 1, &extra->pathPointX, &extra->pathPointY, &extra->pathPointZ, 0);
            *(u8*)((char*)obj + 0x37) = saved;
        }
    }
    else
    {
        ((void (*)(int*, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p1, p2, p3, p4, lbl_803E4758);
    }
}

void dll_16C_init(void* obj, void* arg2)
{
    Dll16CState* extra;
    ((GameObject*)obj)->animEventCallback = dll_16C_SeqFn;
    if (((GameObject*)obj)->anim.modelState != NULL)
    {
        ((GameObject*)obj)->anim.modelState->flags |= 0x4000;
        ((GameObject*)obj)->anim.modelState->shadowTintA = 100;
        ((GameObject*)obj)->anim.modelState->shadowTintB = 150;
    }
    extra = ((GameObject*)obj)->extra;
    extra->linkedObj = NULL;
    extra->subObjIndex = *(s8*)((char*)arg2 + 0x27);
    extra->opacity = 0xff;
}

/* dll_16C_SeqFn: per-frame sequence callback - manage the spawned sub-object
 * from a small id table, then run the map-event sub-object state callbacks. */
int dll_16C_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int* p;
    int* extra = ((GameObject*)obj)->extra;
    s16 ids[5];

    ((Dll16CState*)extra)->opacity = 0xff;
    p = (int*)*extra;
    if (animUpdate->triggerCommand == 3)
    {
        ((Dll16CState*)extra)->subObjIndex = -1;
        animUpdate->triggerCommand = 0;
    }
    *(Blob10*)ids = *(Blob10*)lbl_802C2308;

    if (((Dll16CState*)extra)->subObjIndex != ((Dll16CState*)extra)->subObjIndexApplied)
    {
        if (((GameObject*)obj)->childObjs[0] != NULL)
        {
            Obj_FreeObject(((GameObject*)obj)->childObjs[0]);
            *(int*)&((GameObject*)obj)->childObjs[0] = 0;
            ((GameObject*)obj)->childCount = 0;
        }
        if (Obj_IsLoadingLocked())
        {
            s8 idx = ((Dll16CState*)extra)->subObjIndex;
            if (idx > 0)
            {
                *(int*)&((GameObject*)obj)->childObjs[0] =
                    Obj_SetupObject(Obj_AllocObjectSetup(24, ids[idx - 1]), 4, -1, -1,
                                    *(int*)&((GameObject*)obj)->anim.parent);
                ((GameObject*)obj)->childCount = 1;
            }
            ((Dll16CState*)extra)->subObjIndexApplied = ((Dll16CState*)extra)->subObjIndex;
        }
        else
        {
            ((Dll16CState*)extra)->subObjIndexApplied = 0;
        }
    }

    animUpdate->hitVolumePair = animUpdate->activeHitVolumePair;

    if (p != NULL && animUpdate->triggerCommand == 2)
    {
        ((Dll16CState*)extra)->unk04 = lbl_803E4758;
        ((Dll16CState*)extra)->snapX = ((Dll16CState*)extra)->pathPointX;
        ((Dll16CState*)extra)->snapY = ((Dll16CState*)extra)->pathPointY;
        ((Dll16CState*)extra)->snapZ = ((Dll16CState*)extra)->pathPointZ;
        (*(void (**)(int*, int))(**(int**)((char*)p + 0x68) + 0x3c))(p, 2);
        ObjAnim_SetCurrentMove((int)obj, 0x100, lbl_803E4748, 1);
        if (((GameObject*)obj)->anim.modelState != NULL)
        {
            ((GameObject*)obj)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
        animUpdate->hitVolumePair &= ~4;
        animUpdate->triggerCommand = 0;
    }
    else if (p != NULL && animUpdate->triggerCommand == 1)
    {
        (*(void (**)(int*, int))(**(int**)((char*)p + 0x68) + 0x3c))(p, 0);
        animUpdate->triggerCommand = 0;
    }

    if (p != NULL)
    {
        if ((*(int (**)(int*))(**(int**)((char*)p + 0x68) + 0x38))(p) == 2)
        {
            animUpdate->hitVolumePair &= ~3;
        }
    }
    return 0;
}

/* dll_16C_syncSubObjectTransform: snapshot the map-event sub-object's transform into the boulder
 * extra block, optionally re-issuing a move on the sub-object first. */
void dll_16C_syncSubObjectTransform(void* dst, void* src, int p1, int p2, int p3, int p4, int visible,
                                    int opacity, int reissueMove)
{
    if (reissueMove != 0 && (s8)visible != 0 && opacity > 0)
    {
        u8 saved = *(u8*)((char*)src + 0x37);
        *(u8*)((char*)src + 0x37) = opacity;
        (*(void (**)(void*, int, int, int, int, int))(**(int**)&((GameObject*)src)->anim.dll + 0x10))(src, p1, p2, p3, p4, -1);
        *(u8*)((char*)src + 0x37) = saved;
    }
    ((GameObject*)dst)->anim.previousWorldPosX = ((GameObject*)dst)->anim.worldPosX;
    ((GameObject*)dst)->anim.previousWorldPosY = ((GameObject*)dst)->anim.worldPosY;
    ((GameObject*)dst)->anim.previousWorldPosZ = ((GameObject*)dst)->anim.worldPosZ;
    ((GameObject*)dst)->anim.previousLocalPosX = ((GameObject*)dst)->anim.localPosX;
    ((GameObject*)dst)->anim.previousLocalPosY = ((GameObject*)dst)->anim.localPosY;
    ((GameObject*)dst)->anim.previousLocalPosZ = ((GameObject*)dst)->anim.localPosZ;
    {
        f32 x, y, z;
        (*(void (**)(void*, f32*, f32*, f32*))(**(int**)&((GameObject*)src)->anim.dll + 0x28))(src, &x, &y, &z);
        ((GameObject*)dst)->anim.localPosX = x;
        ((GameObject*)dst)->anim.localPosY = y;
        ((GameObject*)dst)->anim.localPosZ = z;
    }
    ((GameObject*)dst)->anim.rotX = ((GameObject*)src)->anim.rotX;
    ((GameObject*)dst)->anim.rotY = ((GameObject*)src)->anim.rotY;
    ((GameObject*)dst)->anim.rotZ = ((GameObject*)src)->anim.rotZ;
    ((GameObject*)dst)->anim.worldPosX = ((GameObject*)dst)->anim.localPosX;
    ((GameObject*)dst)->anim.worldPosY = ((GameObject*)dst)->anim.localPosY;
    ((GameObject*)dst)->anim.worldPosZ = ((GameObject*)dst)->anim.localPosZ;
    ((GameObject*)dst)->anim.velocityX = ((GameObject*)src)->anim.velocityX;
    ((GameObject*)dst)->anim.velocityY = ((GameObject*)src)->anim.velocityY;
    ((GameObject*)dst)->anim.velocityZ = ((GameObject*)src)->anim.velocityZ;
}

/* dll_16C_update: re-link the spawned sub-object, then while active/visible run
 * its move and fade opacity by distance to the player. */
void dll_16C_update(int* obj)
{
    Dll16CState* extra = ((GameObject*)obj)->extra;
    s16 ids[5];

    *(Blob10*)ids = *(Blob10*)lbl_802C2308;
    if (extra->subObjIndex != extra->subObjIndexApplied)
    {
        if (((GameObject*)obj)->childObjs[0] != NULL)
        {
            Obj_FreeObject(((GameObject*)obj)->childObjs[0]);
            *(int*)&((GameObject*)obj)->childObjs[0] = 0;
            ((GameObject*)obj)->childCount = 0;
        }
        if (Obj_IsLoadingLocked())
        {
            s8 idx = extra->subObjIndex;
            if (idx > 0)
            {
                *(int*)&((GameObject*)obj)->childObjs[0] =
                    Obj_SetupObject(Obj_AllocObjectSetup(24, ids[idx - 1]), 4, -1, -1,
                                    *(int*)&((GameObject*)obj)->anim.parent);
                ((GameObject*)obj)->childCount = 1;
            }
            extra->subObjIndexApplied = extra->subObjIndex;
        }
        else
        {
            extra->subObjIndexApplied = 0;
        }
    }

    if (extra->linkedObj == NULL)
    {
        int* objs;
        int count;
        int i;
        int sel;
        objs = ObjGroup_GetObjects(10, &count);
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 365:
        case 883:
        default:
            sel = 364;
            break;
        case 368:
            sel = 367;
            break;
        }
        for (i = 0; i < count; i++)
        {
            if (sel == ((GameObject*)objs[i])->anim.seqId)
            {
                extra->linkedObj = (void*)objs[i];
                i = count;
            }
        }
    }

    if (((GameObject*)obj)->anim.seqId == 883 || GameBit_Get(0x3a2) != 0)
    {
        int* sub = extra->linkedObj;
        f32 b;
        f32 blend;
        f32 a;
        if (((GameObject*)obj)->anim.currentMove != 0x100)
        {
            ObjAnim_SetCurrentMove((int)obj, 0x100, lbl_803E4748, 0);
        }
        (*(void (**)(int*, f32*))(**(int**)((char*)sub + 0x68) + 0x44))(sub, &blend);
        blend = lbl_803E474C;
        (*(void (**)(int*, f32*, f32*))(**(int**)((char*)sub + 0x68) + 0x40))(sub, &a, &b);
        ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)((int)obj, blend, (f32)(u32)framesThisStep, NULL);
        if (extra->linkedObj != NULL)
        {
            f32 t;
            int* player = (int*)Obj_GetPlayerObject();
            t = Vec_distance(&((GameObject*)extra->linkedObj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX);
            t = (t - lbl_803E475C) / lbl_803E4760;
            if (t < lbl_803E4748)
            {
                t = lbl_803E4748;
            }
            else if (t > lbl_803E4758)
            {
                t = lbl_803E4758;
            }
            t = lbl_803E4758 - t;
            extra->opacity = lbl_803E4764 * t;
            if (((GameObject*)obj)->anim.modelState != NULL)
            {
                ((GameObject*)obj)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
            }
        }
        else
        {
            extra->opacity = 0xff;
            if (((GameObject*)obj)->anim.modelState != NULL)
            {
                ((GameObject*)obj)->anim.modelState->flags &= ~(long long)OBJ_MODEL_STATE_SHADOW_FADE_OUT;
            }
        }
    }
}
