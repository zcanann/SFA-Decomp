#include "main/dll/DR/dll_80209FE0_shared.h"
#include "main/obj_placement.h"
#include "main/game_object.h"

/*
 * Function: drakord_thornbush_getExtraSize
 * EN v1.0 Address: 0x8020BAB4
 * EN v1.0 Size: 8b
 */
int drakord_thornbush_getExtraSize(void)
{
  return 0x7c;
}

/*
 * Function: drakord_thornbush_getObjectTypeId
 * EN v1.0 Address: 0x8020BABC
 * EN v1.0 Size: 8b
 */
int drakord_thornbush_getObjectTypeId(void)
{
  return 0;
}

/*
 * Function: drakord_thornbush_release
 * EN v1.0 Address: 0x8020C270
 * EN v1.0 Size: 4b
 */
void drakord_thornbush_release(void)
{
}

/*
 * Function: drakord_thornbush_initialise
 * EN v1.0 Address: 0x8020C274
 * EN v1.0 Size: 4b
 */
void drakord_thornbush_initialise(void)
{
}

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off

void drakord_thornbush_free(int obj)
{
    int inner = *(int *)&((GameObject *)obj)->extra;
    if (((GameObject *)obj)->anim.seqId == 0x709) {
        fn_80221978(obj, inner + 0x14, 3, inner + 0x64, lbl_803E6588);
    }
    if (*(void **)((char *)inner + 0x64) != NULL) {
        ModelLightStruct_free(*(int *)((char *)inner + 0x64));
    }
}

void drakord_thornbush_render(int p1, int p2, int p3, int p4, int p5, s8 vis)
{
    int inner = *(int *)((char *)p1 + 0xb8);
    f32 v;
    if (*(s16 *)((char *)p1 + 0x46) == 0x709) {
        v = *(f32 *)((char *)inner + 0x68);
        if (v < lbl_803E6590) {
            v = lbl_803E658C;
        }
        fn_80221978(p1, inner + 0x14, 3, inner + 0x64, v);
    }
    objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E6594);
}

void drakord_thornbush_update(int obj)
{
    int inner = *(int *)&((GameObject *)obj)->extra;
    int setup = *(int *)&((GameObject *)obj)->anim.placementData;
    int s2;
    if (fn_80080150((int)((char *)inner + 0xc)) != 0) {
        if (*(f32 *)((char *)inner + 0xc) < (f32)(s32)*(s16 *)((char *)setup + 0x1c)) {
            ObjHits_EnableObject(obj);
            ObjHitbox_SetSphereRadius(obj, (int)(lbl_803E65A8 + (f32)(s32)*(s16 *)((char *)setup + 0x1c) - *(f32 *)((char *)inner + 0xc)));
        }
        if (timerCountDown((f32 *)((char *)inner + 0xc)) != 0) {
            ((GameObject *)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            ((DrakorFlags *)((char *)inner + 0x79))->b80 = 1;
            if (*(u32 *)&((ObjPlacement *)setup)->mapId == 0xffffffff) {
                Obj_FreeObject(obj);
            }
        }
    } else {
        Sfx_KeepAliveLoopedObjectSound(obj, 0x479);
        if (((DrakorFlags *)((char *)inner + 0x79))->b80) {
            ((DrakorFlags *)((char *)inner + 0x79))->b80 = 0;
        }
        switch (((GameObject *)obj)->anim.seqId) {
        case 0x727:
            if (fn_802972A8((int)Obj_GetPlayerObject()) != NULL) {
                ObjHits_ClearHitVolumes(obj);
                ObjHits_EnableObject(obj);
            } else {
                ObjHits_SetHitVolumeSlot(obj, 0xe, 1, 0);
            }
            break;
        case 0x709:
            if (Vec_distance((int *)((char *)Obj_GetPlayerObject() + 0x18), (int *)&((GameObject *)obj)->anim.worldPosX) <
                (f32)(s32)(*(s16 *)((char *)setup + 0x1c) << 1)) {
                ObjHits_RecordObjectHit((int)Obj_GetPlayerObject(), obj, 5, 1, 0);
            }
            break;
        }
        if (*(int *)((char *)inner + 0) == 0) {
            s2 = *(int *)&((GameObject *)obj)->anim.placementData;
            ObjHits_EnableObject(obj);
            *(int *)((char *)inner + 0) = *(u8 *)((char *)s2 + 0x19);
            ObjHitbox_SetSphereRadius(obj, (s16)*(int *)((char *)inner + 0x74));
        }
        if (((GameObject *)obj)->anim.seqId == 0x709) {
            if (*(f32 *)((char *)inner + 0x68) < lbl_803E658C) {
                *(f32 *)((char *)inner + 0x68) = lbl_803E65AC * (f32)(u32)framesThisStep + *(f32 *)((char *)inner + 0x68);
                ((GameObject *)obj)->anim.rootMotionScale =
                    *(f32 *)((char *)inner + 0x68) * (*(f32 *)((char *)*(int *)&((GameObject *)obj)->anim.modelInstance + 4) * (f32)(s32)*(s16 *)((char *)setup + 0x1c)) / lbl_803E65B0;
            }
        }
    }
}

void drakord_thornbush_hitDetect(int obj)
{
    int inner = *(int *)&((GameObject *)obj)->extra;
    f32 v2;
    f32 v1;
    f32 v0;
    int pC;
    int hitObj;
    int flag;
    int setup;
    if (*(int *)((char *)inner + 0) != 0) {
        flag = timerCountDown((f32 *)((char *)inner + 0x10));
        if (ObjHits_GetPriorityHitWithPosition(obj, &hitObj, 0, &pC, &v0, &v1, &v2) != 0) {
            if (*(s16 *)((char *)hitObj + 0x46) != 0x35f &&
                *(int *)((char *)inner + 8) != hitObj &&
                arrayIndexOf(*(int *)((char *)inner + 0x6c), 2) != -1) {
                *(int *)((char *)inner + 8) = hitObj;
                Obj_SpawnHitLightAndFade(obj, &v0, lbl_803E6598);
                *(int *)((char *)inner + 0) -= pC;
                if (*(int *)((char *)inner + 0) <= 0) {
                    flag = 1;
                } else {
                    Sfx_PlayFromObject(obj, 0x496);
                }
            }
        } else {
            *(int *)((char *)inner + 8) = 0;
        }
        if (flag != 0) {
            setup = *(int *)&((GameObject *)obj)->anim.placementData;
            *(int *)((char *)inner + 0) = 0;
            switch (((GameObject *)obj)->anim.seqId) {
            case 0x727:
                spawnExplosion((int *)obj, (f32)(s32)*(s16 *)((char *)setup + 0x1c), 1, 0, 0, 0, 0, 1, 1);
                break;
            case 0x709:
                Sfx_PlayFromObject(obj, 0x2f9);
                spawnExplosion((int *)obj, (f32)(s32)(*(int *)((char *)inner + 0x74) << 1), 1, 1, 1, 1, 0, 1, 0);
                fn_80221978(obj, inner + 0x14, 3, inner + 0x64, lbl_803E6588);
                break;
            }
            if (*(s16 *)((char *)setup + 0x1a) != 0) {
                s16toFloat((void *)((char *)inner + 0xc), *(s16 *)((char *)setup + 0x1a));
                ((GameObject *)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                ObjHits_DisableObject(obj);
            } else if (*(u32 *)&((ObjPlacement *)setup)->mapId == 0xffffffff) {
                Obj_FreeObject(obj);
            } else {
                Obj_RemoveFromUpdateList((int *)obj);
                ObjHits_DisableObject(obj);
                ((GameObject *)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            }
        }
    }
}

void drakord_thornbush_init(int obj, u8 *init)
{
    int inner = *(int *)&((GameObject *)obj)->extra;
    *(int *)((char *)inner + 0) = 0;
    ObjHits_SetTargetMask(obj, 4);
    ((GameObject *)obj)->anim.rotY = (s16)((s8)init[0x18] << 8);
    if (*(u32 *)((char *)init + 0x14) == 0xffffffff) {
        ((DrakorFlags *)((char *)inner + 0x79))->b80 = 1;
    }
    storeZeroToFloatParam((f32 *)((char *)inner + 0xc));
    storeZeroToFloatParam((f32 *)((char *)inner + 0x10));
    *(int *)((char *)inner + 8) = 0;
    switch (((GameObject *)obj)->anim.seqId) {
    case 0x727:
        *(void **)((char *)inner + 0x6c) = &lbl_803DC1A8;
        ObjHitbox_SetSphereRadius(obj, *(s16 *)((char *)init + 0x1c));
        *(int *)((char *)inner + 0x74) = *(s16 *)((char *)init + 0x1c);
        *(f32 *)((char *)inner + 0x70) = lbl_803E65C0;
        ((GameObject *)obj)->anim.rootMotionScale =
            *(f32 *)((char *)*(int *)&((GameObject *)obj)->anim.modelInstance + 4) * (f32)(s32)*(s16 *)((char *)init + 0x1c) / lbl_803E6590;
        break;
    case 0x709:
        *(void **)((char *)inner + 0x6c) = &lbl_803DC1A0;
        ((GameObject *)obj)->anim.rootMotionScale =
            *(f32 *)((char *)*(int *)&((GameObject *)obj)->anim.modelInstance + 4) * (f32)(s32)*(s16 *)((char *)init + 0x1c) / lbl_803E65C4;
        ObjHitbox_SetSphereRadius(obj, (s16)(*(s16 *)((char *)init + 0x1c) / 7));
        s16toFloat((f32 *)((char *)inner + 0x10), (int)lbl_803DC1B0);
        *(f32 *)((char *)inner + 0x70) = lbl_803E65C8;
        *(int *)((char *)inner + 0x74) = *(s16 *)((char *)init + 0x1c) / 5;
        *(f32 *)((char *)inner + 0x68) = lbl_803E6594;
        break;
    }
}

#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset
