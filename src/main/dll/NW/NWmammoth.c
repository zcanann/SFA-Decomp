#include "main/dll/ediblemushroom.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/dll/rom_curve_interface.h"
#include "main/objanim_internal.h"

typedef struct EdiblemushroomState {
    u8 pad0[0x68 - 0x0];
    f32 unk68;
    u8 pad6C[0x70 - 0x6C];
    f32 unk70;
    u8 pad74[0x108 - 0x74];
    f32 unk108;
    f32 unk10C;
    f32 unk110;
    f32 unk114;
    f32 unk118;
    f32 unk11C;
    f32 unk120;
    u8 pad124[0x136 - 0x124];
    u8 unk136;
    u8 flags137;
} EdiblemushroomState;



extern undefined4 FUN_80006824();
extern undefined4 FUN_80017688();
extern undefined4 GameBit_Set(int eventId, int value);
extern double FUN_80017714();
extern undefined4 FUN_8001771c();
extern undefined4 FUN_80017a28();
extern byte FUN_80017a34();
extern undefined4 FUN_80017a3c();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_DisableObject();
extern void ObjHits_EnableObject(int obj);
extern void ObjHits_RefreshObjectState(int obj);
extern int ObjHits_GetPriorityHit();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_AllocQueue();
extern u32 randomGetRange(int min,int max);
extern int FUN_800620e8();
extern int FUN_800632f4();
extern undefined4 FUN_80081118();
extern undefined4 edibleMushroomFn_801d083c();
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();

extern undefined4* DAT_803dd71c;
extern f64 DOUBLE_803e5f58;
extern f32 FLOAT_803e5f20;
extern f32 FLOAT_803e5f2c;
extern f32 FLOAT_803e5f38;
extern f32 FLOAT_803e5f40;
extern f32 FLOAT_803e5f78;
extern f32 FLOAT_803e5f7c;
extern f32 FLOAT_803e5f80;
extern f32 FLOAT_803e5f84;
extern f32 FLOAT_803e5f88;
extern f32 FLOAT_803e5f8c;

extern void *Obj_GetPlayerObject(void);
extern u32 GameBit_Get(int bit);
extern f32 Vec_distance(int a, int b);

extern f32 lbl_803E5288;
extern f32 lbl_803E52A0;
extern f32 lbl_803E52A8;
extern f64 lbl_803E52C0;
extern f32 lbl_803E52E0;
extern f32 lbl_803E52E4;
extern f32 lbl_803E52E8;
extern f32 lbl_803E52EC;
extern f32 lbl_803E52F0;
extern f32 lbl_803E52F4;
extern f32 lbl_803E52F8;
extern f32 lbl_803E52FC;
extern f32 lbl_803E5300;
extern f32 lbl_803E5304;
extern f64 lbl_803E5308;

/*
 * --INFO--
 *
 * Function: ediblemushroom_init
 * EN v1.0 Address: 0x801D1978
 * EN v1.0 Size: 644b
 */
void ediblemushroom_init(int obj, int aux)
{
    int state;
    int player;
    int local_x;
    ObjAnimEventList animEvents;
    f32 dist;

    state = *(int *)&((GameObject *)obj)->extra;
    local_x = 0x19;
    player = (int)Obj_GetPlayerObject();

    ((GameObject *)obj)->animEventCallback = (void *)EdibleMushroom_SeqFn;
    ((GameObject *)obj)->objectFlags = (u16)(((GameObject *)obj)->objectFlags | 0x4000);

    if (GameBit_Get(*(short *)(aux + 0x1a)) != 0) {
        ((EdiblemushroomState *)state)->unk136 = 8;
        ObjHits_DisableObject(obj);
        ((GameObject *)obj)->anim.flags = (short)(((GameObject *)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
    }

    ((GameObject *)obj)->anim.modelState->flags |= 0x810;

    ((EdiblemushroomState *)state)->unk110 = lbl_803E52E0;
    ((EdiblemushroomState *)state)->unk114 = lbl_803E52E4 *
        ((f32)*(u8 *)(aux + 0x1c) / lbl_803E52E8);

    ObjAnim_SetCurrentMove(obj, 1, lbl_803E5288, 0);
    ((int (*)(int, f32, f32, void *))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E52A8, *(f32 *)&lbl_803E52A8, &animEvents);
    ((EdiblemushroomState *)state)->unk118 = animEvents.rootDeltaX;
    if (((EdiblemushroomState *)state)->unk118 < lbl_803E5288) {
        ((EdiblemushroomState *)state)->unk118 = -((EdiblemushroomState *)state)->unk118;
    }
    ((EdiblemushroomState *)state)->unk118 = ((EdiblemushroomState *)state)->unk118 * ((EdiblemushroomState *)state)->unk110;
    ((EdiblemushroomState *)state)->unk118 = ((EdiblemushroomState *)state)->unk118 + lbl_803E52A0;

    ObjAnim_SetCurrentMove(obj, 4, lbl_803E5288, 0);
    ((int (*)(int, f32, f32, void *))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E52A8, *(f32 *)&lbl_803E52A8, &animEvents);
    ((EdiblemushroomState *)state)->unk11C = animEvents.rootDeltaZ;
    if (((EdiblemushroomState *)state)->unk11C < lbl_803E5288) {
        ((EdiblemushroomState *)state)->unk11C = -((EdiblemushroomState *)state)->unk11C;
    }
    ((EdiblemushroomState *)state)->unk11C = ((EdiblemushroomState *)state)->unk11C + lbl_803E52A0;

    ObjMsg_AllocQueue(obj, 1);

    {
        int v = *(u8 *)(aux + 0x18);
        switch (v) {
        case 4:
        case 5:
            ((EdiblemushroomState *)state)->flags137 |= 2;
            (*gRomCurveInterface)->initCurve((void *)state, (void *)obj, lbl_803E52EC, &local_x, -1);
            ((GameObject *)obj)->anim.localPosX = ((EdiblemushroomState *)state)->unk68;
            ((GameObject *)obj)->anim.localPosZ = ((EdiblemushroomState *)state)->unk70;
            break;
        }
    }

    ((EdiblemushroomState *)state)->unk120 = lbl_803E52F0;

    if ((void *)player != NULL) {
        dist = Vec_distance(player + 0x18, obj + 0x18);
        ((EdiblemushroomState *)state)->unk108 = dist;
        ((EdiblemushroomState *)state)->unk10C = dist;
    } else {
        {
            f32 z = lbl_803E52F4;
            ((EdiblemushroomState *)state)->unk108 = z;
            ((EdiblemushroomState *)state)->unk10C = z;
        }
    }

    ObjGroup_AddObject(obj, 0x31);
    ObjGroup_AddObject(obj, 0x47);

    if (((GameObject *)obj)->anim.seqId == 0x658) {
        *(short *)(state + 0x134) = 0x66d;
    } else {
        *(short *)(state + 0x134) = 0xc1;
    }
}

void enemymushroom_resetToSpawn(EnemyMushroomObject *obj,EnemyMushroomState *state,int enableTimer)
{
  EnemyMushroomMapData *mapData;
  u32 randomValue;
  f32 fr;

  mapData = obj->mapData;
  obj->rotZ = (s16)randomGetRange(-0x5dc,0x5dc);
  obj->rotY = (s16)randomGetRange(-0x5dc,0x5dc);
  obj->rotX = (s16)randomGetRange(-0x5dc,0x5dc);
  obj->alpha = 0xff;
  obj->flags = (s16)(obj->flags & ~0x4000);
  obj->posX = mapData->posX;
  obj->posY = mapData->posY;
  obj->posZ = mapData->posZ;
  if (enableTimer != 0) {
    obj->scale = lbl_803E52F8;
    state->timer = lbl_803E52FC;
    randomValue = randomGetRange(0,100);
    fr = (f32)(s32)randomValue;
    fr = lbl_803E5300 + fr;
    state->riseDuration = fr;
    randomValue = randomGetRange(-100,100);
    fr = (f32)(s32)randomValue;
    fr = lbl_803E5304 * fr + state->baseScale;
    state->heightTarget = fr;
    state->riseStep = state->heightTarget / state->riseDuration;
  }
  ObjHits_EnableObject((int)obj);
  ObjHits_RefreshObjectState((int)obj);
}

/*
 * --INFO--
 *
 * Function: enemymushroom_getExtraSize
 * EN v1.0 Address: 0x801D1D58
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int enemymushroom_getExtraSize(void)
{
  return 0x3c;
}

/*
 * --INFO--
 *
 * Function: enemymushroom_getObjectTypeId
 * EN v1.0 Address: 0x801D1D60
 * EN v1.0 Size: 20b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int enemymushroom_getObjectTypeId(EnemyMushroomObject *obj)
{
  return (*(byte *)(*(int *)&((GameObject *)obj)->anim.placementData + 0x1f) << 0xb) | 0x400;
}

void enemymushroom_free(EnemyMushroomObject *obj)
{
  (*gExpgfxInterface)->freeSource((u32)obj);
  ObjGroup_RemoveObject((int)obj,3);
}

extern void objRenderFn_8003b8f4(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, double scale);
extern void ObjPath_GetPointWorldPosition(void *obj, int idx, void *out0, void *out1, void *out2, int flag);
extern f32 lbl_803E5310;

void enemymushroom_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible)
{
    void *state = ((GameObject *)obj)->extra;
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E5310);
        ObjPath_GetPointWorldPosition(obj, 0, (char *)state + 0x20, (char *)state + 0x24, (char *)state + 0x28, 0);
    }
}

/*
 * --INFO--
 *
 * Function: enemymushroom_hitDetect
 * EN v1.0 Address: 0x801D1E20
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void enemymushroom_hitDetect(void)
{
}
