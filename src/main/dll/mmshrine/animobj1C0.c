#include "main/dll/mmshrine/animobj1C0.h"
#include "main/game_object.h"
#include "main/objanim.h"
#include "main/objseq.h"

typedef struct EcshShrineState {
    u8 pad0[0x24 - 0x0];
    s16 unk24;
    s16 unk26;
    u8 pad28[0x2E - 0x28];
    u8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} EcshShrineState;


extern u32 randomGetRange(int min, int max);
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern int FUN_80017af8();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern int FUN_800632f4();
extern undefined4 FUN_80135814();
extern double FUN_80194a70();
extern void *Obj_GetPlayerObject(void);
extern s16 getAngle(f32 deltaX, f32 deltaZ);
extern f32 Vec_xzDistance(f32 *a, f32 *b);
extern f32 mathSinf(f32 x);
extern void fn_80296518(void *obj, int arg, int enable);
extern void GameBit_Set(int eventId, int value);
extern void modelLightStruct_setEnabled(int light, int mode, f32 value);

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd718;
extern ObjectTriggerInterface **gObjectTriggerInterface;
extern f32 timeDelta;
extern f64 DOUBLE_803e5c08;
extern f32 lbl_803E4F90;
extern f32 lbl_803E4F94;
extern f32 lbl_803E4F98;
extern f32 lbl_803E4F9C;
extern f32 lbl_803E4FA0;
extern f32 lbl_803E4FA4;
extern f32 lbl_803E4FA8;
extern f32 lbl_803E4FAC;
extern f32 lbl_803E4FB0;
extern f32 lbl_803E4FB4;
extern f32 lbl_803E4FB8;
extern f32 lbl_803E4FC8;
extern f32 lbl_803E5C00;
extern f32 lbl_803E5C10;
extern f32 lbl_803E5C18;
extern f32 lbl_803E5C1C;
extern f32 lbl_803E5C20;

typedef struct MmShrineAnimObj {
    s16 yaw;
    s16 pitch;
    s16 roll;
    s16 flags;
    u8 pad08[0x8];
    f32 posY;
    u8 pad14[0x4];
    f32 posX;
    u8 pad1C[0x4];
    f32 posZ;
    u8 pad24[0x12];
    u8 fadeAlpha;
    u8 pad37[0x15];
    u8 *config;
    u8 pad50[0x68];
    u8 *state;
} MmShrineAnimObj;

typedef struct MmShrineAnimState {
    int light;
    u8 pad04[0x24];
    s16 orbitA;
    s16 orbitB;
    s16 orbitC;
    u8 pad2E[0x2];
    u8 hasTorchSignal;
} MmShrineAnimState;

typedef struct MmShrineAnimEvents {
    u8 pad00[0x56];
    u8 eventStatus;
    u8 pad57[0x19];
    s16 eventModel;
    u8 pad72[0xF];
    u8 events[10];
    u8 eventCount;
} MmShrineAnimEvents;

/*
 * --INFO--
 *
 * Function: FUN_801c5990
 * EN v1.0 Address: 0x801C5990
 * EN v1.0 Size: 668b
 * EN v1.1 Address: 0x801C5B9C
 * EN v1.1 Size: 456b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_801c5990(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  uint uVar1;
  undefined2 *puVar2;
  undefined4 uVar3;
  int iVar4;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar5;
  double dVar6;
  double dVar7;
  
  iVar5 = *(int *)&((GameObject *)param_9)->extra;
  *(undefined2 *)(iVar5 + 0x6a) = *(undefined2 *)(param_10 + 0x1a);
  *(undefined2 *)(iVar5 + 0x6e) = 0xffff;
  dVar6 = DOUBLE_803e5c08;
  dVar7 = (double)lbl_803E5C00;
  *(float *)(iVar5 + 0x24) =
       (float)(dVar7 / (double)(float)(dVar7 + (double)(float)((double)CONCAT44(0x43300000,
                                                                                (uint)*(byte *)(
                                                  param_10 + 0x24)) - DOUBLE_803e5c08)));
  *(undefined4 *)(iVar5 + 0x28) = 0xffffffff;
  iVar4 = ((GameObject *)param_9)->countF4;
  if ((iVar4 == 0) && (*(short *)(param_10 + 0x18) != 1)) {
    (*gObjectTriggerInterface)->loadAnimData((u8 *)iVar5, (u8 *)param_10);
    ((GameObject *)param_9)->countF4 = *(short *)(param_10 + 0x18) + 1;
  }
  else if ((iVar4 != 0) && ((int)*(short *)(param_10 + 0x18) != iVar4 + -1)) {
    (*gObjectTriggerInterface)->freeState((u8 *)iVar5);
    if (*(short *)(param_10 + 0x18) != -1) {
      (*gObjectTriggerInterface)->loadAnimData((u8 *)iVar5, (u8 *)param_10);
    }
    ((GameObject *)param_9)->countF4 = *(short *)(param_10 + 0x18) + 1;
  }
  uVar1 = FUN_80017ae8();
  if ((uVar1 & 0xff) != 0) {
    puVar2 = FUN_80017aa4(0x24,0x1b8);
    *(undefined4 *)(puVar2 + 4) = *(undefined4 *)&((GameObject *)param_9)->anim.localPosX;
    *(undefined4 *)(puVar2 + 6) = *(undefined4 *)&((GameObject *)param_9)->anim.localPosY;
    *(undefined4 *)(puVar2 + 8) = *(undefined4 *)&((GameObject *)param_9)->anim.localPosZ;
    *(undefined *)(puVar2 + 2) = 0x20;
    *(undefined *)((int)puVar2 + 5) = 4;
    *(undefined *)((int)puVar2 + 7) = 0xff;
    uVar3 = FUN_80017ae4(dVar6,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,0xff,
                         0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    *(undefined4 *)&((GameObject *)param_9)->seqIdC8 = uVar3;
    *(float *)(*(int *)&((GameObject *)param_9)->seqIdC8 + 8) =
         *(float *)(*(int *)&((GameObject *)param_9)->seqIdC8 + 8) * lbl_803E5C10;
  }
  return;
}


#pragma scheduling off
#pragma peephole off
void fn_801C5990(MmShrineAnimObj *obj)
{
    u8 *config;
    MmShrineAnimState *state;
    void *player;
    f32 trigA;
    f32 trigB;
    f32 distance;
    s32 angleDelta;
    ObjAnimEventList animEvents;

    config = obj->config;
    state = (MmShrineAnimState *)obj->state;
    player = Obj_GetPlayerObject();

    if ((obj->flags & 0x4000) != 0) {
        obj->yaw = 0;
        obj->posY = *(f32 *)(config + 0xC);
        return;
    }

    state->orbitA = (s16)(state->orbitA + (s32)(lbl_803E4F90 * timeDelta));
    state->orbitB = (s16)(state->orbitB + (s32)(lbl_803E4F94 * timeDelta));
    state->orbitC = (s16)(state->orbitC + (s32)(lbl_803E4F98 * timeDelta));

    obj->posY = lbl_803E4F9C +
                (*(f32 *)(config + 0xC) +
                 mathSinf((lbl_803E4FA0 * (f32)state->orbitA) / lbl_803E4FA4));

    trigA = mathSinf((lbl_803E4FA0 * (f32)state->orbitB) / lbl_803E4FA4);
    trigB = mathSinf((lbl_803E4FA0 * (f32)state->orbitA) / lbl_803E4FA4);
    trigB = trigB + trigA;
    obj->roll = lbl_803E4FA8 * trigB;

    trigA = mathSinf((lbl_803E4FA0 * (f32)state->orbitC) / lbl_803E4FA4);
    trigB = mathSinf((lbl_803E4FA0 * (f32)state->orbitA) / lbl_803E4FA4);
    trigB = trigB + trigA;
    obj->pitch = lbl_803E4FA8 * trigB;

    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803E4FAC, timeDelta,
                               &animEvents);

    if (player != NULL) {
        angleDelta = (u16)getAngle(obj->posX - ((GameObject *)player)->anim.worldPosX,
                                   obj->posZ - ((GameObject *)player)->anim.worldPosZ) -
                     (u16)obj->yaw;
        if (angleDelta > 0x8000) {
            angleDelta -= 0xFFFF;
        }
        if (angleDelta < -0x8000) {
            angleDelta += 0xFFFF;
        }

        obj->yaw = (s16)(*(s16 *)(int)&obj->yaw + (s32)(((f32)angleDelta * timeDelta) / lbl_803E4FB0));
        distance = Vec_xzDistance((f32 *)((int)&obj->posX), (f32 *)((int)player + 0x18));
        if (distance <= lbl_803E4FB4) {
            obj->fadeAlpha = (u8)(s32)(lbl_803E4FB8 * (distance / lbl_803E4FB4));
        } else {
            obj->fadeAlpha = 0xFF;
        }
    }
}

int fn_801C5CE4(void *objArg, int unused, void *eventListArg)
{
    MmShrineAnimObj *obj;
    MmShrineAnimState *state;
    MmShrineAnimEvents *eventList;
    void *player;
    int i;
    u8 event;

    (void)unused;
    obj = (MmShrineAnimObj *)objArg;
    eventList = (MmShrineAnimEvents *)eventListArg;
    state = (MmShrineAnimState *)obj->state;
    player = Obj_GetPlayerObject();
    eventList->eventModel = -1;
    eventList->eventStatus = 0;

    for (i = 0; i < eventList->eventCount; i++) {
        event = eventList->events[i];
        if (event != 0) {
            switch (event) {
            case 3:
                state->hasTorchSignal = 1;
                break;
            case 7:
                fn_80296518(player, 8, 1);
                GameBit_Set(0x143, 1);
                GameBit_Set(0xBA8, 1);
                break;
            case 13:
                (*gObjectTriggerInterface)->setCamVars(0x48, 100, 0, 0x50);
                break;
            case 14:
                obj->flags |= 0x4000;
                if ((void *)state->light != NULL) {
                    modelLightStruct_setEnabled(state->light, 0, lbl_803E4FC8);
                }
                break;
            case 15:
                obj->flags &= ~0x4000;
                if ((void *)state->light != NULL) {
                    modelLightStruct_setEnabled(state->light, 0, lbl_803E4FC8);
                }
                break;
            }
        }
        eventList->events[i] = 0;
    }

    return 0;
}

extern int lbl_803DDBC4;
void ecsh_shrine_modelMtxFn(int *p1, u8 *p2) {
    int *obj = (int *)lbl_803DDBC4;
    int *inner;
    if (obj == NULL) return;
    inner = ((GameObject *)obj)->extra;
    *p2 = ((EcshShrineState *)inner)->unk2E;
    *p1 = ((EcshShrineState *)inner)->unk24;
}
void ecsh_shrine_func0E(u8 v) {
    int *obj = (int *)lbl_803DDBC4;
    int *inner;
    if (obj == NULL) return;
    inner = ((GameObject *)obj)->extra;
    if ((u32)(u8)v == ((EcshShrineState *)inner)->unk2E) {
        ((EcshShrineState *)inner)->unk26 = 1;
    } else {
        ((EcshShrineState *)inner)->unk26 = 0;
    }
}

extern s16 lbl_80326238[];
typedef struct EcshRenderPair {
    f32 a;
    f32 b;
} EcshRenderPair;
extern EcshRenderPair lbl_80326208[];
void ecsh_shrine_render2(u8 idx, f32 a, f32 b) {
    int v;
    if ((int *)lbl_803DDBC4 == NULL) return;
    v = lbl_80326238[(u32)idx];
    lbl_80326208[v].a = a;
    lbl_80326208[v].b = b;
}
