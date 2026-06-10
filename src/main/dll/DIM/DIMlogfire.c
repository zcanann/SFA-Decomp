#include "main/dll/DIM/dimlogfire.h"
#include "main/obj_placement.h"
#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"

typedef struct AnimsharpclawPlacement {
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    u8 pad1A[0x20 - 0x1A];
} AnimsharpclawPlacement;


typedef struct MoonSeedPlantingSpotPlacement {
    u8 pad0[0xC - 0x0];
    f32 unkC;
} MoonSeedPlantingSpotPlacement;


typedef struct AnimsharpclawState {
    u8 pad0[0x24 - 0x0];
    f32 unk24;
    s32 unk28;
    u8 pad2C[0x57 - 0x2C];
    u8 unk57;
    u8 pad58[0x6A - 0x58];
    s16 unk6A;
    u8 pad6C[0x6E - 0x6C];
    s16 unk6E;
    u8 pad70[0x94 - 0x70];
    s32 unk94;
    s32 unk98;
    u8 pad9C[0x140 - 0x9C];
} AnimsharpclawState;


typedef struct CcgasventcontrolState {
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    f32 unk8;
    s16 unkC;
    u8 padE[0x10 - 0xE];
} CcgasventcontrolState;


typedef struct MoonSeedPlantingSpotState {
    u8 pad0[0x1 - 0x0];
    u8 unk1;
    u8 pad2[0x4 - 0x2];
    f32 unk4;
    f32 unk8;
    f32 unkC;
    f32 unk10;
    f32 unk14;
    u8 pad18[0x24 - 0x18];
    f32 unk24;
    s32 unk28;
    u8 pad2C[0x57 - 0x2C];
    u8 unk57;
    u8 pad58[0x6A - 0x58];
    s16 unk6A;
    u8 pad6C[0x6E - 0x6C];
    s16 unk6E;
    u8 pad70[0x94 - 0x70];
    s32 unk94;
    s32 unk98;
    u8 pad9C[0xA0 - 0x9C];
} MoonSeedPlantingSpotState;


extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern double FUN_80017708();
extern undefined4 FUN_80017748();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017a7c();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern int FUN_80017ae4();
extern undefined4 FUN_80017b00();
extern int ObjHits_GetPriorityHit();
extern undefined4 ObjGroup_FindNearestObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined8 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern undefined4 FUN_8003b56c();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800810f4();
extern undefined4 ccqueen_render();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80293f90();

extern undefined4 DAT_803ad590;
extern undefined4 DAT_803ad598;
extern undefined4 DAT_803ad59c;
extern undefined4 DAT_803ad5a0;
extern undefined4 DAT_803ad5a4;
extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6e8;
extern EffectInterface **gPartfxInterface;
extern ObjectTriggerInterface **gObjectTriggerInterface;
extern int *gTitleMenuControlInterfaceCopy;
#define gTitleMenuControlInterface gTitleMenuControlInterfaceCopy
extern f64 DOUBLE_803e5250;
extern f64 DOUBLE_803e5268;
extern f64 DOUBLE_803e5280;
extern f32 lbl_803DC074;
extern f32 lbl_803E5248;
extern f32 lbl_803E524C;
extern f32 lbl_803E5260;
extern f32 lbl_803E5270;
extern f32 lbl_803E5274;
extern f32 lbl_803E5288;
extern f32 lbl_803E528C;
extern f32 lbl_803E5290;
extern f32 lbl_803E5294;
extern f32 lbl_803E5298;
extern f32 lbl_803E529C;
extern f32 lbl_803E52A0;
extern f32 lbl_803E52A8;
extern f32 lbl_803E52AC;

/*
 * --INFO--
 *
 * Function: FUN_801a8f88
 * EN v1.0 Address: 0x801A8F88
 * EN v1.0 Size: 836b
 * EN v1.1 Address: 0x801A9044
 * EN v1.1 Size: 944b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a8f88(void)
{
  int iVar1;
  uint uVar2;
  short *psVar3;
  
  iVar1 = FUN_80286840();
  psVar3 = *(short **)(iVar1 + 0xb8);
  if (((int)*psVar3 == 0xffffffff) || (uVar2 = GameBit_Get((int)*psVar3), uVar2 != 0)) {
    *(float *)(psVar3 + 0x14) = *(float *)(psVar3 + 0x14) - lbl_803DC074;
    if (*(float *)(psVar3 + 0x14) < lbl_803E5248) {
      *(float *)(psVar3 + 0xc) = lbl_803E524C;
      uVar2 = randomGetRange(-(uint)(ushort)psVar3[1],(uint)(ushort)psVar3[1]);
      *(float *)(psVar3 + 0xe) =
           (f32)(s32)(uVar2);
      uVar2 = randomGetRange(-(uint)(ushort)psVar3[3],(uint)(ushort)psVar3[3]);
      *(float *)(psVar3 + 0x10) =
           (f32)(s32)(uVar2);
      uVar2 = randomGetRange(-(uint)(ushort)psVar3[2],(uint)(ushort)psVar3[2]);
      *(float *)(psVar3 + 0x12) =
           (f32)(s32)(uVar2);
      FUN_80017748((ushort *)(psVar3 + 4),(float *)(psVar3 + 0xe));
      *(float *)(psVar3 + 0xe) = *(float *)(psVar3 + 0xe) + *(float *)(iVar1 + 0xc);
      *(float *)(psVar3 + 0x10) = *(float *)(psVar3 + 0x10) + *(float *)(iVar1 + 0x10);
      *(float *)(psVar3 + 0x12) = *(float *)(psVar3 + 0x12) + *(float *)(iVar1 + 0x14);
      uVar2 = randomGetRange(100,200);
      *(float *)(psVar3 + 0x14) =
           (f32)(s32)(uVar2);
      uVar2 = randomGetRange(0x32,100);
      *(float *)(psVar3 + 0x16) =
           (f32)(s32)(uVar2);
    }
    *(float *)(psVar3 + 0x16) = *(float *)(psVar3 + 0x16) - lbl_803DC074;
    if (lbl_803E5248 < *(float *)(psVar3 + 0x16)) {
      (*gPartfxInterface)->spawnObject((void *)iVar1, 0x71f, psVar3 + 8, 0x200001, -1, NULL);
    }
    DAT_803ad598 = lbl_803E524C;
    uVar2 = randomGetRange(-(uint)(ushort)psVar3[1],(uint)(ushort)psVar3[1]);
    DAT_803ad59c = (f32)(s32)(uVar2);
    uVar2 = randomGetRange(-(uint)(ushort)psVar3[3],(uint)(ushort)psVar3[3]);
    DAT_803ad5a0 = (f32)(s32)(uVar2);
    uVar2 = randomGetRange(-(uint)(ushort)psVar3[2],(uint)(ushort)psVar3[2]);
    DAT_803ad5a4 = (f32)(s32)(uVar2);
    FUN_80017748((ushort *)(psVar3 + 4),&DAT_803ad59c);
    DAT_803ad59c = DAT_803ad59c + *(float *)(iVar1 + 0xc);
    DAT_803ad5a0 = DAT_803ad5a0 + *(float *)(iVar1 + 0x10);
    DAT_803ad5a4 = DAT_803ad5a4 + *(float *)(iVar1 + 0x14);
    (*gPartfxInterface)->spawnObject((void *)iVar1, 0x720, &DAT_803ad590, 0x200001, -1, NULL);
  }
  FUN_8028688c();
  return;
}


/*
 * --INFO--
 *
 * Function: FUN_801a9408
 * EN v1.0 Address: 0x801A9408
 * EN v1.0 Size: 524b
 * EN v1.1 Address: 0x801A953C
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801a9408(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            ObjAnimUpdateState *animUpdate)
{
  byte bVar1;
  undefined2 *puVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  
  for (iVar3 = 0; iVar3 < (int)(uint)animUpdate->eventCount; iVar3 = iVar3 + 1) {
    bVar1 = animUpdate->eventIds[iVar3];
    if (bVar1 == 2) {
      iVar4 = *(int *)&((GameObject *)param_9)->unkC8;
      if (iVar4 != 0) {
        uVar5 = ObjLink_DetachChild(param_9,iVar4);
        param_1 = FUN_80017ac8(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4);
      }
      *(undefined4 *)(param_9 + 0xf8) = 0xffffffff;
    }
    else if ((bVar1 < 2) && (bVar1 != 0)) {
      *(undefined4 *)(param_9 + 0xf8) = 0x30b;
      iVar4 = *(int *)&((GameObject *)param_9)->unkC8;
      if (iVar4 != 0) {
        uVar5 = ObjLink_DetachChild(param_9,iVar4);
        param_1 = FUN_80017ac8(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4);
      }
      puVar2 = FUN_80017aa4(0x20,(short)*(undefined4 *)(param_9 + 0xf8));
      iVar4 = FUN_80017ae4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,4,
                           ((GameObject *)param_9)->anim.mapEventSlot,0xffffffff,*(uint **)&((GameObject *)param_9)->anim.parent,
                           in_r8,in_r9,in_r10);
      param_1 = ObjLink_AttachChild(param_9,iVar4,0);
    }
  }
  return 0;
}



/* Trivial 4b 0-arg blr leaves. */
void animsharpclaw_hitDetect(void) {}
void animsharpclaw_release(void) {}
void animsharpclaw_initialise(void) {}
void MoonSeedPlantingSpot_hitDetect(void) {}
void MoonSeedPlantingSpot_release(void) {}
void MoonSeedPlantingSpot_initialise(void) {}


#pragma scheduling off
#pragma peephole off
void MoonSeedPlantingSpot_init(int *obj, u8 *init) {
    u8 *sub;
    int mapId;

    sub = ((GameObject *)obj)->extra;
    ((GameObject *)obj)->animEventCallback = (void *)MoonSeedPlantingSpot_SeqFn;
    *(s16*)obj = (s16)(init[0x1f] << 8);
    sub[0] = 0;
    ObjGroup_AddObject((int)obj, 0x2e);
    mapId = *(int*)(init + 0x14);
    switch (mapId) {
        case 0x41a5b:
            *(s16*)(sub + 8) = 0x866;
            *(s16*)(sub + 0xa) = 0x856;
            break;
        case 0x41a59:
            *(s16*)(sub + 8) = 0x867;
            *(s16*)(sub + 0xa) = 0x858;
            break;
        case 0x41a5c:
            *(s16*)(sub + 8) = 0x868;
            *(s16*)(sub + 0xa) = 0x85a;
            break;
        case 0x41a5d:
            *(s16*)(sub + 8) = 0x869;
            *(s16*)(sub + 0xa) = 0x864;
            break;
        case 0x43e04:
            *(s16*)(sub + 8) = 0x9a2;
            *(s16*)(sub + 0xa) = 0x99a;
            break;
        case 0x43e1f:
            *(s16*)(sub + 8) = 0x9a3;
            *(s16*)(sub + 0xa) = 0x99c;
            break;
        case 0x43e20:
            *(s16*)(sub + 8) = 0x9a4;
            *(s16*)(sub + 0xa) = 0x99e;
            break;
        case 0x43e21:
            *(s16*)(sub + 8) = 0x9a5;
            *(s16*)(sub + 0xa) = 0x9a0;
            break;
        case 0x476ae:
            *(s16*)(sub + 8) = 0x3d5;
            *(s16*)(sub + 0xa) = 0x3d2;
            break;
        case 0x4b26e:
            *(s16*)(sub + 8) = 0xd4d;
            *(s16*)(sub + 0xa) = 0xd4b;
            break;
        case 0x4bea3:
            *(s16*)(sub + 8) = 0xe21;
            *(s16*)(sub + 0xa) = 0xe10;
            break;
    }
    sub[1] = 0;
}
#pragma peephole reset
#pragma scheduling reset
void ccgasvent_render(void) {}

/* 8b "li r3, N; blr" returners. */
int animsharpclaw_getExtraSize(void) { return 0x140; }
int animsharpclaw_getObjectTypeId(void) { return 0xb; }
int MoonSeedPlantingSpot_render2(void) { return 0x2; }
int MoonSeedPlantingSpot_modelMtxFn(void) { return 0x0; }
int MoonSeedPlantingSpot_func0B(void) { return 0x0; }
int MoonSeedPlantingSpot_getExtraSize(void) { return 0x18; }
int MoonSeedPlantingSpot_getObjectTypeId(void) { return 0x1; }
int ccgasvent_getExtraSize(void) { return 0x1; }
int ccgasventcontrol_getExtraSize(void) { return 0x10; }
int ccqueen_getExtraSize(void) { return 0x654; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E45C8;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E4620;
#pragma peephole off
void animsharpclaw_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E45C8); }
void ccgasventcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4620); }
#pragma peephole reset

/* ObjGroup_RemoveObject(x, N) wrappers. */
#pragma scheduling off
void MoonSeedPlantingSpot_free(int x) { ObjGroup_RemoveObject(x, 0x2e); }
void ccgasvent_free(int x) { ObjGroup_RemoveObject(x, 0x3f); }
#pragma scheduling reset

/* call(x, N) wrappers. */
#pragma scheduling off
void ccgasvent_init(int x) { ObjGroup_AddObject(x, 0x3f); }
#pragma scheduling reset

/* MoonSeedPlantingSpot_SeqFn: leaf flag-set on obj's extra struct, returns 0. */
extern void disableHeavyFog(void);
#pragma scheduling off
#pragma peephole off
void animsharpclaw_free(int obj) {
    char *inner;
    int *child;
    child = ((GameObject *)obj)->unkC8;
    inner = ((GameObject *)obj)->extra;
    if (child != NULL) {
        ObjLink_DetachChild(obj, (int)child);
        Obj_FreeObject((int)child);
    }
    (*gObjectTriggerInterface)->freeState((u8 *)inner);
    (*(void (*)(int, int, int, int, int))(*(int *)(*gTitleMenuControlInterface + 0x8)))(obj, 0xffff, 0, 0, 0);
    Sfx_StopObjectChannel(obj, 0x7f);
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void ccgasventcontrol_free(int obj) {
    char *inner = ((GameObject *)obj)->extra;
    u8 t = *(u8 *)inner;
    if (t == 3 || t == 4) {
        disableHeavyFog();
    }
    (*gGameUIInterface)->airMeterSetShutdown();
}
void ccgasventcontrol_init(int obj, u8 *p) {
    char *inner = ((GameObject *)obj)->extra;
    ((GameObject *)obj)->animEventCallback = (void *)CCGasVentControl_SeqFn;
    *(s16 *)obj = (s16)((u32)p[0x1a] << 8);
    if (GameBit_Get(0xa3) != 0) {
        *(u8 *)inner = 7;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int MoonSeedPlantingSpot_SeqFn(int obj)
{
    obj = *(int *)&((GameObject *)obj)->extra;
    *(u8 *)(obj + 1) = (u8)((uint)*(u8 *)(obj + 1) | 1);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

/* CCGasVentControl_SeqFn: trampoline to CCGasVentControlFn_801a9fd0 passing (obj, obj->extra), returns 0. */
extern u8 CCGasVentControlFn_801a9fd0(int obj, int extra);
#pragma scheduling off
int CCGasVentControl_SeqFn(int obj)
{
    CCGasVentControlFn_801a9fd0(obj, *(int *)&((GameObject *)obj)->extra);
    return 0;
}
#pragma scheduling reset

extern int *ObjGroup_GetObjects(int group, int *count);
extern f32 lbl_803E4618;
extern f32 timeDelta;
extern MapEventInterface **gMapEventInterface;
extern int Obj_GetPlayerObject(void);
extern void Sfx_PlayFromObject(int obj, int id);
extern void enableHeavyFog(f32 a, f32 b, f32 c, f32 d, f32 e, u8 mode);
extern f32 lbl_803E4624;
extern f32 lbl_803E4628;
extern f32 lbl_803E462C;
extern f32 lbl_803E4630;
extern f32 lbl_803E4634;
extern f32 lbl_803E4638;
extern f32 lbl_803E463C;
extern f32 lbl_803E4640;

#pragma scheduling off
#pragma peephole off
void ccgasventcontrol_update(int obj)
{
    int ex = *(int *)&((GameObject *)obj)->extra;
    u8 b = CCGasVentControlFn_801a9fd0(obj, ex);
    switch (*(u8 *)ex) {
    case 0: {
        int cnt;
        ObjGroup_GetObjects(0x3f, &cnt);
        if (cnt == 4) {
            *(u8 *)ex = 1;
        }
        break;
    }
    case 1:
        if (GameBit_Get(0x3ec) != 0) {
            (*gObjectTriggerInterface)->runSequence(0, (void *)obj, -1);
            *(u8 *)ex = 2;
        }
        break;
    case 2:
        (*gGameUIInterface)->initAirMeter(6000, 0x603);
        ((CcgasventcontrolState *)ex)->unk4 = lbl_803E4624;
        *(u8 *)ex = 3;
        *(u8 *)((char *)ex + 0xc) = b;
        break;
    case 3:
        if (b != 0) {
            int player = Obj_GetPlayerObject();
            ((CcgasventcontrolState *)ex)->unk8 = ((CcgasventcontrolState *)ex)->unk8 + timeDelta / lbl_803E4618;
            if (((CcgasventcontrolState *)ex)->unk8 > lbl_803E4628) {
                ((CcgasventcontrolState *)ex)->unk8 = *(f32 *)&lbl_803E4628;
            }
            if (((GameObject *)player)->anim.localPosY <= ((GameObject *)obj)->anim.localPosY + ((CcgasventcontrolState *)ex)->unk8) {
                ((CcgasventcontrolState *)ex)->unk4 = -(timeDelta * (f32)b - ((CcgasventcontrolState *)ex)->unk4);
            } else {
                ((CcgasventcontrolState *)ex)->unk4 = lbl_803E462C * timeDelta + ((CcgasventcontrolState *)ex)->unk4;
                if (((CcgasventcontrolState *)ex)->unk4 > lbl_803E4624) {
                    ((CcgasventcontrolState *)ex)->unk4 = *(f32 *)&lbl_803E4624;
                }
            }
            enableHeavyFog(((GameObject *)obj)->anim.localPosY + ((CcgasventcontrolState *)ex)->unk8,
                           ((GameObject *)obj)->anim.localPosY - lbl_803E4630, lbl_803E4634, lbl_803E4638,
                           lbl_803E463C, 0);
            if (((CcgasventcontrolState *)ex)->unk4 >= lbl_803E4640) {
                (*gGameUIInterface)->runAirMeter((int)((CcgasventcontrolState *)ex)->unk4);
            } else {
                (*gGameUIInterface)->airMeterSetShutdown();
                ((GameObject *)obj)->anim.localPosX = ((GameObject *)player)->anim.localPosX;
                ((GameObject *)obj)->anim.localPosY = ((GameObject *)player)->anim.localPosY;
                ((GameObject *)obj)->anim.localPosZ = ((GameObject *)player)->anim.localPosZ;
                (*gObjectTriggerInterface)->runSequence(1, (void *)obj, -1);
                (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x1e, 0xff);
                *(u8 *)ex = 4;
            }
            if (b != *(u8 *)((char *)ex + 0xc)) {
                Sfx_PlayFromObject(0, 0x409);
                *(u8 *)((char *)ex + 0xc) = b;
            }
        } else {
            Sfx_PlayFromObject(0, 0x7e);
            (*gGameUIInterface)->airMeterSetShutdown();
            GameBit_Set(0xa3, 1);
            GameBit_Set(0x620, 0);
            *(u8 *)ex = 5;
        }
        break;
    case 4:
        (*gMapEventInterface)->finishCurrentEvent(*gMapEventInterface);
        break;
    case 5: {
        int player = Obj_GetPlayerObject();
        (*gMapEventInterface)->triggerEvent(player + 0xc, *(s16 *)player, 1, 0);
        *(u8 *)ex = 6;
        break;
    }
    case 6:
        if (GameBit_Get(0x1c0) == 0) {
            disableHeavyFog();
            *(u8 *)ex = 7;
        }
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset

extern f32 getXZDistance(f32 *a, f32 *b);
extern void Sfx_AddLoopedObjectSound(int obj, int sfxId);
extern void Sfx_RemoveLoopedObjectSound(int obj, int sfxId);
extern void Sfx_SetObjectSfxVolume(int obj, int sound, int vol, f32 v);
extern f32 lbl_803E461C;

#pragma scheduling off
#pragma peephole off
u8 CCGasVentControlFn_801a9fd0(int obj, int extra)
{
    u8 i;
    u8 count = 0;
    if (GameBit_Get(0x1c0) != 0) {
        int cnt;
        int *list = ObjGroup_GetObjects(0x3f, &cnt);
        f32 thr;
        i = 0;
        thr = lbl_803E4618;
        for (; i < 4; i++) {
            int other = ObjGroup_FindNearestObject(5, list[i], 0);
            if (getXZDistance((f32 *)(list[i] + 0x18), (f32 *)(other + 0x18)) > thr) {
                count = (u8)count + 1;
            }
        }
    }
    if (count != 0) {
        if (*(u8 *)((char *)extra + 1) == 0) {
            Sfx_AddLoopedObjectSound(obj, 0x223);
            *(u8 *)((char *)extra + 1) = 1;
        }
        Sfx_SetObjectSfxVolume(obj, 0x223, (u8)(count * 0xf + 0x28), lbl_803E461C);
    } else {
        if (*(u8 *)((char *)extra + 1) != 0) {
            Sfx_RemoveLoopedObjectSound(obj, 0x223);
            *(u8 *)((char *)extra + 1) = 0;
        }
    }
    return count;
}
#pragma peephole reset
#pragma scheduling reset

extern int getTrickyObject(void);
extern void objfx_spawnDirectionalBurst(int obj, int a, f32 fa, int b, int c, int d, f32 fb, int e, int f);
extern f32 lbl_803E45DC;
extern f64 lbl_803E45E8;
extern f32 lbl_803E45F0;
extern f32 lbl_803E45F4;
extern f32 lbl_803E45F8;
extern f32 lbl_803E45FC;
extern f32 lbl_803E4600;
extern f32 lbl_803E4604;
extern f32 lbl_803E4608;

#pragma scheduling off
#pragma peephole off
void MoonSeedPlantingSpot_update(int obj)
{
    int ex = *(int *)&((GameObject *)obj)->extra;
    int setup = *(int *)&((GameObject *)obj)->anim.placementData;
    if (((MoonSeedPlantingSpotState *)ex)->unk1 & 1) {
        *(u8 *)ex = 2;
        GameBit_Set(*(s16 *)((char *)ex + 8), 1);
        ((MoonSeedPlantingSpotState *)ex)->unk1 = ((MoonSeedPlantingSpotState *)ex)->unk1 & ~1;
        ((GameObject *)obj)->anim.alpha = 0xff;
    }
    if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 4) && !(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 8)) {
        if (GameBit_Get(0x86a) != 0) {
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~0x10;
        } else {
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 0x10;
        }
    }
    ((MoonSeedPlantingSpotState *)ex)->unk1 |= 2;
    switch (*(u8 *)ex) {
    case 0:
        *(u8 *)ex = 1;
        ((GameObject *)obj)->anim.localPosY = ((ObjPlacement *)setup)->posY - lbl_803E45F0;
        if (GameBit_Get(*(s16 *)((char *)ex + 8)) != 0) {
            *(u8 *)ex = 2;
            ((GameObject *)obj)->anim.localPosY = ((ObjPlacement *)setup)->posY;
            ((GameObject *)obj)->anim.alpha = 0xff;
        }
        if (GameBit_Get(*(s16 *)((char *)ex + 0xa)) != 0) {
            int setup2;
            int ex2;
            ex2 = *(int *)&((GameObject *)obj)->extra;
            setup2 = *(int *)&((GameObject *)obj)->anim.placementData;
            if (GameBit_Get(*(s16 *)((char *)ex2 + 8)) != 0) {
                *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
                GameBit_Set(*(s16 *)((char *)ex2 + 0xa), 1);
                *(u8 *)ex2 = 4;
                ((GameObject *)obj)->anim.localPosY = ((MoonSeedPlantingSpotPlacement *)setup2)->unkC;
            }
        }
        break;
    case 1:
        if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 1) &&
            (*gGameUIInterface)->isEventReady(0x86a) != 0) {
            int cnt = GameBit_Get(0x86a);
            if (cnt != 0) {
                ((GameObject *)obj)->anim.localPosY = ((ObjPlacement *)setup)->posY;
                ((GameObject *)obj)->anim.alpha = 0;
                (*gObjectTriggerInterface)->runSequence(0, (void *)obj, -1);
                GameBit_Set(0x86a, cnt - 1);
                *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
            }
        }
        break;
    case 2: {
        int tricky = getTrickyObject();
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
        if (((MoonSeedPlantingSpotState *)ex)->unk1 & 2) {
            void *player;
            if (((MoonSeedPlantingSpotState *)ex)->unk1 & 4) {
                ((GameObject *)obj)->anim.localPosY =
                    ((ObjPlacement *)setup)->posY + (f32)(int)randomGetRange(-1, 1);
                (*gPartfxInterface)->spawnObject((void *)obj, 0x70f, NULL, 2, -1, NULL);
            }
            ((MoonSeedPlantingSpotState *)ex)->unk14 = ((MoonSeedPlantingSpotState *)ex)->unk14 - timeDelta;
            if (((MoonSeedPlantingSpotState *)ex)->unk14 <= lbl_803E45F4) {
                if ((int)randomGetRange(0, 1) != 0) {
                    ((MoonSeedPlantingSpotState *)ex)->unk14 = lbl_803E45F8;
                    ((MoonSeedPlantingSpotState *)ex)->unk1 |= 4;
                    Sfx_PlayFromObject(obj, 0x438);
                } else {
                    ((MoonSeedPlantingSpotState *)ex)->unk14 = (f32)(int)randomGetRange(0x32, 200);
                    ((MoonSeedPlantingSpotState *)ex)->unk1 &= ~4;
                }
            }
            player = (void *)Obj_GetPlayerObject();
            if (player != NULL && getXZDistance(&((GameObject *)player)->anim.worldPosX, &((GameObject *)obj)->anim.worldPosX) <= lbl_803E45FC) {
                objfx_spawnDirectionalBurst(obj, 5, lbl_803E45DC, 5, 1, 0x28, lbl_803E4600, 0, 0);
                (*(void (*)(int, int, int, int))(*(int *)(*(int *)(*(int *)((char *)tricky + 0x68)) + 0x28)))(tricky, obj, 1, 4);
            } else {
                objfx_spawnDirectionalBurst(obj, 5, lbl_803E45DC, 6, 1, 0x28, lbl_803E4604, 0, 0);
            }
            if (ObjHits_GetPriorityHit(obj, 0, 0, 0) == 0x1a) {
                *(u8 *)ex = 3;
                *(s16 *)((char *)ex + 0xc) = 0;
                ((MoonSeedPlantingSpotState *)ex)->unk10 = lbl_803E4608;
            }
        }
        break;
    }
    case 3: {
        int tricky = getTrickyObject();
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
        ((GameObject *)obj)->anim.localPosY = ((ObjPlacement *)setup)->posY;
        if (getXZDistance((f32 *)(tricky + 0x18), &((GameObject *)obj)->anim.worldPosX) <= lbl_803E45FC) {
            objfx_spawnDirectionalBurst(obj, 5, lbl_803E45DC, 5, 1, 0x28, lbl_803E4600, 0, 0);
        } else {
            objfx_spawnDirectionalBurst(obj, 5, lbl_803E45DC, 6, 1, 0x28, lbl_803E4604, 0, 0);
        }
        if (((MoonSeedPlantingSpotState *)ex)->unk10 <= lbl_803E45F4 && GameBit_Get(*(s16 *)((char *)ex + 8)) != 0 &&
            GameBit_Get(*(s16 *)((char *)ex + 0xa)) == 0) {
            int setup2;
            int ex2;
            ex2 = *(int *)&((GameObject *)obj)->extra;
            setup2 = *(int *)&((GameObject *)obj)->anim.placementData;
            if (GameBit_Get(*(s16 *)((char *)ex2 + 8)) != 0) {
                *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
                GameBit_Set(*(s16 *)((char *)ex2 + 0xa), 1);
                *(u8 *)ex2 = 4;
                ((GameObject *)obj)->anim.localPosY = ((MoonSeedPlantingSpotPlacement *)setup2)->unkC;
            }
        }
        ((MoonSeedPlantingSpotState *)ex)->unk10 = ((MoonSeedPlantingSpotState *)ex)->unk10 - timeDelta;
        if (((MoonSeedPlantingSpotState *)ex)->unk10 < lbl_803E45F4) {
            ((MoonSeedPlantingSpotState *)ex)->unk10 = *(f32 *)&lbl_803E45F4;
        }
        break;
    }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int Obj_AllocObjectSetup(int size, int type);
extern int Obj_SetupObject(int allocResult, int a, int b, int c, int d);

#pragma scheduling off
#pragma dont_inline on
int fn_801A8F88(int obj, ObjAnimUpdateState *animUpdate)
{
    int i;
    int state;
    int alloc;
    for (i = 0; i < (int)animUpdate->eventCount; i++) {
        u8 v = animUpdate->eventIds[i];
        switch (v) {
        case 1:
            ((GameObject *)obj)->unkF8 = 779;
            state = (int)((GameObject *)obj)->unkC8;
            if ((void *)state != NULL) {
                ObjLink_DetachChild(obj, state);
                Obj_FreeObject(state);
            }
            alloc = Obj_AllocObjectSetup(32, ((GameObject *)obj)->unkF8);
            alloc = Obj_SetupObject(alloc, 4, ((GameObject *)obj)->anim.mapEventSlot, -1, *(int *)&((GameObject *)obj)->anim.parent);
            ObjLink_AttachChild(obj, alloc, 0);
            break;
        case 2:
            state = (int)((GameObject *)obj)->unkC8;
            if ((void *)state != NULL) {
                ObjLink_DetachChild(obj, state);
                Obj_FreeObject(state);
            }
            ((GameObject *)obj)->unkF8 = -1;
            break;
        }
    }
    return 0;
}
#pragma dont_inline reset
#pragma scheduling reset

extern f32 lbl_803E4610;
extern f32 lbl_803E4614;

#pragma scheduling off
#pragma peephole off
void ccgasvent_update(int *obj) {
    f32 dist = lbl_803E4610;
    u8 *state = ((GameObject *)obj)->extra;
    if (GameBit_Get(0x1c0) != 0) {
        ObjGroup_FindNearestObject(5, (uint)obj, &dist);
        switch (state[0]) {
        case 0:
            if (dist >= lbl_803E4614) {
                state[0] = 1;
            }
            break;
        case 1:
            if (dist < lbl_803E4614) {
                state[0] = 0;
            } else {
                (*gPartfxInterface)->spawnObject(obj, 0x3df, NULL, 0, -1, NULL);
            }
            break;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int MoonSeedPlantingSpot_setScale(int *obj, int arg) {
    int *sub;
    u8 *inner;
    int ret;

    inner = ((GameObject *)obj)->extra;
    ret = 0;
    if (arg == 0) {
        if ((inner[1] & 2) != 0) {
            inner[0] = 3;
            *(s16 *)(inner + 0xc) = 0;
        }
        ret = 1;
    } else if (arg == 1) {
        if (inner[0] == 3) {
            ret = 1;
            if (GameBit_Get(*(s16 *)(inner + 8)) != 0 && GameBit_Get(*(s16 *)(inner + 0xa)) == 0) {
                sub = *(int **)&((GameObject *)obj)->anim.placementData;
                inner = ((GameObject *)obj)->extra;
                if (GameBit_Get(*(s16 *)(inner + 8)) != 0) {
                    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
                    GameBit_Set(*(s16 *)(inner + 0xa), 1);
                    inner[0] = 4;
                    ((GameObject *)obj)->anim.localPosY = ((MoonSeedPlantingSpotState *)sub)->unkC;
                }
            }
        }
    }
    return ret;
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E45D8;
extern f32 lbl_803E45E0;
extern f32 lbl_803E45E4;
extern f32 mathSinf(f32 x);
extern void fn_8003B608(int r, int g, int b);

#pragma scheduling off
#pragma peephole off
void MoonSeedPlantingSpot_render(int p1, int p2, int p3, int p4, int p5, s8 visible) {
    u8 *inner = ((GameObject *)p1)->extra;
    s32 v = visible;
    if (v != 0) {
        if (inner[0] == 2) {
            if ((inner[1] & 2) != 0) {
                f32 s;
                int iv;
                *(s16 *)(inner + 0xc) += 0x1000;
                s = mathSinf(lbl_803E45E0 * (f32)*(s16 *)(inner + 0xc) / lbl_803E45E4);
                iv = (int)(lbl_803E45D8 * (lbl_803E45DC + s));
                fn_8003B608((u8)(iv + 0x7f), 0xff, 0xff);
            }
        } else if (inner[0] == 3) {
            if (*(s16 *)(inner + 0xc) < 0x7d00) {
                *(s16 *)(inner + 0xc) += 0xff;
            }
            fn_8003B608((s16)(*(s16 *)(inner + 0xc) >> 7), 0xff, 0xff);
        } else {
            fn_8003B608(0xff, 0xff, 0xff);
        }
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E45DC);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void objSetSlot(void *obj, int slot);

#pragma scheduling off
#pragma peephole off
void animsharpclaw_init(int *obj, u8 *init) {
    int *inner;
    int f4;

    ((GameObject *)obj)->animEventCallback = NULL;
    objSetSlot(obj, 0x64);
    inner = ((GameObject *)obj)->extra;
    ((AnimsharpclawState *)inner)->unk6A = *(s16 *)((char *)init + 0x1a);
    ((AnimsharpclawState *)inner)->unk6E = -1;
    ((AnimsharpclawState *)inner)->unk24 = lbl_803E45C8 / (lbl_803E45C8 + (f32)(u32)init[0x24]);
    ((AnimsharpclawState *)inner)->unk28 = -1;
    ((AnimsharpclawState *)inner)->unk98 = 0;
    ((AnimsharpclawState *)inner)->unk94 = 0;
    ((GameObject *)obj)->unkF8 = -1;
    f4 = ((GameObject *)obj)->unkF4;
    if (f4 == 0 && *(s16 *)((char *)init + 0x18) != 1) {
        (*gObjectTriggerInterface)->loadAnimData((u8 *)inner, init);
        ((GameObject *)obj)->unkF4 = *(s16 *)((char *)init + 0x18) + 1;
    } else if (f4 != 0 && *(s16 *)((char *)init + 0x18) != f4 - 1) {
        (*gObjectTriggerInterface)->freeState((u8 *)inner);
        if (*(s16 *)((char *)init + 0x18) != -1) {
            (*gObjectTriggerInterface)->loadAnimData((u8 *)inner, init);
        }
        ((GameObject *)obj)->unkF4 = *(s16 *)((char *)init + 0x18) + 1;
    }
    if (((GameObject *)obj)->anim.modelState != NULL) {
        ((GameObject *)obj)->anim.modelState->shadowTintA = 0x64;
        ((GameObject *)obj)->anim.modelState->shadowTintB = 0x96;
    }
}
#pragma peephole reset
#pragma scheduling reset

extern u8 framesThisStep;

#pragma scheduling off
#pragma peephole off
void animsharpclaw_update(int *obj) {
    int *found;
    int *inner;
    int *child;
    int kind;
    int matchCount;
    int *objects;
    int i;
    int count;
    int result;

    inner = ((GameObject *)obj)->extra;
    child = *(int **)&((GameObject *)obj)->anim.placementData;
    if (child == NULL) {
        return;
    }
    if (((AnimsharpclawPlacement *)child)->unk18 == -1) {
        return;
    }
    {
        volatile int vres = (*gObjectTriggerInterface)->update((u8 *)obj, (f32)(u32)framesThisStep);
        fn_801A8F88((int)obj, (ObjAnimUpdateState *)inner);
        if (vres == 0) {
            return;
        }
    }
    if (((GameObject *)obj)->unkB4 != -2) {
        return;
    }
    kind = (s8)((AnimsharpclawState *)inner)->unk57;
    found = NULL;
    objects = (int *)ObjList_GetObjects(&i, &count);
    matchCount = 0;
    for (i = 0; i < count; i++) {
        int *o = (int *)objects[i];
        if (*(s16 *)((char *)o + 0xb4) == kind) {
            found = o;
        }
        if (*(s16 *)((char *)o + 0xb4) == -2 && *(s16 *)((char *)o + 0x44) == 0x10 &&
            kind == (s8)*(u8 *)((char *)*(int **)((char *)o + 0xb8) + 0x57)) {
            matchCount++;
        }
    }
    if (matchCount <= 1 && found != NULL && *(s16 *)((char *)found + 0xb4) != -1) {
        *(s16 *)((char *)found + 0xb4) = -1;
        (*gObjectTriggerInterface)->endSequence(kind);
    }
    ((GameObject *)obj)->unkB4 = -1;
}
#pragma peephole reset
#pragma scheduling reset
