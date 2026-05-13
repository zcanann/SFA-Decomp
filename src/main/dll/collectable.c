#include "ghidra_import.h"
#include "dolphin/mtx.h"
#include "main/dll/collectable.h"

extern undefined4 FUN_800067e8();
extern bool FUN_800067f0();
extern undefined4 FUN_8000680c();
extern undefined8 FUN_80006824();
extern undefined8 FUN_800068cc();
extern undefined8 FUN_800068d0();
extern char FUN_80006a64();
extern undefined4 FUN_80006a68();
extern void* FUN_80017624();
extern undefined4 FUN_80017688();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern double FUN_80017708();
extern uint FUN_80017730();
extern undefined4 FUN_80017748();
extern uint FUN_80017760();
extern void Sfx_RemoveLoopedObjectSound(int param_1,int param_2);
extern int Sfx_IsPlayingFromObjectChannel(int param_1,int param_2);
extern int Sfx_PlayFromObject(int obj,int sfxId);
extern int Sfx_PlayFromObjectLimited(int obj,int sfxId,int maxCount);
extern undefined8 FUN_800178ec();
extern undefined4 FUN_80017a28();
extern undefined4 FUN_80017a30();
extern undefined4 FUN_80017a3c();
extern int FUN_80017a54();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined8 FUN_80017ac8();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern int FUN_80017af8();
extern int voxmaps_traceLine(void *from,void *to,int param_3,u8 *hit,int param_5);
extern void voxmaps_worldToGrid(Vec *world,void *grid);
extern int ObjList_FindObjectById(int objId);
extern undefined4 FUN_8002f6ac();
extern int FUN_8002fc3c();
extern int getTrickyObject(void);
extern void ObjAnim_SetCurrentMove(f32 moveProgress,int obj,int moveId,int flags);
extern undefined4 FUN_800305c4();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined4 ObjHits_SyncObjectPosition();
extern int ObjHits_GetPriorityHitWithPosition();
extern int ObjHits_GetPriorityHit();
extern int ObjGroup_FindNearestObject(int group,int obj,f32 *maxDistance);
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined8 ObjLink_DetachChild();
extern undefined8 ObjLink_AttachChild();
extern void Obj_FreeObject(int param_1);
extern int Obj_AllocObjectSetup();
extern int Obj_SetupObject(int setup,int param_2,int param_3,int param_4,int param_5);
extern u8 Obj_IsLoadingLocked(void);
extern undefined4 ObjPath_GetPointWorldPositionArray();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_80038f38();
extern undefined8 FUN_80039468();
extern void objAudioFn_800393f8(int param_1,void *param_2,int param_3,int param_4,int param_5,
                                int param_6);
extern int FUN_8003964c();
extern f32 getXZDistance(f32 *a, f32 *b);
extern undefined4 FUN_8003a1c4();
extern undefined4 fn_8003A328();
extern undefined4 FUN_8003b1a4();
extern undefined4 FUN_8003b280();
extern undefined4 FUN_8003b818();
extern void objRenderFn_8003b8f4(f32 scale,...);
extern int fn_800395D8(int obj,int param_2);
extern undefined4 FUN_80046f44();
extern undefined4 FUN_80046f84();
extern void fn_8004B594(void *param_1);
extern int fn_8005A10C(f32 *pos,f32 radius);
extern undefined8 FUN_800571f8();
extern int FUN_800575b4();
extern int FUN_800620e8();
extern u16 hitDetectFn_80065e50(f32 x,f32 y,f32 z,int obj,int *hits,int param_6,int param_7);
extern undefined4 FUN_8006dca8();
extern void fn_8006EDCC(f32 param_1,f32 param_2,int obj,u16 param_4,int param_5,float *points,void *aux);
extern undefined4 FUN_8006ef38();
extern undefined4 FUN_8008111c();
extern undefined4 FUN_80081120();
extern undefined4 FUN_800da700();
extern undefined8 FUN_800da850();
extern undefined4 FUN_800db47c();
extern ushort FUN_800db690();
extern undefined4 FUN_800dbc68();
extern undefined8 FUN_800dd3dc();
extern undefined4 FUN_800dd3e0();
extern void fn_800DD640(void);
extern void gameBitIncrement(int eventId);
extern void GameBit_Set(int eventId,int value);
extern undefined8 FUN_80135d54();
extern void fn_801389E0(int param_1,int param_2,int *param_3);
extern void trickyImpress(int obj);
extern int fn_8014460C(int obj,int state);
extern void objAnimFn_8013a3f0(int obj,int animId,f32 blend,int flags);
extern int trickyFn_8013b368(int obj,f32 radius,int state);
extern undefined4 FUN_80135f38();
extern undefined4 FUN_80136310();
extern undefined4 FUN_8013651c();
extern int FUN_801365c4();
extern undefined4 FUN_801367b4();
extern int FUN_80136870();
extern undefined4 FUN_8013939c();
extern undefined4 FUN_80139a4c();
extern undefined4 FUN_8013a408();
extern void fn_8013ADFC(int obj);
extern void fn_80139164(int obj,int state);
extern int FUN_8013b368();
extern int FUN_8013dc88();
extern int FUN_801451dc();
extern undefined4 FUN_8014a9f0();
extern undefined4 FUN_8014fef8();
extern byte FUN_80150620();
extern undefined4 FUN_801523bc();
extern undefined4 FUN_80152b8c();
extern undefined4 FUN_80152f54();
extern undefined4 FUN_80153440();
extern undefined4 FUN_80153db4();
extern undefined4 FUN_80154108();
extern undefined4 FUN_80154cc8();
extern undefined4 FUN_80155b08();
extern undefined4 FUN_801564ec();
extern undefined4 FUN_80156e48();
extern undefined4 FUN_801578c4();
extern undefined4 FUN_80157168();
extern undefined4 FUN_80158540();
extern undefined4 FUN_80159c60();
extern undefined4 FUN_8015a4c4();
extern undefined4 FUN_8015b2cc();
extern undefined4 FUN_801778d0();
extern void objSetAnimSpeedTo1(int param_1);
extern f32 fn_801948C0(int obj,int param_2);
extern double FUN_80194a70();
extern undefined4 FUN_8020a568();
extern undefined4 FUN_80247eb8();
extern double FUN_80247f54();
extern undefined4 FUN_80286830();
extern uint FUN_80286834();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028fa2c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern undefined4 FUN_80294c68();
extern int FUN_80294c80();
extern undefined4 FUN_80294ca8();
extern undefined4 FUN_80294dc4();
extern void trickyReportError(const char *fmt, ...);
extern void objParticleFn_80099d84(f32 param_1,f32 param_2,int obj,int param_4,int param_5);
extern int objBboxFn_800640cc(f32 radius,Vec *from,Vec *to,int mode,void *hit,int obj,int param_7,
                              int param_8,int param_9,int param_10);
extern f32 fn_80293E80(f32 x);
extern f32 sin(f32 x);

extern undefined4 DAT_802c2948;
extern undefined4 DAT_802c294c;
extern undefined4 DAT_802c2950;
extern undefined4 DAT_802c2954;
extern undefined4 DAT_802c2958;
extern undefined4 DAT_802c2970;
extern undefined4 DAT_802c2974;
extern undefined4 DAT_802c2978;
extern undefined4 DAT_802c297c;
extern undefined4 DAT_802c2980;
extern undefined4 DAT_802c2984;
extern undefined4 DAT_802c2988;
extern undefined4 DAT_802c298c;
extern u32 lbl_802C21F0[4];
extern undefined4 DAT_8031df38;
extern undefined4 DAT_8031df50;
extern char sInWaterMessage[];
extern char lbl_8031D478[];
extern undefined4 DAT_803dc8a8;
extern undefined4 DAT_803dc8b0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd728;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803dd734;
extern undefined4 DAT_803de6c8;
extern undefined4* DAT_803de6d0;
extern undefined4 DAT_803de6d4;
extern undefined4 DAT_803e3050;
extern undefined4 DAT_803e3054;
extern undefined4 DAT_803e3058;
extern undefined4 DAT_803e31e8;
extern undefined4 DAT_803e31ec;
extern undefined4 DAT_803e31f0;
extern undefined4 DAT_803e31f4;
extern undefined4 DAT_803e31f8;
extern char sSidekickCommandDebugTextBlock[];
extern undefined4 lbl_803DDA48;
extern int lbl_803DDA54;
extern undefined4* lbl_803DCA78;
extern int *lbl_803DCAAC;
extern f64 DOUBLE_803e30f0;
extern f64 DOUBLE_803e3218;
extern f32 lbl_803DC074;
extern f32 lbl_803DC078;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 timeDelta;
extern f32 oneOverTimeDelta;
extern void *lbl_803DCAA8;
extern f32 lbl_803E23DC;
extern f32 lbl_803E23E8;
extern f32 lbl_803E2410;
extern f32 lbl_803E2414;
extern f32 lbl_803E243C;
extern f32 lbl_803E2440;
extern f32 lbl_803E2444;
extern f32 lbl_803E24B8;
extern f32 lbl_803E2454;
extern f32 lbl_803E2458;
extern f64 lbl_803E2460;
extern f32 lbl_803E247C;
extern f32 lbl_803E253C;
extern f32 lbl_803E2540;
extern u32 lbl_803E2558;
extern u32 lbl_803E255C;
extern u32 lbl_803E2560;
extern u32 lbl_803E2564;
extern u16 lbl_803E2568;
extern f32 lbl_803E2574;
extern f32 lbl_803E2570;
extern f32 lbl_803E2578;
extern f32 lbl_803E257C;
extern f32 lbl_803E256C;
extern f32 lbl_803E2598;
extern f32 lbl_803E25A0;
extern f32 lbl_803E25A8;
extern f32 lbl_803E25AC;
extern f32 lbl_803E25B0;
extern f32 lbl_803E25B4;
extern f32 lbl_803E25B8;
extern f32 lbl_803E25BC;
extern f32 lbl_803E25C0;
extern f32 lbl_803E25C4;
extern f32 lbl_803E25C8;
extern f32 lbl_803E306C;
extern f32 lbl_803E3078;
extern f32 lbl_803E307C;
extern f32 lbl_803E3098;
extern f32 lbl_803E30A0;
extern f32 lbl_803E30A4;
extern f32 lbl_803E30A8;
extern f32 lbl_803E30CC;
extern f32 lbl_803E30D0;
extern f32 lbl_803E30D4;
extern f32 lbl_803E30E4;
extern f32 lbl_803E310C;
extern f32 lbl_803E3138;
extern f32 lbl_803E3148;
extern f32 lbl_803E3158;
extern f32 lbl_803E3168;
extern f32 lbl_803E317C;
extern f32 lbl_803E3188;
extern f32 lbl_803E3190;
extern f32 lbl_803E31C4;
extern f32 lbl_803E31C8;
extern f32 lbl_803E31CC;
extern f32 lbl_803E31D0;
extern f32 lbl_803E31D4;
extern f32 lbl_803E31D8;
extern f32 lbl_803E31DC;
extern f32 lbl_803E31E0;
extern f32 lbl_803E31FC;
extern f32 lbl_803E3200;
extern f32 lbl_803E3204;
extern f32 lbl_803E3208;
extern f32 lbl_803E320C;
extern f32 lbl_803E3210;
extern f32 lbl_803E3220;
extern f32 lbl_803E3224;
extern f32 lbl_803E3228;
extern f32 lbl_803E322C;
extern f32 lbl_803E3234;
extern f32 lbl_803E3238;
extern f32 lbl_803E323C;
extern f32 lbl_803E3240;
extern f32 lbl_803E3244;
extern f32 lbl_803E3250;
extern f32 lbl_803E3254;

/*
 * --INFO--
 *
 * Function: FUN_80144e40
 * EN v1.0 Address: 0x80144E40
 * EN v1.0 Size: 736b
 * EN v1.1 Address: 0x80144ED8
 * EN v1.1 Size: 752b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80144e40(int param_1,int param_2)
{
  float fVar1;
  int iVar2;
  bool bVar4;
  uint uVar3;
  int local_18 [3];
  
  *(float *)(param_2 + 0x720) = *(float *)(param_2 + 0x720) - lbl_803DC074;
  if (*(float *)(param_2 + 0x720) < lbl_803E306C) {
    *(float *)(param_2 + 0x720) = lbl_803E306C;
  }
  iVar2 = ObjHits_GetPriorityHit(param_1,local_18,(int *)0x0,(uint *)0x0);
  if (((iVar2 != 0) && (*(int *)(local_18[0] + 0xc4) != 0)) &&
     (*(short *)(*(int *)(local_18[0] + 0xc4) + 0x44) == 1)) {
    fVar1 = *(float *)(param_2 + 0x720);
    if (lbl_803E306C < fVar1) {
      *(float *)(param_2 + 0x720) = fVar1 + lbl_803E30D0;
      if (*(char *)(param_2 + 10) != '\v') {
        if ((*(uint *)(param_2 + 0x54) & 0x10) == 0) {
          iVar2 = *(int *)(param_1 + 0xb8);
          if ((((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
              ((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)))) &&
             (bVar4 = FUN_800067f0(param_1,0x10), !bVar4)) {
            FUN_80039468(param_1,iVar2 + 0x3a8,0x350,0x500,0xffffffff,0);
          }
          *(undefined *)(param_2 + 10) = 10;
          *(uint *)(param_2 + 0x54) = *(uint *)(param_2 + 0x54) | 0x10;
        }
        else if (*(float *)(param_2 + 0x720) <= lbl_803E31C4) {
          iVar2 = *(int *)(param_1 + 0xb8);
          if ((((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
              ((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)))) &&
             (bVar4 = FUN_800067f0(param_1,0x10), !bVar4)) {
            FUN_80039468(param_1,iVar2 + 0x3a8,0x350,0x500,0xffffffff,0);
          }
        }
        else {
          *(float *)(param_2 + 0x720) = *(float *)(param_2 + 0x720) * lbl_803E3138;
          uVar3 = FUN_80017690(0x245);
          if (uVar3 != 0) {
            if (lbl_803E306C == *(float *)(param_2 + 0x2ac)) {
              bVar4 = false;
            }
            else if (lbl_803E30A0 == *(float *)(param_2 + 0x2b0)) {
              bVar4 = true;
            }
            else if (*(float *)(param_2 + 0x2b4) - *(float *)(param_2 + 0x2b0) <= lbl_803E30A4) {
              bVar4 = false;
            }
            else {
              bVar4 = true;
            }
            if (!bVar4) {
              *(undefined *)(param_2 + 10) = 0xb;
              return;
            }
          }
          iVar2 = *(int *)(param_1 + 0xb8);
          if (((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
             (((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)) &&
              (bVar4 = FUN_800067f0(param_1,0x10), !bVar4)))) {
            FUN_80039468(param_1,iVar2 + 0x3a8,0x350,0x500,0xffffffff,0);
          }
        }
      }
    }
    else {
      *(float *)(param_2 + 0x720) = fVar1 + lbl_803E317C;
      iVar2 = *(int *)(param_1 + 0xb8);
      if ((((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
          ((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)))) &&
         (bVar4 = FUN_800067f0(param_1,0x10), !bVar4)) {
        FUN_80039468(param_1,iVar2 + 0x3a8,0x34f,0x500,0xffffffff,0);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80145120
 * EN v1.0 Address: 0x80145120
 * EN v1.0 Size: 272b
 * EN v1.1 Address: 0x801451C8
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80145120(int param_1,int param_2)
{
  int *piVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  int local_38 [2];
  
  iVar3 = 0;
  piVar1 = ObjGroup_GetObjects(0x4b,local_38);
  dVar4 = FUN_80017708((float *)(*(int *)(param_2 + 4) + 0x18),(float *)(param_1 + 0x18));
  if ((((double)lbl_803E31C8 <= dVar4) || (lbl_803E306C < *(float *)(param_2 + 0x71c))) &&
     (iVar2 = FUN_800575b4((double)lbl_803E3190,(float *)(param_1 + 0xc)), iVar2 == 0)) {
    dVar6 = (double)lbl_803E30A8;
    for (iVar2 = 0; iVar2 < local_38[0]; iVar2 = iVar2 + 1) {
      dVar5 = FUN_80017708((float *)(*(int *)(param_2 + 4) + 0x18),(float *)(*piVar1 + 0x18));
      if ((dVar5 < dVar4) && (dVar5 < dVar6)) {
        iVar3 = *piVar1;
        dVar6 = dVar5;
      }
      piVar1 = piVar1 + 1;
    }
  }
  return iVar3;
}

/*
 * --INFO--
 *
 * Function: FUN_80145230
 * EN v1.0 Address: 0x80145230
 * EN v1.0 Size: 952b
 * EN v1.1 Address: 0x801452D8
 * EN v1.1 Size: 648b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80145230(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int *param_10,int param_11,undefined4 param_12,byte param_13,
                 uint param_14,undefined4 param_15,undefined4 param_16)
{
  short sVar1;
  int iVar2;
  uint uVar3;
  bool bVar4;
  double dVar5;
  double dVar6;
  
  iVar2 = FUN_801451dc(param_9,param_10);
  if (iVar2 == 0) {
    dVar5 = (double)FUN_80293f90();
    param_10[0x1cb] = (int)(float)((double)*(float *)(param_9 + 0x18) - dVar5);
    param_10[0x1cc] = *(int *)(param_9 + 0x1c);
    dVar6 = (double)lbl_803E30E4;
    dVar5 = (double)FUN_80294964();
    param_10[0x1cd] = (int)(float)((double)*(float *)(param_9 + 0x20) - dVar5);
    iVar2 = FUN_8013b368((double)lbl_803E310C,dVar6,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,param_10,param_11,param_12,param_13,param_14,param_15,
                         param_16);
    if (iVar2 != 1) {
      param_10[0x1d0] = (int)((float)param_10[0x1d0] - lbl_803DC074);
      if ((float)param_10[0x1d0] <= lbl_803E306C) {
        uVar3 = FUN_80017760(500,0x2ee);
        param_10[0x1d0] =
             (int)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e30f0);
        iVar2 = *(int *)(param_9 + 0xb8);
        if (((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
           (((0x2f < *(short *)(param_9 + 0xa0) || (*(short *)(param_9 + 0xa0) < 0x29)) &&
            (bVar4 = FUN_800067f0(param_9,0x10), !bVar4)))) {
          FUN_80039468(param_9,iVar2 + 0x3a8,0x360,0x500,0xffffffff,0);
        }
      }
      if (lbl_803E306C == (float)param_10[0xab]) {
        bVar4 = false;
      }
      else if (lbl_803E30A0 == (float)param_10[0xac]) {
        bVar4 = true;
      }
      else if ((float)param_10[0xad] - (float)param_10[0xac] <= lbl_803E30A4) {
        bVar4 = false;
      }
      else {
        bVar4 = true;
      }
      if (bVar4) {
        FUN_80139a4c((double)lbl_803E30CC,param_9,8,0);
        param_10[0x1e7] = (int)lbl_803E30D0;
        param_10[0x20e] = (int)lbl_803E306C;
        FUN_80146fa0();
      }
      else {
        sVar1 = *(short *)(param_9 + 0xa0);
        if (sVar1 != 0x31) {
          if ((sVar1 < 0x31) && (sVar1 == 0xd)) {
            if ((param_10[0x15] & 0x8000000U) != 0) {
              FUN_80139a4c((double)lbl_803E30CC,param_9,0x31,0);
            }
          }
          else {
            FUN_80139a4c((double)lbl_803E30D4,param_9,0xd,0);
          }
        }
        FUN_80146fa0();
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801455e8
 * EN v1.0 Address: 0x801455E8
 * EN v1.0 Size: 444b
 * EN v1.1 Address: 0x80145560
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801455e8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  float fVar1;
  ushort uVar3;
  undefined2 *puVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 extraout_f1;
  undefined8 uVar4;
  byte local_18 [16];
  
  local_18[0] = FUN_800db47c((float *)(param_9 + 0x18),(undefined *)0x0);
  uVar4 = extraout_f1;
  if ((local_18[0] == 0) && (uVar3 = FUN_800db690((float *)(param_9 + 0x18)), uVar3 != 0)) {
    uVar4 = FUN_800da850((uint)uVar3,local_18);
  }
  if (local_18[0] != 0) {
    *(ushort *)(param_10 + 0x532) = (ushort)local_18[0];
    *(undefined *)(param_10 + 8) = 1;
    *(undefined *)(param_10 + 10) = 0;
    fVar1 = lbl_803E306C;
    *(float *)(param_10 + 0x71c) = lbl_803E306C;
    *(float *)(param_10 + 0x720) = fVar1;
    *(uint *)(param_10 + 0x54) = *(uint *)(param_10 + 0x54) & 0xffffffef;
    *(uint *)(param_10 + 0x54) = *(uint *)(param_10 + 0x54) & 0xfffeffff;
    *(uint *)(param_10 + 0x54) = *(uint *)(param_10 + 0x54) & 0xfffdffff;
    *(uint *)(param_10 + 0x54) = *(uint *)(param_10 + 0x54) & 0xfffbffff;
    *(undefined *)(param_10 + 0xd) = 0xff;
  }
  if (DAT_803de6c8 == 0) {
    puVar2 = FUN_80017aa4(0x18,0x25);
    DAT_803de6c8 = FUN_80017ae4(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2
                                ,4,0xff,0xffffffff,*(uint **)(param_9 + 0x30),in_r8,in_r9,in_r10);
  }
  *(byte *)(param_10 + 0x58) = *(byte *)(param_10 + 0x58) & 0x7f | 0x80;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801457a4
 * EN v1.0 Address: 0x801457A4
 * EN v1.0 Size: 1792b
 * EN v1.1 Address: 0x8014568C
 * EN v1.1 Size: 1328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801457a4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  byte bVar1;
  float fVar2;
  uint uVar3;
  bool bVar9;
  int *piVar4;
  int iVar5;
  uint uVar6;
  undefined2 *puVar7;
  int iVar8;
  int iVar10;
  int *piVar11;
  undefined8 extraout_f1;
  undefined8 uVar12;
  undefined8 extraout_f1_00;
  undefined auStack_98 [13];
  char local_8b;
  
  uVar3 = FUN_80286834();
  piVar11 = *(int **)(uVar3 + 0xb8);
  uVar12 = extraout_f1;
  if ((piVar11[0x15] & 0x200U) == 0) {
    ObjHits_DisableObject(uVar3);
    FUN_8000680c(uVar3,0x7f);
    if ((piVar11[0x15] & 0x800U) != 0) {
      piVar11[0x15] = piVar11[0x15] & 0xfffff7ff;
      piVar11[0x15] = piVar11[0x15] | 0x1000;
      iVar10 = 0;
      piVar4 = piVar11;
      do {
        FUN_801778d0(piVar4[0x1c0]);
        piVar4 = piVar4 + 1;
        iVar10 = iVar10 + 1;
      } while (iVar10 < 7);
      FUN_800068cc();
      iVar10 = *(int *)(uVar3 + 0xb8);
      if (((*(byte *)(iVar10 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < *(short *)(uVar3 + 0xa0) || (*(short *)(uVar3 + 0xa0) < 0x29)) &&
          (bVar9 = FUN_800067f0(uVar3,0x10), !bVar9)))) {
        param_14 = 0;
        FUN_80039468(uVar3,iVar10 + 0x3a8,0x29d,0,0xffffffff,0);
      }
    }
    uVar12 = FUN_800068cc();
    piVar11[0x15] = piVar11[0x15] | 0x200;
    if ((*(ushort *)(param_11 + 0x6e) & 3) == 0) {
      piVar11[0x15] = piVar11[0x15] | 0x4000;
    }
    if ((*(byte *)((int)piVar11 + 0x82e) >> 5 & 1) == 0) {
      piVar4 = (int *)FUN_80017a54(uVar3);
      uVar12 = FUN_800178ec(piVar4);
      *(byte *)((int)piVar11 + 0x82e) = *(byte *)((int)piVar11 + 0x82e) & 0xbf;
    }
  }
  if (((piVar11[0x15] & 0x4000U) != 0) && ((*(ushort *)(piVar11[9] + 0xb0) & 0x40) != 0)) {
    *(undefined *)(piVar11 + 2) = 1;
    *(undefined *)((int)piVar11 + 10) = 0;
    fVar2 = lbl_803E306C;
    piVar11[0x1c7] = (int)lbl_803E306C;
    piVar11[0x1c8] = (int)fVar2;
    piVar11[0x15] = piVar11[0x15] & 0xffffffef;
    piVar11[0x15] = piVar11[0x15] & 0xfffeffff;
    piVar11[0x15] = piVar11[0x15] & 0xfffdffff;
    piVar11[0x15] = piVar11[0x15] & 0xfffbffff;
    *(undefined *)((int)piVar11 + 0xd) = 0xff;
    *(undefined *)((int)piVar11 + 9) = 0;
    piVar11[4] = (int)fVar2;
    piVar11[5] = (int)fVar2;
  }
  for (iVar10 = 0; iVar10 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar10 = iVar10 + 1) {
    bVar1 = *(byte *)(param_11 + iVar10 + 0x81);
    if (bVar1 == 3) {
      *(undefined *)*piVar11 = *(undefined *)((int)piVar11 + 0x82d);
    }
    else if (bVar1 < 3) {
      if (bVar1 == 1) {
        if ((piVar11[0x15] & 0x800U) == 0) {
          uVar6 = FUN_80017ae8();
          if ((uVar6 & 0xff) != 0) {
            piVar11[0x15] = piVar11[0x15] | 0x800;
            iVar8 = 0;
            piVar4 = piVar11;
            do {
              puVar7 = FUN_80017aa4(0x24,0x4f0);
              *(undefined *)(puVar7 + 2) = 2;
              *(undefined *)((int)puVar7 + 5) = 1;
              puVar7[0xd] = (short)iVar8;
              iVar5 = FUN_80017ae4(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                   puVar7,5,*(undefined *)(uVar3 + 0xac),0xffffffff,
                                   *(uint **)(uVar3 + 0x30),param_14,param_15,param_16);
              piVar4[0x1c0] = iVar5;
              piVar4 = piVar4 + 1;
              iVar8 = iVar8 + 1;
              uVar12 = extraout_f1_00;
            } while (iVar8 < 7);
            FUN_80006824(uVar3,0x3db);
            uVar12 = FUN_800068d0(uVar3,0x3dc);
          }
        }
        else {
          piVar11[0x15] = piVar11[0x15] & 0xfffff7ff;
          piVar11[0x15] = piVar11[0x15] | 0x1000;
          iVar8 = 0;
          piVar4 = piVar11;
          do {
            FUN_801778d0(piVar4[0x1c0]);
            piVar4 = piVar4 + 1;
            iVar8 = iVar8 + 1;
          } while (iVar8 < 7);
          uVar12 = FUN_800068cc();
          iVar8 = *(int *)(uVar3 + 0xb8);
          if (((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) &&
             (((0x2f < *(short *)(uVar3 + 0xa0) || (*(short *)(uVar3 + 0xa0) < 0x29)) &&
              (bVar9 = FUN_800067f0(uVar3,0x10), !bVar9)))) {
            param_14 = 0;
            uVar12 = FUN_80039468(uVar3,iVar8 + 0x3a8,0x29d,0,0xffffffff,0);
          }
        }
      }
      else if (bVar1 != 0) {
        uVar12 = FUN_80017698(0x186,1);
        uVar6 = FUN_80017690(0x186);
        if (((uVar6 != 0) && (piVar11[499] == 0)) && (uVar6 = FUN_80017ae8(), (uVar6 & 0xff) != 0))
        {
          uVar12 = FUN_800571f8(auStack_98);
          if (local_8b == '\0') {
            puVar7 = FUN_80017aa4(0x20,0x254);
          }
          else {
            puVar7 = FUN_80017aa4(0x20,0x244);
          }
          iVar8 = FUN_80017ae4(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar7
                               ,4,0xff,0xffffffff,*(uint **)(uVar3 + 0x30),param_14,param_15,
                               param_16);
          piVar11[499] = iVar8;
          uVar12 = ObjLink_AttachChild(uVar3,piVar11[499],3);
        }
      }
    }
    else if (bVar1 == 0x2c) {
      *(uint *)(*(int *)(uVar3 + 100) + 0x30) = *(uint *)(*(int *)(uVar3 + 100) + 0x30) | 4;
    }
    else if ((bVar1 < 0x2c) && (0x2a < bVar1)) {
      *(uint *)(*(int *)(uVar3 + 100) + 0x30) = *(uint *)(*(int *)(uVar3 + 100) + 0x30) & 0xfffffffb
      ;
    }
  }
  uVar12 = FUN_80135d54(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar3,
                        (int)piVar11,piVar11 + 0x1ea);
  uVar12 = FUN_80135d54(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar3,
                        (int)piVar11,piVar11 + 0x1ec);
  FUN_80135d54(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar3,(int)piVar11,
               piVar11 + 0x1ee);
  FUN_80136310(uVar3,piVar11);
  FUN_80135f38(uVar3,piVar11);
  FUN_8006ef38((double)lbl_803E3078,(double)lbl_803E3078,uVar3,param_11 + 0xf0,1,
               (int)(piVar11 + 0x1f6),(int)(piVar11 + 0x3e));
  if ((piVar11[0x15] & 1U) != 0) {
    *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) & 0xffbf;
    FUN_8003b280(uVar3,(int)(piVar11 + 0xde));
    (**(code **)(*DAT_803dd6d4 + 0x78))(uVar3,param_11,1,0xf,0x1e,0,0);
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80145ea4
 * EN v1.0 Address: 0x80145EA4
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x80145BBC
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80145ea4(int param_1)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  uVar1 = FUN_80017690(0x4e4);
  if (uVar1 != 0) {
    *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) | 0x10000;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80145ee8
 * EN v1.0 Address: 0x80145EE8
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x80145CE4
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80145ee8(int param_1,int param_2,int param_3)
{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if (param_2 == 0) {
    *(uint *)(iVar4 + 0x54) = *(uint *)(iVar4 + 0x54) | 0x10000;
  }
  else if (*(char *)(iVar4 + 8) == '\x05') {
    if (*(char *)(iVar4 + 10) != '\0') {
      *(int *)(iVar4 + 0x24) = param_3;
    }
  }
  else if ((*(uint *)(iVar4 + 0x54) & 0x10) == 0) {
    uVar1 = FUN_800da700(param_3 + 0x18,0xffffffff,3);
    *(undefined4 *)(iVar4 + 0x700) = uVar1;
    uVar2 = FUN_80017760(0x168,0x28);
    *(float *)(iVar4 + 0x710) =
         (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e30f0);
    *(undefined *)(iVar4 + 8) = 5;
    *(int *)(iVar4 + 0x24) = param_3;
    iVar3 = *(int *)(iVar4 + 0x700) + 8;
    if (*(int *)(iVar4 + 0x28) != iVar3) {
      *(int *)(iVar4 + 0x28) = iVar3;
      *(uint *)(iVar4 + 0x54) = *(uint *)(iVar4 + 0x54) & 0xfffffbff;
      *(undefined2 *)(iVar4 + 0xd2) = 0;
    }
    *(undefined *)(iVar4 + 10) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: sideCommandEnable
 * EN v1.0 Address: 0x801459E0
 * EN v1.0 Size: 240b
 * EN v1.1 Address: 0x80145E08
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void sideCommandEnable(int param_1,int param_2,int param_3,int param_4)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(byte *)(iVar1 + 0x798) == 10) {
    trickyReportError(sSidekickCommandDebugTextBlock);
    return;
  }
  *(byte *)(iVar1 + 0xb) = *(byte *)(iVar1 + 0xb) | (byte)(1 << param_4);
  iVar3 = 0;
  iVar2 = iVar1;
  for (iVar4 = (uint)*(byte *)(iVar1 + 0x798); 0 < iVar4; iVar4 = iVar4 - 1) {
    if (*(uint *)(iVar2 + 0x748) == (uint)param_2) {
      *(undefined *)(iVar1 + iVar3 * 8 + 0x74e) = 3;
      return;
    }
    iVar2 = iVar2 + 8;
    iVar3 = iVar3 + 1;
  }
  iVar2 = iVar1 + (uint)*(byte *)(iVar1 + 0x798) * 8;
  *(int *)(iVar2 + 0x748) = param_2;
  iVar2 = iVar1 + (uint)*(byte *)(iVar1 + 0x798) * 8;
  *(char *)(iVar2 + 0x74c) = (char)param_3;
  iVar2 = iVar1 + (uint)*(byte *)(iVar1 + 0x798) * 8;
  *(char *)(iVar2 + 0x74d) = (char)param_4;
  iVar2 = iVar1 + (uint)*(byte *)(iVar1 + 0x798) * 8;
  *(undefined *)(iVar2 + 0x74e) = 3;
  *(char *)(iVar1 + 0x798) = *(char *)(iVar1 + 0x798) + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801460b8
 * EN v1.0 Address: 0x801460B8
 * EN v1.0 Size: 1980b
 * EN v1.1 Address: 0x80145F10
 * EN v1.1 Size: 1648b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801460b8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  char cVar1;
  ushort uVar2;
  bool bVar3;
  bool bVar4;
  bool bVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  bool bVar11;
  undefined2 *puVar9;
  undefined4 uVar10;
  byte bVar12;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar13;
  double extraout_f1;
  double extraout_f1_00;
  double dVar14;
  char local_38 [4];
  char local_34 [4];
  undefined4 local_30 [12];
  
  iVar6 = FUN_80286834();
  iVar13 = *(int *)(iVar6 + 0xb8);
  bVar11 = false;
  bVar3 = false;
  bVar4 = false;
  bVar5 = false;
  local_30[0] = DAT_803e3058;
  dVar14 = extraout_f1;
  uVar7 = FUN_80017690(0x4e4);
  if (uVar7 != 0) {
    if ((*(uint *)(iVar13 + 0x54) & 0x10) != 0) {
      *(undefined *)(iVar13 + 0xb) = 0;
    }
    cVar1 = *(char *)(iVar13 + 8);
    if (((cVar1 == '\b') || (cVar1 == '\r')) ||
       ((cVar1 == '\x0e' && (*(char *)(iVar13 + 10) == '\x01')))) {
      bVar3 = true;
    }
    else {
      iVar8 = FUN_801365c4();
      dVar14 = extraout_f1_00;
      if (iVar8 != 0) {
        bVar3 = true;
        bVar5 = true;
      }
    }
    if (*(char *)(iVar13 + 0xb) != '\0') {
      for (bVar12 = 0; bVar12 < *(byte *)(iVar13 + 0x798); bVar12 = bVar12 + 1) {
        iVar8 = iVar13 + (uint)bVar12 * 8;
        cVar1 = *(char *)(iVar8 + 0x74c);
        if (cVar1 == '\0') {
          if (*(short *)(*(int *)(iVar8 + 0x748) + 0x46) == 0x6a) {
            bVar4 = true;
          }
          bVar3 = true;
        }
        else if (cVar1 == '\x01') {
          bVar11 = true;
        }
      }
    }
    if (((*(uint *)(iVar13 + 0x54) & 0x10) == 0) && (uVar7 = FUN_80017690(0x3f8), uVar7 != 0)) {
      iVar8 = FUN_80017a98();
      iVar8 = FUN_80294c80(iVar8);
      if ((iVar8 != 0) && (uVar7 = FUN_80017690(0xd00), uVar7 == 0)) {
        FUN_80294ca8(*(int *)(iVar13 + 4));
      }
    }
    FUN_80017690(0xdd);
    FUN_80017690(0x9e);
    FUN_80017690(0x245);
    *(undefined *)(iVar13 + 0xb) = 0;
    if ((bVar11) && ((*(uint *)(iVar13 + 0x54) & 0x200) == 0)) {
      *(float *)(iVar13 + 0x7b4) = lbl_803E3188;
      if ((*(int *)(iVar13 + 0x7b0) == 0) && (uVar7 = FUN_80017ae8(), (uVar7 & 0xff) != 0)) {
        uVar7 = FUN_80017760(0,1);
        uVar2 = *(ushort *)((int)local_30 + uVar7 * 2);
        iVar8 = *(int *)(iVar6 + 0xb8);
        if (((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) &&
           (((0x2f < *(short *)(iVar6 + 0xa0) || (*(short *)(iVar6 + 0xa0) < 0x29)) &&
            (bVar11 = FUN_800067f0(iVar6,0x10), !bVar11)))) {
          in_r8 = 0;
          dVar14 = (double)FUN_80039468(iVar6,iVar8 + 0x3a8,uVar2,0x500,0xffffffff,0);
        }
        puVar9 = FUN_80017aa4(0x20,0x17c);
        local_34[0] = -1;
        local_34[1] = -1;
        local_34[2] = -1;
        if (*(int *)(iVar13 + 0x7a8) != 0) {
          local_34[*(byte *)(iVar13 + 0x7bc) >> 6] = '\x01';
        }
        if (*(int *)(iVar13 + 0x7b0) != 0) {
          local_34[*(byte *)(iVar13 + 0x7bc) >> 4 & 3] = '\x01';
        }
        if (*(int *)(iVar13 + 0x7b8) != 0) {
          local_34[*(byte *)(iVar13 + 0x7bc) >> 2 & 3] = '\x01';
        }
        if (local_34[0] == -1) {
          uVar7 = 0;
        }
        else if (local_34[1] == -1) {
          uVar7 = 1;
        }
        else if (local_34[2] == -1) {
          uVar7 = 2;
        }
        else if (local_34[3] == -1) {
          uVar7 = 3;
        }
        else {
          uVar7 = 0xffffffff;
        }
        *(byte *)(iVar13 + 0x7bc) =
             (byte)((uVar7 & 0xff) << 4) & 0x30 | *(byte *)(iVar13 + 0x7bc) & 0xcf;
        uVar10 = FUN_80017ae4(dVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar9,
                              4,0xff,0xffffffff,*(uint **)(iVar6 + 0x30),in_r8,in_r9,in_r10);
        *(undefined4 *)(iVar13 + 0x7b0) = uVar10;
        dVar14 = (double)ObjLink_AttachChild(iVar6,*(int *)(iVar13 + 0x7b0),
                                      *(byte *)(iVar13 + 0x7bc) >> 4 & 3);
      }
    }
    else if (*(int *)(iVar13 + 0x7b0) != 0) {
      *(float *)(iVar13 + 0x7b4) = *(float *)(iVar13 + 0x7b4) - lbl_803DC074;
      dVar14 = (double)*(float *)(iVar13 + 0x7b4);
      if (dVar14 <= (double)lbl_803E306C) {
        dVar14 = (double)FUN_80135d54(dVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                      ,iVar6,iVar13,(int *)(iVar13 + 0x7b0));
      }
    }
    if ((bVar3) && ((*(uint *)(iVar13 + 0x54) & 0x200) == 0)) {
      *(float *)(iVar13 + 0x7ac) = lbl_803E3188;
      if ((*(int *)(iVar13 + 0x7a8) == 0) && (uVar7 = FUN_80017ae8(), (uVar7 & 0xff) != 0)) {
        uVar7 = FUN_80017760(0,3);
        if (uVar7 == 0) {
          if (bVar4) {
            iVar8 = *(int *)(iVar6 + 0xb8);
            if (((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) &&
               (((0x2f < *(short *)(iVar6 + 0xa0) || (*(short *)(iVar6 + 0xa0) < 0x29)) &&
                (bVar11 = FUN_800067f0(iVar6,0x10), !bVar11)))) {
              in_r8 = 0;
              dVar14 = (double)FUN_80039468(iVar6,iVar8 + 0x3a8,0x359,0x500,0xffffffff,0);
            }
          }
          else if ((((bVar5) &&
                    (iVar8 = *(int *)(iVar6 + 0xb8), (*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0)) &&
                   ((0x2f < *(short *)(iVar6 + 0xa0) || (*(short *)(iVar6 + 0xa0) < 0x29)))) &&
                  (bVar11 = FUN_800067f0(iVar6,0x10), !bVar11)) {
            in_r8 = 0;
            dVar14 = (double)FUN_80039468(iVar6,iVar8 + 0x3a8,0x358,0x500,0xffffffff,0);
          }
        }
        puVar9 = FUN_80017aa4(0x20,0x175);
        local_38[0] = -1;
        local_38[1] = -1;
        local_38[2] = -1;
        if (*(int *)(iVar13 + 0x7a8) != 0) {
          local_38[*(byte *)(iVar13 + 0x7bc) >> 6] = '\x01';
        }
        if (*(int *)(iVar13 + 0x7b0) != 0) {
          local_38[*(byte *)(iVar13 + 0x7bc) >> 4 & 3] = '\x01';
        }
        if (*(int *)(iVar13 + 0x7b8) != 0) {
          local_38[*(byte *)(iVar13 + 0x7bc) >> 2 & 3] = '\x01';
        }
        if (local_38[0] == -1) {
          uVar7 = 0;
        }
        else if (local_38[1] == -1) {
          uVar7 = 1;
        }
        else if (local_38[2] == -1) {
          uVar7 = 2;
        }
        else if (local_38[3] == -1) {
          uVar7 = 3;
        }
        else {
          uVar7 = 0xffffffff;
        }
        *(byte *)(iVar13 + 0x7bc) = (byte)((uVar7 & 0xff) << 6) | *(byte *)(iVar13 + 0x7bc) & 0x3f;
        uVar10 = FUN_80017ae4(dVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar9,
                              4,0xff,0xffffffff,*(uint **)(iVar6 + 0x30),in_r8,in_r9,in_r10);
        *(undefined4 *)(iVar13 + 0x7a8) = uVar10;
        ObjLink_AttachChild(iVar6,*(int *)(iVar13 + 0x7a8),(ushort)(*(byte *)(iVar13 + 0x7bc) >> 6));
      }
    }
    else if (*(int *)(iVar13 + 0x7a8) != 0) {
      *(float *)(iVar13 + 0x7ac) = *(float *)(iVar13 + 0x7ac) - lbl_803DC074;
      if ((double)*(float *)(iVar13 + 0x7ac) <= (double)lbl_803E306C) {
        FUN_80135d54((double)*(float *)(iVar13 + 0x7ac),param_2,param_3,param_4,param_5,param_6,
                     param_7,param_8,iVar6,iVar13,(int *)(iVar13 + 0x7a8));
      }
    }
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80146874
 * EN v1.0 Address: 0x80146874
 * EN v1.0 Size: 124b
 * EN v1.1 Address: 0x80146580
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80146874(void)
{
  uint uVar1;
  uint uVar2;
  
  uVar2 = 0;
  uVar1 = FUN_80017690(0x4e4);
  if (uVar1 != 0) {
    uVar2 = 10;
    uVar1 = FUN_80017690(0xdd);
    if (uVar1 != 0) {
      uVar2 = 0xb;
    }
    uVar1 = FUN_80017690(0x25);
    if (uVar1 != 0) {
      uVar2 = uVar2 | 0x20;
    }
    uVar1 = FUN_80017690(0x245);
    if (uVar1 != 0) {
      uVar2 = uVar2 | 0x10;
    }
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: Tricky_destroy
 * EN v1.0 Address: 0x801461DC
 * EN v1.0 Size: 480b
 * EN v1.1 Address: 0x80146604
 * EN v1.1 Size: 480b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void Tricky_destroy(int obj,int shouldKeepFlameChildren)
{
  bool bVar1;
  int state;
  int i;
  int childSlot;
  
  state = *(int *)(obj + 0xb8);
  fn_8004B594((void *)(state + 0x538));
  fn_8004B594((void *)(state + 0x568));
  fn_8004B594((void *)(state + 0x598));
  fn_8004B594((void *)(state + 0x5c8));
  fn_8004B594((void *)(state + 0x5f8));
  fn_8004B594((void *)(state + 0x628));
  fn_8004B594((void *)(state + 0x658));
  fn_8004B594((void *)(state + 0x688));
  fn_8004B594((void *)(state + 0x6b8));
  ObjGroup_RemoveObject(obj,1);
  (**(code **)(*lbl_803DCA78 + 0x14))(obj);
  if ((shouldKeepFlameChildren == 0) && ((*(uint *)(state + 0x54) & 0x800) != 0)) {
    *(uint *)(state + 0x54) = *(uint *)(state + 0x54) & 0xfffff7ff;
    *(uint *)(state + 0x54) = *(uint *)(state + 0x54) | 0x1000;
    i = 0;
    childSlot = state;
    do {
      objSetAnimSpeedTo1(*(int *)(childSlot + 0x700));
      childSlot = childSlot + 4;
      i = i + 1;
    } while (i < 7);
    Sfx_RemoveLoopedObjectSound(obj,0x3dc);
    childSlot = *(int *)(obj + 0xb8);
    if (((*(byte *)(childSlot + 0x58) >> 6 & 1) == 0) &&
       (((0x2f < *(short *)(obj + 0xa0) || (*(short *)(obj + 0xa0) < 0x29)) &&
        (bVar1 = Sfx_IsPlayingFromObjectChannel(obj,0x10), !bVar1)))) {
      objAudioFn_800393f8(obj,(void *)(childSlot + 0x3a8),0x29d,0,0xffffffff,0);
    }
  }
  fn_800DD640();
  fn_801389E0(obj,state,(int *)(state + 0x7a8));
  fn_801389E0(obj,state,(int *)(state + 0x7b0));
  fn_801389E0(obj,state,(int *)(state + 0x7b8));
  if (*(int *)(state + 0x7cc) != 0) {
    ObjLink_DetachChild(obj,*(int *)(state + 0x7cc));
    Obj_FreeObject(*(int *)(state + 0x7cc));
  }
  if (((*(byte *)(state + 0x58) >> 7 & 1) != 0) && (lbl_803DDA48 != 0)) {
    Obj_FreeObject(lbl_803DDA48);
    lbl_803DDA48 = 0;
  }
  return;
}

/* fn_80148C18: 372b - resume Tricky visibility, collision, and fade after command finish. */
#pragma scheduling off
void fn_80148C18(int obj,int state)
{
  u8 moveId;

  *(u8 *)(state + 0x2ef) = 1;
  if (((*(u32 *)(state + 0x2dc) & 0x1000) != 0) &&
      ((*(u32 *)(state + 0x2e0) & 0x1000) == 0)) {
    *(s16 *)(obj + 6) = *(s16 *)(obj + 6) & 0xbfff;
    moveId = *(u8 *)(state + 0x320);
    *(f32 *)(state + 0x308) = lbl_803E256C / (lbl_803E2570 * *(f32 *)(state + 0x314));
    *(u8 *)(state + 0x323) = 1;
    ObjAnim_SetCurrentMove(lbl_803E2574,obj,moveId,0x10);
    if (*(int *)(obj + 0x54) != 0) {
      *(u8 *)(*(int *)(obj + 0x54) + 0x70) = 0;
    }
    *(u32 *)(state + 0x2e8) = *(u32 *)(state + 0x2e8) | 4;
    Sfx_PlayFromObjectLimited(obj,1099,2);
    ObjHits_EnableObject(obj);
  }
  if ((*(u32 *)(state + 0x2dc) & 0x40000000) == 0) {
    *(u8 *)(obj + 0x36) = (int)(lbl_803E257C * *(f32 *)(obj + 0x98));
    *(f32 *)(state + 0x30c) = *(f32 *)(obj + 0x98);
  }
  else {
    *(f32 *)(state + 0x308) = lbl_803E2578;
    *(u8 *)(state + 0x323) = 0;
    ObjAnim_SetCurrentMove(lbl_803E2574,obj,0,0);
    if (*(int *)(obj + 0x54) != 0) {
      *(u8 *)(*(int *)(obj + 0x54) + 0x70) = 0;
    }
    *(u32 *)(state + 0x2dc) = *(u32 *)(state + 0x2dc) & 0xffffef7f;
    *(u32 *)(state + 0x2e8) = *(u32 *)(state + 0x2e8) & 0xfffffffb;
    *(f32 *)(state + 0x30c) = lbl_803E2574;
    *(u8 *)(obj + 0x36) = 0xff;
  }
}
#pragma scheduling reset

/* fn_80148D8C: 828b - handle Tricky's completed-command fade and reward spawning. */
#pragma scheduling off
void fn_80148D8C(int obj,int state)
{
  int setup;
  int alpha;
  int tricky;
  u32 spawnBits;
  u8 moveId;

  setup = *(int *)(obj + 0x4c);
  *(u8 *)(state + 0x2ef) = 0;
  if (((*(u32 *)(state + 0x2dc) & 0x800) != 0) &&
      ((*(u32 *)(state + 0x2e0) & 0x800) == 0)) {
    tricky = getTrickyObject();
    if (tricky != 0) {
      trickyImpress(tricky);
    }
    if ((*(u32 *)(state + 0x2e4) & 0x40000000) == 0) {
      if (*(s16 *)(setup + 0x18) != -1) {
        gameBitIncrement(*(s16 *)(setup + 0x18));
      }
      if (*(s16 *)(setup + 0x1a) != -1) {
        GameBit_Set(*(s16 *)(setup + 0x1a),0);
      }
    }
    *(u32 *)(state + 0x29c) = 0;
    ObjHits_DisableObject(obj);
    *(u8 *)(obj + 0xaf) = *(u8 *)(obj + 0xaf) | 8;
    moveId = *(u8 *)(state + 0x321);
    *(f32 *)(state + 0x308) = lbl_803E256C / (lbl_803E2570 * *(f32 *)(state + 0x318));
    *(u8 *)(state + 0x323) = 1;
    ObjAnim_SetCurrentMove(lbl_803E2574,obj,moveId,0);
    if (*(int *)(obj + 0x54) != 0) {
      *(u8 *)(*(int *)(obj + 0x54) + 0x70) = 0;
    }
    *(u32 *)(state + 0x2e8) = *(u32 *)(state + 0x2e8) | 1;
    Sfx_PlayFromObject(obj,0x233);
    if (randomGetRange(0,100) > 50) {
      if ((*(u32 *)(state + 0x2e4) & 0x100000) != 0) {
        fn_80149CEC(obj,state,*(u8 *)(state + 0x2f5),0,4);
      }
      else {
        spawnBits = *(s16 *)(setup + 0x22) & 0xf00;
        if (spawnBits != 0) {
          fn_80149CEC(obj,state,spawnBits,0,1);
        }
        spawnBits = *(s16 *)(setup + 0x22) & 0xf000;
        if (spawnBits != 0) {
          fn_80149CEC(obj,state,spawnBits,0,2);
        }
        spawnBits = *(s16 *)(setup + 0x22) & 0xff;
        if (spawnBits != 0) {
          fn_80149CEC(obj,state,spawnBits,0,3);
        }
      }
    }
  }
  alpha = 0xff - (int)(lbl_803E257C * *(f32 *)(obj + 0x98));
  if (alpha < 0) {
    alpha = 0;
  }
  else if (alpha > 0xff) {
    alpha = 0xff;
  }
  *(u8 *)(obj + 0x36) = alpha;
  *(f32 *)(state + 0x30c) =
      lbl_803E256C + (f32)(0xff - *(u8 *)(obj + 0x36)) / lbl_803E257C;
  if (*(u8 *)(obj + 0x36) < 5) {
    if ((*(u32 *)(state + 0x2e4) & 0x40000000) != 0) {
      if (*(s16 *)(setup + 0x18) != -1) {
        gameBitIncrement(*(s16 *)(setup + 0x18));
      }
      if (*(s16 *)(setup + 0x1a) != -1) {
        GameBit_Set(*(s16 *)(setup + 0x1a),0);
      }
    }
    *(f32 *)(state + 0x30c) = lbl_803E2574;
    *(u32 *)(state + 0x2dc) = 0;
    *(s16 *)(obj + 6) = *(s16 *)(obj + 6) | 0x4000;
    *(u8 *)(obj + 0x36) = 0;
    *(u32 *)(obj + 0xf4) = 1;
    if (*(int *)(setup + 0x14) == -1) {
      Obj_FreeObject(obj);
    }
    else {
      if (*(s16 *)(setup + 0x2c) != 0) {
        (*(void (**)(f32))(*(int *)lbl_803DCAAC + 0x64))
            (lbl_803E2570 * (f32)*(s16 *)(setup + 0x2c));
      }
      *(u32 *)(state + 0x2dc) = *(u32 *)(state + 0x2dc) & 0xfffff7ff;
      *(u32 *)(state + 0x2e8) = *(u32 *)(state + 0x2e8) & 0xfffffffc;
    }
  }
}
#pragma scheduling reset

/* fn_80149CEC: 876b - spawn or reposition Tricky reward objects from packed command bits. */
#pragma scheduling off
int fn_80149CEC(int obj,int state,u32 spawnBits,u32 useAltMode,u32 mode)
{
  struct TrickyRewardSpawnTail {
    u32 pair;
    u16 single;
  } rewardTail;
  u32 commandSpawnIds[2];
  u32 rewardSpawnIds0;
  f32 nearestDistance;
  int parentSetup;
  int setup;
  int index;
  f32 savedX;
  f32 savedY;
  f32 savedZ;

  (void)state;
  parentSetup = *(int *)(obj + 0x4c);
  commandSpawnIds[0] = lbl_803E2558;
  commandSpawnIds[1] = lbl_803E255C;
  rewardSpawnIds0 = lbl_803E2560;
  rewardTail.pair = lbl_803E2564;
  rewardTail.single = lbl_803E2568;
  setup = 0;
  if (spawnBits == 0) {
    return 0;
  }
  if (Obj_IsLoadingLocked() == 0) {
    return 0;
  }
  mode = (u8)mode;
  if (mode == 1) {
    index = ((int)(spawnBits & 0xf00) >> 8) - 1;
    if (index > 3) {
      index = 3;
    }
    setup = Obj_AllocObjectSetup(0x30,*(u16 *)((int)commandSpawnIds + index * 2));
  }
  else if (mode == 2) {
    index = ((int)(spawnBits & 0xf000) >> 0xc) - 1;
    if (index > 1) {
      index = 1;
    }
    setup = Obj_AllocObjectSetup(0x30,*(u16 *)((int)&rewardSpawnIds0 + index * 2));
  }
  else if (mode == 3) {
    if (spawnBits == 3) {
      setup = Obj_AllocObjectSetup(0x30,0xb);
    }
    else if ((int)spawnBits < 3) {
      if (spawnBits != 1) {
        return 0;
      }
      setup = Obj_AllocObjectSetup(0x30,0x2cd);
    }
    else {
      if (spawnBits == 5) {
        savedX = *(f32 *)(obj + 0x18);
        savedY = *(f32 *)(obj + 0x1c);
        savedZ = *(f32 *)(obj + 0x20);
        parentSetup = *(int *)(obj + 0x4c);
        if (parentSetup != 0) {
          *(f32 *)(obj + 0x18) = *(f32 *)(parentSetup + 8);
          *(f32 *)(obj + 0x1c) = *(f32 *)(parentSetup + 0xc);
          *(f32 *)(obj + 0x20) = *(f32 *)(parentSetup + 0x10);
        }
        nearestDistance = lbl_803E25A8;
        lbl_803DDA54 = ObjGroup_FindNearestObject(4,obj,&nearestDistance);
        *(f32 *)(obj + 0x18) = savedX;
        *(f32 *)(obj + 0x1c) = savedY;
        *(f32 *)(obj + 0x20) = savedZ;
        if (lbl_803DDA54 != 0) {
          *(f32 *)(lbl_803DDA54 + 0x18) = *(f32 *)(obj + 0xc);
          *(f32 *)(lbl_803DDA54 + 0xc) = *(f32 *)(obj + 0xc);
          *(f32 *)(lbl_803DDA54 + 0x1c) = lbl_803E25AC + *(f32 *)(obj + 0x10);
          *(f32 *)(lbl_803DDA54 + 0x10) = lbl_803E25AC + *(f32 *)(obj + 0x10);
          *(f32 *)(lbl_803DDA54 + 0x20) = *(f32 *)(obj + 0x14);
          *(f32 *)(lbl_803DDA54 + 0x14) = *(f32 *)(obj + 0x14);
        }
        return lbl_803DDA54;
      }
      if ((int)spawnBits > 4) {
        return 0;
      }
      setup = Obj_AllocObjectSetup(0x30,0x2cd);
    }
  }
  else if (mode == 4) {
    if ((int)spawnBits > 3) {
      spawnBits = 3;
    }
    if ((int)spawnBits < 1) {
      return 0;
    }
    setup = Obj_AllocObjectSetup(0x30,*(u16 *)((int)&rewardTail.pair + (spawnBits - 1) * 2));
  }
  *(u8 *)(setup + 0x1a) = 0x14;
  *(s16 *)(setup + 0x2c) = -1;
  *(s16 *)(setup + 0x1c) = -1;
  *(s16 *)(setup + 0x24) = -1;
  *(f32 *)(setup + 8) = *(f32 *)(obj + 0xc);
  *(f32 *)(setup + 0xc) = lbl_803E2598 + *(f32 *)(obj + 0x10);
  *(f32 *)(setup + 0x10) = *(f32 *)(obj + 0x14);
  if ((useAltMode & 0xff) != 0) {
    *(s16 *)(setup + 0x2e) = 2;
  }
  else {
    *(s16 *)(setup + 0x2e) = 1;
  }
  *(u8 *)(setup + 4) = *(u8 *)(parentSetup + 4);
  *(u8 *)(setup + 6) = *(u8 *)(parentSetup + 6);
  *(u8 *)(setup + 5) = *(u8 *)(parentSetup + 5);
  *(u8 *)(setup + 7) = *(u8 *)(parentSetup + 7);
  lbl_803DDA54 = Obj_SetupObject(setup,5,*(s8 *)(obj + 0xac),-1,*(int *)(obj + 0x30));
  if ((*(s16 *)(lbl_803DDA54 + 0x46) == 0x3cd) ||
      (*(s16 *)(lbl_803DDA54 + 0x46) == 0xb)) {
    (*(void (**)(f32,f32,f32))(*(int *)(*(int *)(lbl_803DDA54 + 0x68)) + 0x2c))
        (lbl_803E2574,lbl_803E256C,lbl_803E2574);
  }
  return lbl_803DDA54;
}
#pragma scheduling reset

/* fn_8014A058: 248b - refresh Tricky's attached child object when its setup id changes. */
#pragma scheduling off
void fn_8014A058(int obj,int state)
{
  int parentSetup;
  int child;
  int setup;

  parentSetup = *(int *)(obj + 0x4c);
  if ((*(s16 *)(state + 0x2b4) != *(s16 *)(state + 0x2b6)) &&
      (*(u8 *)(obj + 0x36) != 0)) {
    child = *(int *)(obj + 0xc8);
    if (child != 0) {
      ObjLink_DetachChild(obj,child);
      Obj_FreeObject(child);
    }
    if (Obj_IsLoadingLocked() != 0) {
      if (*(s16 *)(state + 0x2b6) > 0) {
        setup = Obj_AllocObjectSetup(0x20);
        *(u8 *)(setup + 5) = *(u8 *)(setup + 5) | (*(u8 *)(parentSetup + 5) & 0x18);
        child = Obj_SetupObject(setup,4,*(s8 *)(obj + 0xac),-1,*(int *)(obj + 0x30));
        ObjLink_AttachChild(obj,child,0);
        *(s16 *)(state + 0x2b4) = *(s16 *)(state + 0x2b6);
      }
    }
    else {
      *(s16 *)(state + 0x2b4) = 0;
    }
  }
}
#pragma scheduling reset

/* fn_8014A150: 436b - line-of-sight and bbox visibility check between Tricky and a target. */
#pragma scheduling off
int fn_8014A150(int obj,int state,void *from,void *to)
{
  u8 traceHit[4];
  s16 toGrid[4];
  s16 fromGrid[4];
  Vec probe;
  Vec delta;
  u8 bboxHit[116];
  s16 setupId;
  u8 visible;
  int keepGroundOffset;

  traceHit[0] = 0;
  visible = 0;
  if (*(u32 *)(state + 0x29c) != 0) {
    probe.x = *(f32 *)((int)from + 0);
    probe.y = *(f32 *)((int)from + 4);
    probe.z = *(f32 *)((int)from + 8);
    keepGroundOffset = 1;
    setupId = *(s16 *)(obj + 0x46);
    if (((((setupId != 0x613) && (setupId != 0x642)) && (setupId != 0x3fe)) &&
        ((setupId != 0x7c6) && (setupId != 0x7c8))) &&
        ((setupId != 0x251) && (setupId != 0x851))) {
      probe.y += lbl_803E25A0;
      keepGroundOffset = 0;
    }
    voxmaps_worldToGrid(&probe,fromGrid);
    probe.x = *(f32 *)((int)to + 0);
    probe.y = lbl_803E25A0 + *(f32 *)((int)to + 4);
    probe.z = *(f32 *)((int)to + 8);
    voxmaps_worldToGrid(&probe,toGrid);
    PSVECSubtract((Vec *)from,&probe,&delta);
    if (PSVECMag(&delta) < lbl_803E25B0) {
      if (*(u32 *)(obj + 0x30) == 0) {
        visible = voxmaps_traceLine(toGrid,fromGrid,0,traceHit,0);
      }
      if ((keepGroundOffset == 0) && (traceHit[0] == 1)) {
        visible = 1;
      }
    }
  }
  if ((visible != 0) && ((*(u32 *)(state + 0x2e4) & 8) != 0)) {
    if (objBboxFn_800640cc(lbl_803E256C,(Vec *)from,&probe,0,bboxHit,obj,*(u8 *)(state + 0x261),
                           -1,0,0) != 0) {
      visible = 0;
    }
  }
  return visible;
}
#pragma scheduling reset

/* fn_8014A304: 760b - update Tricky's four quadrant line-of-sight state bits. */
#pragma scheduling off
void fn_8014A304(f32 radius,int obj,int state)
{
  u8 traceHit[4];
  s16 probeGrid[4];
  s16 baseGrid[4];
  Vec probe;
  u32 visibilityBits[4];
  Vec delta;
  u8 bboxHit[84];
  s16 baseAngle;
  int i;
  u8 visible;
  f32 angle;
  f32 angleScale;
  f32 angleDivisor;
  f32 maxDistance;
  s16 setupId;

  visibilityBits[0] = lbl_802C21F0[0];
  visibilityBits[1] = lbl_802C21F0[1];
  visibilityBits[2] = lbl_802C21F0[2];
  visibilityBits[3] = lbl_802C21F0[3];
  probe.x = *(f32 *)(obj + 0xc);
  probe.y = lbl_803E25A0 + *(f32 *)(obj + 0x10);
  probe.z = *(f32 *)(obj + 0x14);
  voxmaps_worldToGrid(&probe,baseGrid);
  if (*(u32 *)(obj + 0x30) != 0) {
    baseAngle = *(s16 *)obj + **(s16 **)(obj + 0x30);
  }
  else {
    baseAngle = *(s16 *)obj;
  }
  angleScale = lbl_803E25B4;
  angleDivisor = lbl_803E25B8;
  maxDistance = lbl_803E25B0;
  for (i = 0; i < 4; i++) {
    angle = (angleScale * (f32)((s32)baseAngle + ((u32)(u16)i << 0xe))) / angleDivisor;
    probe.x = *(f32 *)(obj + 0x18) - (radius * fn_80293E80(angle));
    probe.y = *(f32 *)(obj + 0x1c);
    probe.z = *(f32 *)(obj + 0x20) - (radius * sin(angle));
    setupId = *(s16 *)(obj + 0x46);
    if (((((setupId != 0x613) && (setupId != 0x642)) && (setupId != 0x3fe)) &&
        ((setupId != 0x7c6) && (setupId != 0x7c8))) &&
        ((setupId != 0x251) && (setupId != 0x851))) {
      probe.y += lbl_803E25A0;
    }
    voxmaps_worldToGrid(&probe,probeGrid);
    PSVECSubtract((Vec *)(obj + 0x18),&probe,&delta);
    if (PSVECMag(&delta) < maxDistance) {
      if (*(u32 *)(obj + 0x30) != 0) {
        visible = 1;
      }
      else {
        visible = voxmaps_traceLine(probeGrid,baseGrid,0,traceHit,0);
        if (traceHit[0] == 1) {
          visible = 1;
        }
      }
    }
    else {
      visible = 0;
    }
    if ((visible != 0) && ((*(u32 *)(state + 0x2e4) & 8) != 0)) {
      if (objBboxFn_800640cc(lbl_803E256C,(Vec *)(obj + 0x18),&probe,0,bboxHit,obj,
                             *(u8 *)(state + 0x261),-1,0,0) != 0) {
        visible = 0;
      }
    }
    if (visible != 0) {
      *(u32 *)(state + 0x2dc) |= visibilityBits[i];
    }
    else {
      *(u32 *)(state + 0x2dc) &= ~visibilityBits[i];
    }
  }
}
#pragma scheduling reset

/* fn_8014A5FC: 624b - apply Tricky floor response and movement-control callbacks. */
#pragma scheduling off
void fn_8014A5FC(int obj,int state)
{
  f32 nearestFloorY;
  f32 nearestSpecialY;
  f32 points[6];
  u32 flags;
  f32 dy;

  *(u32 *)(state + 0x2dc) &= 0xf7efffff;
  flags = *(u32 *)(state + 0x2e4);
  if ((flags & 0x28000002) != 0) {
    fn_8014A86C(obj,state,&nearestFloorY,&nearestSpecialY);
    flags = *(u32 *)(state + 0x2e4);
    if ((flags & 0x08000000) != 0) {
      *(f32 *)(obj + 0x28) = (nearestSpecialY - *(f32 *)(obj + 0x10)) * oneOverTimeDelta;
    }
    else if ((flags & 0x20000000) != 0) {
      dy = nearestFloorY - *(f32 *)(obj + 0x10);
      if ((lbl_803E25BC < dy) && (dy < lbl_803E25A0)) {
        *(f32 *)(obj + 0x28) = (lbl_803E25C0 + dy) * oneOverTimeDelta;
        *(u32 *)(state + 0x2dc) |= 0x08000000;
      }
    }
    else {
      dy = nearestFloorY - *(f32 *)(obj + 0x10);
      if ((lbl_803E25BC < dy) && (dy < lbl_803E25A0)) {
        *(f32 *)(obj + 0x28) = dy * oneOverTimeDelta;
        *(u32 *)(state + 0x2dc) |= 0x00100000;
      }
    }
    if ((*(u32 *)(state + 0x2e4) & 8) == 0) {
      *(u8 *)(state + 0x25f) = 0;
    }
  }
  else {
    if ((flags & 0xc) != 0) {
      *(u8 *)(state + 0x25f) = 1;
    }
    else {
      *(u8 *)(state + 0x25f) = 0;
    }
  }

  (*(void (**)(f32,int,int))(*(int *)lbl_803DCAA8 + 0x10))(timeDelta,obj,state + 4);
  if ((*(u32 *)(state + 0x2e4) & 4) != 0) {
    (*(void (**)(int,int))(*(int *)lbl_803DCAA8 + 0x14))(obj,state + 4);
  }
  (*(void (**)(f32,int,int))(*(int *)lbl_803DCAA8 + 0x18))(timeDelta,obj,state + 4);

  if (((*(s8 *)(state + 0x25f) != 0) && ((*(u32 *)(state + 0x2e4) & 0x28000002) == 0)) &&
      ((*(u8 *)(state + 0x264) & 0x10) != 0)) {
    *(f32 *)(obj + 0x28) = lbl_803E2574;
    *(u32 *)(state + 0x2dc) |= 0x00100000;
  }
  if ((*(u32 *)(state + 0x2e4) & 0x00200000) != 0) {
    ObjPath_GetPointWorldPositionArray(obj,2,2,points);
    fn_8006EDCC(*(f32 *)(state + 0x310),lbl_803E256C,obj,*(u16 *)(state + 0x2f8),7,points,
                (void *)(state + 4));
  }
}
#pragma scheduling reset

/* fn_8014A86C: 388b - find nearby floor heights and special surface deltas for Tricky. */
#pragma scheduling off
void fn_8014A86C(int obj,int state,f32 *nearestFloorY,f32 *nearestSpecialY)
{
  int hitList[2];
  u16 hitCount;
  u16 i;
  f32 *hit;
  f32 hitY;
  f32 dy;
  f32 absDy;
  f32 nearestFloorDelta;
  f32 nearestSpecialDelta;

  *nearestFloorY = lbl_803E25C4;
  *nearestSpecialY = lbl_803E25C4;
  hitCount = hitDetectFn_80065e50(*(f32 *)(obj + 0xc),*(f32 *)(obj + 0x10),
                                  *(f32 *)(obj + 0x14),obj,hitList,0,0);
  *nearestFloorY = *(f32 *)(obj + 0x10);
  *nearestSpecialY = *(f32 *)(obj + 0x10);
  nearestFloorDelta = lbl_803E25C8;
  nearestSpecialDelta = nearestFloorDelta;
  *(u32 *)(state + 0x2dc) &= 0xefffffff;
  *(f32 *)(state + 0x1b8) = lbl_803E2574;
  *(u8 *)(state + 0x264) &= 0xef;
  for (i = 0; i < hitCount; i++) {
    hit = *(f32 **)(hitList[0] + ((u32)i << 2));
    hitY = hit[0];
    dy = hitY - *(f32 *)(obj + 0x10);
    absDy = dy;
    if (dy < lbl_803E2574) {
      absDy = -dy;
    }
    if (*(s8 *)(hit + 5) == 0xe) {
      if (absDy < nearestSpecialDelta) {
        *(f32 *)(state + 0x1b8) = dy;
        *(u8 *)(state + 0x264) |= 0x10;
        *nearestSpecialY = **(f32 **)(hitList[0] + ((u32)i << 2));
        nearestSpecialDelta = absDy;
        if (lbl_803E25A0 < *(f32 *)(state + 0x1b8)) {
          *(u32 *)(state + 0x2dc) |= 0x10100000;
        }
      }
    }
    else if (absDy < nearestFloorDelta) {
      *nearestFloorY = hitY;
      *(u8 *)(state + 0x264) |= 0x10;
      nearestFloorDelta = absDy;
    }
  }
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: fn_801463BC
 * EN v1.0 Address: 0x801463BC
 * EN v1.0 Size: 464b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_801463BC(int obj,int param_2,int param_3,int param_4,int param_5,char doRender)
{
  u8 mode;
  int state;
  int pathState;
  int pathPoint;
  int i;
  int pathInfo;

  if (doRender != '\0') {
    state = *(int *)(obj + 0xb8);
    objRenderFn_8003b8f4(lbl_803E23E8);
    pathState = *(int *)(obj + 0xb8);
    i = 0;
    pathPoint = pathState;
    do {
      ObjPath_GetPointWorldPosition(obj,i + 4,(float *)(pathPoint + 0x3d8),
                   (undefined4 *)(pathPoint + 0x3dc),(float *)(pathPoint + 0x3e0),0);
      pathPoint = pathPoint + 0xc;
      i = i + 1;
    } while (i < 4);
    ObjPath_GetPointWorldPosition(obj,8,(float *)(pathState + 0x408),
                 (undefined4 *)(pathState + 0x40c),(float *)(pathState + 0x410),0);
    pathInfo = fn_800395D8(obj,0);
    *(s16 *)(pathState + 0x414) = *(s16 *)(pathInfo + 2);
    if ((*(u32 *)(state + 0x54) & 0x10) != 0) {
      mode = *(u8 *)(state + 8);
      if (mode == 3) {
        if (*(u8 *)(state + 10) == 4) {
          fn_8013ADFC(obj);
        }
      }
      else if ((mode < 3) && (1 < mode)) {
        fn_8013ADFC(obj);
      }
      if ((((*(u32 *)(state + 0x54) & 0x200) == 0) && (*(u8 *)(state + 8) == 0xb)) &&
         (2 < *(u8 *)(state + 10))) {
        if (*(u8 *)(state + 10) != 3) {
          *(f32 *)(*(int *)(state + 0x700) + 0xc) = *(f32 *)(state + 0x408);
          *(f32 *)(*(int *)(state + 0x700) + 0x10) = *(f32 *)(state + 0x40c);
          *(f32 *)(*(int *)(state + 0x700) + 0x14) = *(f32 *)(state + 0x410);
        }
        objRenderFn_8003b8f4(lbl_803E23E8,*(int *)(state + 0x700),param_2,param_3,param_4,param_5);
      }
    }
    fn_80139164(obj,state);
    ObjPath_GetPointWorldPositionArray(obj,4,4,(float *)(state + 0x7d8));
    *(f32 *)(state + 0x838) = *(f32 *)(state + 0x838) - timeDelta;
    if (lbl_803E23DC < *(f32 *)(state + 0x838)) {
      objParticleFn_80099d84(lbl_803E253C,lbl_803E23E8,obj,6,0);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: fn_8014658C
 * EN v1.0 Address: 0x8014658C
 * EN v1.0 Size: 500b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_8014658C(int obj)
{
  f32 dy;
  int *objects;
  int i;
  int state;
  f32 height;
  int count[2];

  state = *(int *)(obj + 0xb8);
  dy = *(f32 *)(obj + 0x10) - *(f32 *)(obj + 0x84);
  if (dy < lbl_803E23DC) {
    dy = -dy;
  }
  if (lbl_803E23E8 == dy) {
    if (*(f32 *)(obj + 0x10) == *(f32 *)(obj + 0x1c)) {
      *(u8 *)(state + 0x58) = (*(u8 *)(state + 0x58) & 0xdf) | 0x20;
      *(s32 *)(state + 0x5c) = -1;
      *(f32 *)(state + 0x60) = lbl_803E23DC;
    }
  }
  else {
    i = ObjList_FindObjectById(0x46406);
    if ((i != 0) && (getXZDistance((f32 *)(obj + 0x18),(f32 *)(i + 0x18)) < lbl_803E2540)) {
      *(u8 *)(state + 0x58) = (*(u8 *)(state + 0x58) & 0xdf) | 0x20;
      *(u32 *)(state + 0x5c) = 0x46406;
      *(f32 *)(state + 0x60) = lbl_803E23DC;
    }
  }
  if ((*(u8 *)(state + 0x58) >> 5 & 1) != 0) {
    objects = ObjGroup_GetObjects(0x51,count);
    for (i = 0; i < count[0]; i++) {
      height = fn_801948C0(*objects,3);
      if (*(s32 *)(state + 0x5c) == -1) {
        dy = height - *(f32 *)(obj + 0x10);
        if (dy < lbl_803E23DC) {
          dy = -dy;
        }
        if (dy < lbl_803E24B8) {
          *(u32 *)(state + 0x5c) = *(u32 *)(*(int *)(*objects + 0x4c) + 0x14);
        }
      }
      if (*(u32 *)(state + 0x5c) == *(u32 *)(*(int *)(*objects + 0x4c) + 0x14)) {
        if ((*(f32 *)(state + 0x60) == lbl_803E23DC) ||
           (*(f32 *)(state + 0x60) != height)) {
          *(f32 *)(obj + 0x10) = height;
          *(f32 *)(state + 0x60) = height;
        }
        else {
          *(u8 *)(state + 0x58) = *(u8 *)(state + 0x58) & 0xdf;
        }
        break;
      }
      objects = objects + 1;
    }
    if (i == count[0]) {
      *(u8 *)(state + 0x58) = *(u8 *)(state + 0x58) & 0xdf;
    }
  }
  return;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80146f94
 * EN v1.0 Address: 0x80146F94
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80146BA8
 * EN v1.1 Size: 8672b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80146f94(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80146f98
 * EN v1.0 Address: 0x80146F98
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80148D88
 * EN v1.1 Size: 536b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80146f98(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80146f9c
 * EN v1.0 Address: 0x80146F9C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80148FA0
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80146f9c(void)
{
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80146fa0
 * EN v1.0 Address: 0x80146FA0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80148FF0
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80146fa0(void)
{
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80146fa4
 * EN v1.0 Address: 0x80146FA4
 * EN v1.0 Size: 628b
 * EN v1.1 Address: 0x80149040
 * EN v1.1 Size: 404b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80146fa4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  *(undefined *)(param_10 + 0x2ef) = 1;
  if (((*(uint *)(param_10 + 0x2dc) & 0x1000) != 0) && ((*(uint *)(param_10 + 0x2e0) & 0x1000) == 0)
     ) {
    *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) & 0xbfff;
    param_2 = (double)*(float *)(param_10 + 0x314);
    if ((double)lbl_803E31FC == param_2) {
      *(float *)(param_10 + 0x308) = lbl_803E3208;
    }
    else {
      *(float *)(param_10 + 0x308) = lbl_803E3200 / (float)((double)lbl_803E3204 * param_2);
    }
    *(undefined *)(param_10 + 0x323) = 1;
    FUN_800305f8((double)lbl_803E31FC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,(uint)*(byte *)(param_10 + 800),0x10,param_12,param_13,param_14,param_15,
                 param_16);
    if (*(int *)(param_9 + 0x54) != 0) {
      *(undefined *)(*(int *)(param_9 + 0x54) + 0x70) = 0;
    }
    *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 4;
    FUN_800067e8(param_9,1099,2);
    ObjHits_EnableObject(param_9);
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) == 0) {
    *(char *)(param_9 + 0x36) = (char)(int)(lbl_803E3210 * *(float *)(param_9 + 0x98));
    *(undefined4 *)(param_10 + 0x30c) = *(undefined4 *)(param_9 + 0x98);
  }
  else {
    *(float *)(param_10 + 0x308) = lbl_803E320C;
    *(undefined *)(param_10 + 0x323) = 0;
    FUN_800305f8((double)lbl_803E31FC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    if (*(int *)(param_9 + 0x54) != 0) {
      *(undefined *)(*(int *)(param_9 + 0x54) + 0x70) = 0;
    }
    *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) & 0xffffef7f;
    *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) & 0xfffffffb;
    *(float *)(param_10 + 0x30c) = lbl_803E31FC;
    *(undefined *)(param_9 + 0x36) = 0xff;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80147218
 * EN v1.0 Address: 0x80147218
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801491D4
 * EN v1.1 Size: 852b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80147218(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8014721c
 * EN v1.0 Address: 0x8014721C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80149528
 * EN v1.1 Size: 2796b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014721c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80147220
 * EN v1.0 Address: 0x80147220
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x8014A014
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80147220(double param_1,int param_2,uint param_3,undefined2 param_4)
{
  *(undefined *)(param_2 + 0x2f1) = 0;
  if ((param_3 & 2) != 0) {
    *(byte *)(param_2 + 0x2f1) = *(byte *)(param_2 + 0x2f1) | 0x20;
  }
  if ((param_3 & 1) != 0) {
    *(byte *)(param_2 + 0x2f1) = *(byte *)(param_2 + 0x2f1) | 0x40;
  }
  if ((param_3 & 4) != 0) {
    *(byte *)(param_2 + 0x2f1) = *(byte *)(param_2 + 0x2f1) | 1;
  }
  if ((param_3 & 8) != 0) {
    *(byte *)(param_2 + 0x2f1) = *(byte *)(param_2 + 0x2f1) | 2;
  }
  if ((param_3 & 0x10) != 0) {
    *(byte *)(param_2 + 0x2f1) = *(byte *)(param_2 + 0x2f1) | 4;
  }
  if ((double)lbl_803E3238 == param_1) {
    *(byte *)(param_2 + 0x2f1) = *(byte *)(param_2 + 0x2f1) | 8;
  }
  else if ((double)lbl_803E3228 == param_1) {
    *(byte *)(param_2 + 0x2f1) = *(byte *)(param_2 + 0x2f1) | 0x10;
  }
  if ((param_3 & 0x80) != 0) {
    *(byte *)(param_2 + 0x2f1) = *(byte *)(param_2 + 0x2f1) | 0x80;
  }
  if ((param_3 & 0x100) == 0) {
    if ((param_3 & 0x200) == 0) {
      if ((param_3 & 0x400) != 0) {
        *(undefined *)(param_2 + 0x2f5) = 3;
      }
    }
    else {
      *(undefined *)(param_2 + 0x2f5) = 2;
    }
  }
  else {
    *(undefined *)(param_2 + 0x2f5) = 1;
  }
  *(undefined2 *)(param_2 + 0x2ec) = param_4;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80147314
 * EN v1.0 Address: 0x80147314
 * EN v1.0 Size: 952b
 * EN v1.1 Address: 0x8014A14C
 * EN v1.1 Size: 876b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80147314(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,uint param_12,uint param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  undefined4 uVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined2 *unaff_r30;
  int iVar6;
  double dVar7;
  double in_f29;
  double in_f30;
  double dVar8;
  double in_f31;
  double dVar9;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined2 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  iVar4 = FUN_8028683c();
  iVar6 = *(int *)(iVar4 + 0x4c);
  local_58 = DAT_803e31e8;
  local_54 = DAT_803e31ec;
  local_68 = DAT_803e31f0;
  local_60 = DAT_803e31f4;
  local_5c = DAT_803e31f8;
  if ((param_11 == 0) || (uVar5 = FUN_80017ae8(), (uVar5 & 0xff) == 0)) goto LAB_8014a488;
  uVar5 = param_13 & 0xff;
  if (uVar5 == 1) {
    iVar3 = ((int)(param_11 & 0xf00) >> 8) + -1;
    if (3 < iVar3) {
      iVar3 = 3;
    }
    unaff_r30 = FUN_80017aa4(0x30,*(undefined2 *)((int)&local_58 + iVar3 * 2));
  }
  else if (uVar5 == 2) {
    iVar3 = ((int)(param_11 & 0xf000) >> 0xc) + -1;
    if (1 < iVar3) {
      iVar3 = 1;
    }
    unaff_r30 = FUN_80017aa4(0x30,*(undefined2 *)((int)&local_68 + iVar3 * 2));
  }
  else if (uVar5 == 3) {
    if (param_11 == 3) {
      unaff_r30 = FUN_80017aa4(0x30,0xb);
    }
    else if ((int)param_11 < 3) {
      if (param_11 != 1) goto LAB_8014a488;
      unaff_r30 = FUN_80017aa4(0x30,0x2cd);
    }
    else {
      if (param_11 == 5) {
        dVar9 = (double)*(float *)(iVar4 + 0x18);
        dVar8 = (double)*(float *)(iVar4 + 0x1c);
        dVar7 = (double)*(float *)(iVar4 + 0x20);
        iVar6 = *(int *)(iVar4 + 0x4c);
        if (iVar6 != 0) {
          *(undefined4 *)(iVar4 + 0x18) = *(undefined4 *)(iVar6 + 8);
          *(undefined4 *)(iVar4 + 0x1c) = *(undefined4 *)(iVar6 + 0xc);
          *(undefined4 *)(iVar4 + 0x20) = *(undefined4 *)(iVar6 + 0x10);
        }
        local_64 = lbl_803E323C;
        DAT_803de6d4 = ObjGroup_FindNearestObject(4,iVar4,(float *)&local_64);
        *(float *)(iVar4 + 0x18) = (float)dVar9;
        *(float *)(iVar4 + 0x1c) = (float)dVar8;
        *(float *)(iVar4 + 0x20) = (float)dVar7;
        if (DAT_803de6d4 != 0) {
          uVar1 = *(undefined4 *)(iVar4 + 0xc);
          *(undefined4 *)(DAT_803de6d4 + 0x18) = uVar1;
          *(undefined4 *)(DAT_803de6d4 + 0xc) = uVar1;
          fVar2 = lbl_803E3240 + *(float *)(iVar4 + 0x10);
          *(float *)(DAT_803de6d4 + 0x1c) = fVar2;
          *(float *)(DAT_803de6d4 + 0x10) = fVar2;
          uVar1 = *(undefined4 *)(iVar4 + 0x14);
          *(undefined4 *)(DAT_803de6d4 + 0x20) = uVar1;
          *(undefined4 *)(DAT_803de6d4 + 0x14) = uVar1;
        }
        goto LAB_8014a488;
      }
      if (4 < (int)param_11) goto LAB_8014a488;
      unaff_r30 = FUN_80017aa4(0x30,0x2cd);
    }
  }
  else if (uVar5 == 4) {
    if (3 < (int)param_11) {
      param_11 = 3;
    }
    if ((int)param_11 < 1) goto LAB_8014a488;
    unaff_r30 = FUN_80017aa4(0x30,*(undefined2 *)((int)&local_64 + param_11 * 2 + 2));
  }
  *(undefined *)(unaff_r30 + 0xd) = 0x14;
  unaff_r30[0x16] = 0xffff;
  unaff_r30[0xe] = 0xffff;
  unaff_r30[0x12] = 0xffff;
  *(undefined4 *)(unaff_r30 + 4) = *(undefined4 *)(iVar4 + 0xc);
  dVar7 = (double)lbl_803E322C;
  *(float *)(unaff_r30 + 6) = (float)(dVar7 + (double)*(float *)(iVar4 + 0x10));
  *(undefined4 *)(unaff_r30 + 8) = *(undefined4 *)(iVar4 + 0x14);
  if ((param_12 & 0xff) == 0) {
    unaff_r30[0x17] = 1;
  }
  else {
    unaff_r30[0x17] = 2;
  }
  *(undefined *)(unaff_r30 + 2) = *(undefined *)(iVar6 + 4);
  *(undefined *)(unaff_r30 + 3) = *(undefined *)(iVar6 + 6);
  *(undefined *)((int)unaff_r30 + 5) = *(undefined *)(iVar6 + 5);
  *(undefined *)((int)unaff_r30 + 7) = *(undefined *)(iVar6 + 7);
  DAT_803de6d4 = FUN_80017ae4(dVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                              unaff_r30,5,*(undefined *)(iVar4 + 0xac),0xffffffff,
                              *(uint **)(iVar4 + 0x30),param_14,param_15,param_16);
  if ((*(short *)(DAT_803de6d4 + 0x46) == 0x3cd) || (*(short *)(DAT_803de6d4 + 0x46) == 0xb)) {
    (**(code **)(**(int **)(DAT_803de6d4 + 0x68) + 0x2c))
              ((double)lbl_803E31FC,(double)lbl_803E3200,(double)lbl_803E31FC);
  }
LAB_8014a488:
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801476cc
 * EN v1.0 Address: 0x801476CC
 * EN v1.0 Size: 440b
 * EN v1.1 Address: 0x8014A4B8
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801476cc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  uint uVar1;
  undefined2 *puVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  
  iVar3 = *(int *)(param_9 + 0x4c);
  if ((*(short *)(param_10 + 0x2b4) != *(short *)(param_10 + 0x2b6)) &&
     (*(char *)(param_9 + 0x36) != '\0')) {
    iVar4 = *(int *)(param_9 + 200);
    if (iVar4 != 0) {
      uVar5 = ObjLink_DetachChild(param_9,iVar4);
      param_1 = FUN_80017ac8(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4);
    }
    uVar1 = FUN_80017ae8();
    if ((uVar1 & 0xff) == 0) {
      *(undefined2 *)(param_10 + 0x2b4) = 0;
    }
    else if (0 < *(short *)(param_10 + 0x2b6)) {
      puVar2 = FUN_80017aa4(0x20,*(short *)(param_10 + 0x2b6));
      *(byte *)((int)puVar2 + 5) = *(byte *)((int)puVar2 + 5) | *(byte *)(iVar3 + 5) & 0x18;
      iVar3 = FUN_80017ae4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,4,
                           *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),
                           in_r8,in_r9,in_r10);
      ObjLink_AttachChild(param_9,iVar3,0);
      *(undefined2 *)(param_10 + 0x2b4) = *(undefined2 *)(param_10 + 0x2b6);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80147884
 * EN v1.0 Address: 0x80147884
 * EN v1.0 Size: 492b
 * EN v1.1 Address: 0x8014A5B0
 * EN v1.1 Size: 436b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80147884(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,float *param_11,float *param_12)
{
  short sVar1;
  bool bVar2;
  int *piVar3;
  char cVar4;
  int iVar5;
  double dVar6;
  undefined8 uVar7;
  char local_a0 [4];
  short asStack_9c [4];
  short asStack_94 [4];
  float afStack_8c [3];
  float local_80;
  float local_7c;
  float local_78;
  int aiStack_74 [29];
  
  uVar7 = FUN_8028683c();
  piVar3 = (int *)((ulonglong)uVar7 >> 0x20);
  iVar5 = (int)uVar7;
  local_a0[0] = '\0';
  cVar4 = '\0';
  if (*(int *)(iVar5 + 0x29c) != 0) {
    local_80 = *param_11;
    local_7c = param_11[1];
    local_78 = param_11[2];
    bVar2 = true;
    sVar1 = *(short *)((int)piVar3 + 0x46);
    if (((((sVar1 != 0x613) && (sVar1 != 0x642)) && (sVar1 != 0x3fe)) &&
        ((sVar1 != 0x7c6 && (sVar1 != 0x7c8)))) && ((sVar1 != 0x251 && (sVar1 != 0x851)))) {
      local_7c = local_7c + lbl_803E3234;
      bVar2 = false;
    }
    FUN_80006a68(&local_80,asStack_9c);
    local_80 = *param_12;
    local_7c = lbl_803E3234 + param_12[1];
    local_78 = param_12[2];
    FUN_80006a68(&local_80,asStack_94);
    FUN_80247eb8(param_11,&local_80,afStack_8c);
    dVar6 = FUN_80247f54(afStack_8c);
    if (dVar6 < (double)lbl_803E3244) {
      if (piVar3[0xc] == 0) {
        cVar4 = FUN_80006a64(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             asStack_94,asStack_9c,(undefined4 *)0x0,local_a0,0);
      }
      if ((!bVar2) && (local_a0[0] == '\x01')) {
        cVar4 = '\x01';
      }
    }
  }
  if ((cVar4 != '\0') && ((*(uint *)(iVar5 + 0x2e4) & 8) != 0)) {
    FUN_800620e8(param_11,&local_80,(float *)0x0,aiStack_74,piVar3,(uint)*(byte *)(iVar5 + 0x261),
                 0xffffffff,0,0);
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80147a70
 * EN v1.0 Address: 0x80147A70
 * EN v1.0 Size: 700b
 * EN v1.1 Address: 0x8014A764
 * EN v1.1 Size: 760b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80147a70(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  short sVar1;
  short sVar2;
  int *piVar3;
  char cVar5;
  int iVar4;
  int iVar6;
  ushort uVar7;
  double extraout_f1;
  double dVar8;
  double in_f26;
  double in_f27;
  double in_f28;
  double in_f29;
  double in_f30;
  double dVar9;
  double in_f31;
  double dVar10;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar11;
  char local_110 [4];
  short asStack_10c [4];
  short asStack_104 [4];
  float afStack_fc [3];
  uint local_f0 [4];
  float local_e0;
  float local_dc;
  float local_d8;
  int aiStack_d4 [21];
  undefined4 local_80;
  uint uStack_7c;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  uVar11 = FUN_8028683c();
  piVar3 = (int *)((ulonglong)uVar11 >> 0x20);
  iVar6 = (int)uVar11;
  local_f0[0] = DAT_802c2970;
  local_f0[1] = DAT_802c2974;
  local_f0[2] = DAT_802c2978;
  local_f0[3] = DAT_802c297c;
  local_e0 = (float)piVar3[3];
  local_dc = lbl_803E3234 + (float)piVar3[4];
  local_d8 = (float)piVar3[5];
  dVar10 = extraout_f1;
  FUN_80006a68(&local_e0,asStack_10c);
  if ((short *)piVar3[0xc] == (short *)0x0) {
    sVar2 = *(short *)piVar3;
  }
  else {
    sVar2 = *(short *)piVar3 + *(short *)piVar3[0xc];
  }
  dVar9 = (double)lbl_803E3244;
  for (uVar7 = 0; uVar7 < 4; uVar7 = uVar7 + 1) {
    uStack_7c = (int)sVar2 + (uint)uVar7 * 0x4000 ^ 0x80000000;
    local_80 = 0x43300000;
    dVar8 = (double)FUN_80293f90();
    local_e0 = -(float)(dVar10 * dVar8 - (double)(float)piVar3[6]);
    local_dc = (float)piVar3[7];
    dVar8 = (double)FUN_80294964();
    local_d8 = -(float)(dVar10 * dVar8 - (double)(float)piVar3[8]);
    sVar1 = *(short *)((int)piVar3 + 0x46);
    if (((((sVar1 != 0x613) && (sVar1 != 0x642)) && (sVar1 != 0x3fe)) &&
        ((sVar1 != 0x7c6 && (sVar1 != 0x7c8)))) && ((sVar1 != 0x251 && (sVar1 != 0x851)))) {
      local_dc = local_dc + lbl_803E3234;
    }
    FUN_80006a68(&local_e0,asStack_104);
    FUN_80247eb8((float *)(piVar3 + 6),&local_e0,afStack_fc);
    dVar8 = FUN_80247f54(afStack_fc);
    if (dVar9 <= dVar8) {
      cVar5 = '\0';
    }
    else if (piVar3[0xc] == 0) {
      cVar5 = FUN_80006a64(dVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,asStack_104
                           ,asStack_10c,(undefined4 *)0x0,local_110,0);
      if (local_110[0] == '\x01') {
        cVar5 = '\x01';
      }
    }
    else {
      cVar5 = '\x01';
    }
    if ((cVar5 != '\0') && ((*(uint *)(iVar6 + 0x2e4) & 8) != 0)) {
      iVar4 = FUN_800620e8(piVar3 + 6,&local_e0,(float *)0x0,aiStack_d4,piVar3,
                           (uint)*(byte *)(iVar6 + 0x261),0xffffffff,0,0);
      if (iVar4 != 0) {
        cVar5 = '\0';
      }
    }
    if (cVar5 == '\0') {
      *(uint *)(iVar6 + 0x2dc) = *(uint *)(iVar6 + 0x2dc) & ~local_f0[uVar7];
    }
    else {
      *(uint *)(iVar6 + 0x2dc) = *(uint *)(iVar6 + 0x2dc) | local_f0[uVar7];
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80147d2c
 * EN v1.0 Address: 0x80147D2C
 * EN v1.0 Size: 588b
 * EN v1.1 Address: 0x8014AA5C
 * EN v1.1 Size: 624b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80147d2c(int param_1,int param_2)
{
  float local_28;
  float local_24;
  float afStack_20 [6];
  
  *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) & 0xf7efffff;
  if ((*(uint *)(param_2 + 0x2e4) & 0x28000002) == 0) {
    if ((*(uint *)(param_2 + 0x2e4) & 0xc) == 0) {
      *(undefined *)(param_2 + 0x25f) = 0;
    }
    else {
      *(undefined *)(param_2 + 0x25f) = 1;
    }
  }
  else {
    FUN_8014a9f0(param_1,param_2,&local_24,&local_28);
    if ((*(uint *)(param_2 + 0x2e4) & 0x8000000) == 0) {
      if ((*(uint *)(param_2 + 0x2e4) & 0x20000000) == 0) {
        local_24 = local_24 - *(float *)(param_1 + 0x10);
        if ((lbl_803E3250 < local_24) && (local_24 < lbl_803E3234)) {
          *(float *)(param_1 + 0x28) = local_24 * lbl_803DC078;
          *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x100000;
        }
      }
      else {
        local_24 = local_24 - *(float *)(param_1 + 0x10);
        if ((lbl_803E3250 < local_24) && (local_24 < lbl_803E3234)) {
          *(float *)(param_1 + 0x28) = (lbl_803E3254 + local_24) * lbl_803DC078;
          *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x8000000;
        }
      }
    }
    else {
      *(float *)(param_1 + 0x28) = (local_28 - *(float *)(param_1 + 0x10)) * lbl_803DC078;
    }
    if ((*(uint *)(param_2 + 0x2e4) & 8) == 0) {
      *(undefined *)(param_2 + 0x25f) = 0;
    }
  }
  (**(code **)(*DAT_803dd728 + 0x10))((double)lbl_803DC074,param_1,param_2 + 4);
  if ((*(uint *)(param_2 + 0x2e4) & 4) != 0) {
    (**(code **)(*DAT_803dd728 + 0x14))(param_1,param_2 + 4);
  }
  (**(code **)(*DAT_803dd728 + 0x18))((double)lbl_803DC074,param_1,param_2 + 4);
  if (((*(char *)(param_2 + 0x25f) != '\0') && ((*(uint *)(param_2 + 0x2e4) & 0x28000002) == 0)) &&
     ((*(byte *)(param_2 + 0x264) & 0x10) != 0)) {
    *(float *)(param_1 + 0x28) = lbl_803E31FC;
    *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x100000;
  }
  if ((*(uint *)(param_2 + 0x2e4) & 0x200000) != 0) {
    ObjPath_GetPointWorldPositionArray(param_1,2,2,afStack_20);
    FUN_8006dca8((double)*(float *)(param_2 + 0x310),(double)lbl_803E3200,param_1,
                 (uint)*(ushort *)(param_2 + 0x2f8),7,(int)afStack_20,param_2 + 4);
  }
  return;
}

/* 8b "li r3, N; blr" returners. */
int Tricky_getExtraSize(void) { return 0x83c; }

/* misc 16b 4-insn patterns. */
#pragma scheduling off
#pragma peephole off
u8 Tricky_func0E(int *obj) { return *((u8*)((int**)obj)[0xb8/4][0x0/4] + 0x1); }
u8 Tricky_render2(int *obj) { return *((u8*)((int**)obj)[0xb8/4][0x0/4] + 0x0); }
#pragma peephole reset
#pragma scheduling reset

/* fn_80145AD0: 24b - signed-byte load and store, return 1. */
#pragma peephole off
#pragma scheduling off
int fn_80145AD0(int *obj, int *out) {
    *out = *((s8*)obj[0xb8/4] + 0xd);
    return 1;
}
#pragma scheduling reset
#pragma peephole reset

extern u32 GameBit_Get(int bit);
extern u8 fn_800DBCFC(void *pos,int param_2);
extern int fn_800DBECC(void *pos);
extern void fn_800DB224(int pathId,u8 *out);
extern int Obj_AllocObjectSetup();
extern int Obj_SetupObject(int setup,int param_2,int param_3,int param_4,int param_5);
extern int fn_800DB0E0(void *pos,int param_2,int param_3);
extern int randomGetRange(int lo,int hi);
extern f32 lbl_803E23DC;

/* fn_801451D8: 300b - seed Tricky's path state and ensure the helper object exists. */
#pragma peephole off
#pragma scheduling off
int fn_801451D8(int obj,int state) {
    u8 pathBytes[16];
    u32 pathByte = fn_800DBCFC((void *)(obj + 0x18), 0);

    pathByte = (u8)pathByte;
    pathBytes[0] = pathByte;
    if (pathByte == 0) {
        int pathId = fn_800DBECC((void *)(obj + 0x18));
        if (pathId != 0) {
            fn_800DB224(pathId & 0xffff, pathBytes);
        }
    }
    if (pathBytes[0] != 0) {
        f32 resetTimer;

        *(u16 *)(state + 0x532) = pathBytes[0];
        *(u8 *)(state + 8) = 1;
        *(u8 *)(state + 10) = 0;
        resetTimer = lbl_803E23DC;
        *(f32 *)(state + 0x71c) = resetTimer;
        *(f32 *)(state + 0x720) = resetTimer;
        *(s32 *)(state + 0x54) = *(s32 *)(state + 0x54) & -17;
        *(s32 *)(state + 0x54) = *(s32 *)(state + 0x54) & -65537;
        *(s32 *)(state + 0x54) = *(s32 *)(state + 0x54) & -131073;
        *(s32 *)(state + 0x54) = *(s32 *)(state + 0x54) & -262145;
        *(s8 *)(state + 0xd) = -1;
    }
    if (lbl_803DDA48 == 0) {
        int setup = Obj_AllocObjectSetup(0x18, 0x25);
        lbl_803DDA48 = Obj_SetupObject(setup, 4, -1, -1, *(int *)(obj + 0x30));
    }
    {
        int ret = 1;
        *(u8 *)(state + 0x58) = (*(u8 *)(state + 0x58) & 0x7f) | (ret << 7);
        return ret;
    }
}
#pragma scheduling reset
#pragma peephole reset

/* fn_80145794: 72b - if GameBit_Get(0x4e4), OR 0x10000 into obj->_b8->_54. */
void fn_80145794(int *obj) {
    int *p = (int*)obj[0xb8/4];
    if (GameBit_Get(0x4e4)) {
        p[0x54/4] |= 0x10000;
    }
}

/* fn_801457DC: 40b - lbz/cmplwi(8/0xe) selector returning 1 or 0. */
#pragma peephole off
#pragma scheduling off
int fn_801457DC(int *obj) {
    u8 v = *((u8*)obj[0xb8/4] + 8);
    if (v == 8 || v == 0xe) return 1;
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

/* fn_80145804: 36b - cmpwi(5) selector returning 1 or 0. */
#pragma peephole off
#pragma scheduling off
#pragma optimize_for_size off
int fn_80145804(int *obj) {
    u8 v;
    int r;
    v = *((u8*)obj[0xb8/4] + 8);
    switch (v) {
    case 5:
        r = 1;
        break;
    default:
        r = 0;
        break;
    }
    return r;
}
#pragma optimize_for_size reset
#pragma scheduling reset
#pragma peephole reset

/* fn_80145828: 148b - enter or queue Tricky's target-driven state 10 command. */
#pragma scheduling off
int fn_80145828(int *obj,int targetObj) {
    int *state = (int*)obj[0xb8/4];
    u32 objBlocked = *(u16*)((u8*)obj + 0xb0) & 0x1000;

    if (objBlocked != 0) {
        return 0;
    }
    if ((state[0x54/4] & 0x10) == 0) {
        void *currentTarget = (void *)state[0x28/4];
        void *nextTarget = (void *)(targetObj + 0x18);

        state[0x24/4] = targetObj;
        if (currentTarget != nextTarget) {
            s32 clearTargetAnim = -1025;

            state[0x28/4] = (int)nextTarget;
            state[0x54/4] = state[0x54/4] & clearTargetAnim;
            *(s16*)((u8*)state + 0xd2) = 0;
        }
        *((u8*)state + 10) = 0;
        *((u8*)state + 8) = 10;
    } else {
        *((u8*)state + 0x7d0) = 1;
        state[0x7d4/4] = targetObj;
        state[0x54/4] |= 0x10000;
    }
    return 1;
}
#pragma scheduling reset

/* fn_801458BC: 260b - start or refresh Tricky's targeted command state. */
#pragma scheduling off
void fn_801458BC(int *obj,int commandEnabled,int targetObj) {
    int *state = (int*)obj[0xb8/4];

    if (commandEnabled != 0) {
        if (*((u8*)state + 8) == 5) {
            if (*((u8*)state + 10) != 0) {
                state[0x24/4] = targetObj;
            }
        } else {
            u32 busy = state[0x54/4] & 0x10;
            void *nextTarget;

            if (busy != 0) {
                return;
            }
            state[0x700/4] = fn_800DB0E0((void *)(targetObj + 0x18), -1, 3);
            *(f32*)((u8*)state + 0x710) = (f32)randomGetRange(0x168, 0x28);
            *((u8*)state + 8) = 5;
            state[0x24/4] = targetObj;
            nextTarget = (void *)(state[0x700/4] + 8);
            if ((void *)state[0x28/4] != nextTarget) {
                s32 clearTargetAnim = -1025;

                state[0x28/4] = (int)nextTarget;
                state[0x54/4] = state[0x54/4] & clearTargetAnim;
                *(s16*)((u8*)state + 0xd2) = 0;
            }
            *((u8*)state + 10) = 0;
        }
    } else {
        state[0x54/4] |= 0x10000;
    }
}
#pragma scheduling reset

/* Tricky_getAvailableCommands: 124b - GameBit_Get cascade returning command flags. */
#pragma peephole off
#pragma scheduling off
int Tricky_getAvailableCommands(void) {
    int r = 0;
    if (GameBit_Get(0x4e4) != 0) {
        r = 0xa;
        if (GameBit_Get(0xdd) != 0) r |= 0x1;
        if (GameBit_Get(0x25) != 0) r |= 0x20;
        if (GameBit_Get(0x245) != 0) r |= 0x10;
    }
    return r;
}
#pragma scheduling reset
#pragma peephole reset

/* trickyReportError: 80b - varargs OSReport-style stub. */
void trickyReportError(const char *fmt, ...) { }

/* trickyDebugPrint: 80b - varargs OSReport-style stub. */
void trickyDebugPrint(const char *fmt, ...) { }

extern f32 lbl_803E25A4;
extern f32 lbl_803E2594;
extern f32 lbl_803E2538;
extern f32 lbl_803E2500;
extern f32 lbl_803E2418;
extern f32 lbl_803E23DC;

extern f32 getXZDistance(f32 *a, f32 *b);
/* fn_80144E40: 272b - find nearest object within distance threshold. */
#pragma scheduling off
int fn_80144E40(int *obj, int *p) {
    int *objs;
    int count[1];
    int result;
    f32 d;
    f32 bestD;
    int i;

    result = 0;
    objs = ObjGroup_GetObjects(0x4b, count);
    d = getXZDistance((f32*)((char*)(int*)p[0x4/4] + 0x18), (f32*)((char*)obj + 0x18));
    if ((d >= lbl_803E2538) || (*(f32*)((char*)p + 0x71c) > lbl_803E23DC)) {
        if (fn_8005A10C((f32*)((char*)obj + 0xc), lbl_803E2500) == 0) {
            bestD = lbl_803E2418;
            for (i = 0; i < count[0]; i++) {
                f32 cd = getXZDistance((f32*)((char*)(int*)p[0x4/4] + 0x18), (f32*)((char*)*objs + 0x18));
                if (cd < d && cd < bestD) {
                    bestD = cd;
                    result = *objs;
                }
                objs++;
            }
        }
    }
    return result;
}
#pragma scheduling reset

/* fn_80144F50: 648b - update Tricky's water/out-of-water probe and animation. */
#pragma scheduling off
void fn_80144F50(int obj, int state) {
    int sfxState;
    int isInWater;
    int sfxDisabled;
    u32 transitionFlag;

    if (fn_8014460C(obj, state) == 0) {
        *(f32*)(state + 0x72c) =
            *(f32*)(obj + 0x18) - fn_80293E80((lbl_803E2454 * (f32)*(s16*)obj) / lbl_803E2458);
        *(f32*)(state + 0x730) = *(f32*)(obj + 0x1c);
        *(f32*)(state + 0x734) =
            *(f32*)(obj + 0x20) - sin((lbl_803E2454 * (f32)*(s16*)obj) / lbl_803E2458);

        if (trickyFn_8013b368(obj, lbl_803E247C, state) != 1) {
            *(f32*)(state + 0x740) -= timeDelta;
            if (*(f32*)(state + 0x740) <= lbl_803E23DC) {
                *(f32*)(state + 0x740) = (f32)randomGetRange(0x1f4, 0x2ee);
                sfxState = *(int*)(obj + 0xb8);
                sfxDisabled = (*(u8*)(sfxState + 0x58) >> 6) & 1;
                if ((sfxDisabled == 0) &&
                    ((*(s16*)(obj + 0xa0) >= 0x30) || (*(s16*)(obj + 0xa0) < 0x29)) &&
                    (Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0)) {
                    objAudioFn_800393f8(obj, (void*)(sfxState + 0x3a8), 0x360, 0x500, -1, 0);
                }
            }

            if (lbl_803E23DC == *(f32*)(state + 0x2ac)) {
                isInWater = 0;
            } else if (lbl_803E2410 == *(f32*)(state + 0x2b0)) {
                isInWater = 1;
            } else if ((*(f32*)(state + 0x2b4) - *(f32*)(state + 0x2b0)) > lbl_803E2414) {
                isInWater = 1;
            } else {
                isInWater = 0;
            }

            if (isInWater) {
                objAnimFn_8013a3f0(obj, 8, lbl_803E243C, 0);
                *(f32*)(state + 0x79c) = lbl_803E2440;
                *(f32*)(state + 0x838) = lbl_803E23DC;
                trickyDebugPrint(sInWaterMessage);
            } else {
                if (*(s16*)(obj + 0xa0) != 0x31) {
                    if ((*(s16*)(obj + 0xa0) < 0x31) && (*(s16*)(obj + 0xa0) == 0xd)) {
                        transitionFlag = *(u32*)(state + 0x54) & 0x08000000;
                        if (transitionFlag != 0) {
                            objAnimFn_8013a3f0(obj, 0x31, lbl_803E243C, 0);
                        }
                    } else {
                        objAnimFn_8013a3f0(obj, 0xd, lbl_803E2444, 0);
                    }
                }
                trickyDebugPrint(lbl_8031D478);
            }
        }
    }
}
#pragma scheduling reset


/* fn_80149BB4: 312b - flag bits to byte field. */
#pragma peephole off
#pragma scheduling off
void fn_80149BB4(int *obj, u32 flags, s16 val, f32 f) {
    *((u8*)obj + 0x2f1) = 0;
    if ((flags & 0x2) != 0) {
        *((u8*)obj + 0x2f1) = (u8)(*((u8*)obj + 0x2f1) | 0x20);
    }
    if ((flags & 0x1) != 0) {
        *((u8*)obj + 0x2f1) = (u8)(*((u8*)obj + 0x2f1) | 0x40);
    }
    if ((flags & 0x4) != 0) {
        *((u8*)obj + 0x2f1) = (u8)(*((u8*)obj + 0x2f1) | 0x1);
    }
    if ((flags & 0x8) != 0) {
        *((u8*)obj + 0x2f1) = (u8)(*((u8*)obj + 0x2f1) | 0x2);
    }
    if ((flags & 0x10) != 0) {
        *((u8*)obj + 0x2f1) = (u8)(*((u8*)obj + 0x2f1) | 0x4);
    }
    if (lbl_803E25A4 == f) {
        *((u8*)obj + 0x2f1) = (u8)(*((u8*)obj + 0x2f1) | 0x8);
    } else if (lbl_803E2594 == f) {
        *((u8*)obj + 0x2f1) = (u8)(*((u8*)obj + 0x2f1) | 0x10);
    }
    if ((flags & 0x80) != 0) {
        *((u8*)obj + 0x2f1) = (u8)(*((u8*)obj + 0x2f1) | 0x80);
    }
    if ((flags & 0x100) != 0) {
        *((u8*)obj + 0x2f5) = 1;
    } else if ((flags & 0x200) != 0) {
        *((u8*)obj + 0x2f5) = 2;
    } else if ((flags & 0x400) != 0) {
        *((u8*)obj + 0x2f5) = 3;
    }
    *(s16*)((char*)obj + 0x2ec) = val;
}
#pragma scheduling reset
#pragma peephole reset
