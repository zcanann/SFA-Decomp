#include "ghidra_import.h"
#include "main/dll/cannon.h"

#pragma peephole off

extern bool FUN_800067f0();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068cc();
extern undefined4 FUN_800068d0();
extern double FUN_80017708();
extern int FUN_80017730();
extern uint FUN_80017760();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern void* ObjGroup_GetObjects();
extern undefined4 FUN_80039468();
extern int FUN_800da5f0();
extern int FUN_800db47c();
extern int fn_800DBCFC(float *pos, void *flag);
extern f32 getXZDistance(float *a, float *b);
extern undefined4 FUN_80139910();
extern int FUN_80139a48();
extern undefined4 FUN_80139a4c();
extern int FUN_8013b368();
extern undefined4 FUN_8013d8f0();
extern undefined4 FUN_80146fa0();
extern undefined4 FUN_801778d0();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

int fn_8014089C(int p);

extern undefined4* DAT_803dd71c;
extern f32 lbl_803DC074;
extern f32 lbl_803E306C;
extern f32 lbl_803E3074;
extern f32 lbl_803E307C;
extern f32 lbl_803E3084;
extern f32 lbl_803E30A0;
extern f32 lbl_803E30A4;
extern f32 lbl_803E30A8;
extern f32 lbl_803E30B0;
extern f32 lbl_803E30CC;
extern f32 lbl_803E30D0;
extern f32 lbl_803E30D4;
extern f32 lbl_803E310C;
extern f32 lbl_803E3118;
extern f32 lbl_803E313C;
extern f32 lbl_803E3154;
extern f32 lbl_803E3160;
extern f32 lbl_803E3168;
extern f32 lbl_803E3188;
extern f32 lbl_803E3194;

/*
 * --INFO--
 *
 * Function: FUN_8013ffb8
 * EN v1.0 Address: 0x8013FFB8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80140340
 * EN v1.1 Size: 2276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013ffb8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 byte param_13,uint param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8013ffbc
 * EN v1.0 Address: 0x8013FFBC
 * EN v1.0 Size: 320b
 * EN v1.1 Address: 0x80140C24
 * EN v1.1 Size: 320b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8013ffbc(int param_1)
{
  int *piVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  short sVar5;
  double dVar6;
  double in_f30;
  int local_28 [2];
  
  iVar4 = 0;
  piVar1 = ObjGroup_GetObjects(3,local_28);
  for (sVar5 = 0; sVar5 < local_28[0]; sVar5 = sVar5 + 1) {
    dVar6 = FUN_80017708((float *)(*piVar1 + 0x18),(float *)(param_1 + 0x71c));
    if (iVar4 == 0) {
      iVar2 = FUN_800db47c((float *)(*piVar1 + 0x18),(undefined *)0x0);
      if (*(int *)(param_1 + 0x730) == iVar2) {
        iVar4 = *piVar1;
        in_f30 = dVar6;
      }
    }
    else if ((dVar6 < in_f30) &&
            (iVar2 = FUN_800db47c((float *)(*piVar1 + 0x18),(undefined *)0x0),
            *(int *)(param_1 + 0x730) == iVar2)) {
      iVar4 = *piVar1;
      in_f30 = dVar6;
    }
    piVar1 = piVar1 + 1;
  }
  if (iVar4 == 0) {
    uVar3 = 0;
  }
  else {
    *(int *)(param_1 + 0x72c) = iVar4;
    if (*(int *)(param_1 + 0x28) != iVar4 + 0x18) {
      *(int *)(param_1 + 0x28) = iVar4 + 0x18;
      *(uint *)(param_1 + 0x54) = *(uint *)(param_1 + 0x54) & 0xfffffbff;
      *(undefined2 *)(param_1 + 0xd2) = 0;
    }
    *(undefined *)(param_1 + 10) = 4;
    uVar3 = 1;
  }
  return uVar3;
}

/*
 * --INFO--
 *
 * Function: FUN_801400fc
 * EN v1.0 Address: 0x801400FC
 * EN v1.0 Size: 2600b
 * EN v1.1 Address: 0x80140D64
 * EN v1.1 Size: 2228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801400fc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 byte param_13,uint param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  short sVar2;
  ushort uVar3;
  ushort *puVar4;
  uint uVar5;
  undefined2 *puVar6;
  undefined4 uVar7;
  bool bVar9;
  int iVar8;
  undefined4 *puVar10;
  int iVar11;
  undefined4 *puVar12;
  double dVar13;
  double extraout_f1;
  double extraout_f1_00;
  undefined8 uVar14;
  
  uVar14 = FUN_8028683c();
  puVar4 = (ushort *)((ulonglong)uVar14 >> 0x20);
  puVar10 = (undefined4 *)uVar14;
  switch(*(undefined *)((int)puVar10 + 10)) {
  case 0:
    FUN_80146fa0();
    iVar11 = 4;
    iVar8 = FUN_800da5f0((float *)(puVar10[9] + 0x18),0xffffffff,4);
    puVar10[0x1c7] = iVar8;
    iVar8 = puVar10[0x1c7];
    if (*(char *)(iVar8 + 3) == '\0') {
      uVar7 = (**(code **)(*DAT_803dd71c + 0x1c))(*(undefined4 *)(iVar8 + 0x1c));
      puVar10[0x1c8] = uVar7;
      if (puVar10[10] != puVar10[0x1c8] + 8) {
        puVar10[10] = puVar10[0x1c8] + 8;
        puVar10[0x15] = puVar10[0x15] & 0xfffffbff;
        *(undefined2 *)((int)puVar10 + 0xd2) = 0;
      }
      *(undefined *)((int)puVar10 + 10) = 3;
    }
    else {
      if (puVar10[10] != iVar8 + 8) {
        puVar10[10] = iVar8 + 8;
        puVar10[0x15] = puVar10[0x15] & 0xfffffbff;
        *(undefined2 *)((int)puVar10 + 0xd2) = 0;
      }
      *(undefined *)((int)puVar10 + 10) = 1;
    }
    FUN_8013b368((double)lbl_803E3118,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 puVar4,puVar10,iVar11,param_12,param_13,param_14,param_15,param_16);
    break;
  case 1:
    FUN_80146fa0();
    iVar8 = FUN_8013b368((double)lbl_803E3118,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,puVar4,puVar10,param_11,param_12,param_13,param_14,param_15,
                         param_16);
    if (iVar8 == 0) {
      puVar10[0x15] = puVar10[0x15] | 0x10;
      *(undefined *)((int)puVar10 + 10) = 2;
    }
    else if (iVar8 == 2) {
      *(undefined *)(puVar10 + 2) = 1;
      *(undefined *)((int)puVar10 + 10) = 0;
      fVar1 = lbl_803E306C;
      puVar10[0x1c7] = lbl_803E306C;
      puVar10[0x1c8] = fVar1;
      puVar10[0x15] = puVar10[0x15] & 0xffffffef;
      puVar10[0x15] = puVar10[0x15] & 0xfffeffff;
      puVar10[0x15] = puVar10[0x15] & 0xfffdffff;
      puVar10[0x15] = puVar10[0x15] & 0xfffbffff;
      *(undefined *)((int)puVar10 + 0xd) = 0xff;
    }
    break;
  case 2:
    FUN_80146fa0();
    FUN_8013d8f0((double)lbl_803E30A8,(short *)puVar4,(int)puVar10,(float *)(puVar10[9] + 0x18),
                 '\x01');
    iVar8 = FUN_80139a48();
    if (iVar8 == 0) {
      FUN_80139a4c((double)lbl_803E3074,(int)puVar4,0x1a,0x4000000);
      *(undefined *)((int)puVar10 + 10) = 6;
      *(char *)*puVar10 = *(char *)*puVar10 + -4;
    }
    break;
  case 3:
    FUN_80146fa0();
    FUN_8013b368((double)lbl_803E3118,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 puVar4,puVar10,param_11,param_12,param_13,param_14,param_15,param_16);
    uVar5 = FUN_800db47c((float *)(puVar4 + 0xc),(undefined *)0x0);
    if (*(byte *)(puVar10[0x1c8] + 3) == uVar5) {
      *(undefined *)((int)puVar10 + 9) = 1;
      *(undefined *)((int)puVar10 + 10) = 4;
    }
    break;
  case 4:
    FUN_80146fa0();
    FUN_8013d8f0((double)lbl_803E3118,(short *)puVar4,(int)puVar10,(float *)(puVar10[0x1c7] + 8),
                 '\x01');
    FUN_80139a48();
    iVar8 = FUN_800db47c((float *)(puVar4 + 0xc),(undefined *)0x0);
    if (iVar8 == 0) {
      puVar10[0x15] = puVar10[0x15] | 0x10;
      *(undefined *)((int)puVar10 + 10) = 5;
    }
    break;
  case 5:
    FUN_80146fa0();
    FUN_8013d8f0((double)lbl_803E3118,(short *)puVar4,(int)puVar10,(float *)(puVar10[0x1c7] + 8),
                 '\x01');
    iVar8 = FUN_80139a48();
    if (iVar8 != 0) break;
    FUN_80139a4c((double)lbl_803E3074,(int)puVar4,0x1a,0x4000000);
    *(undefined *)((int)puVar10 + 10) = 7;
    *(char *)*puVar10 = *(char *)*puVar10 + -4;
  case 7:
    FUN_80146fa0();
    uVar3 = (ushort)((int)*(char *)(puVar10[0x1c7] + 0x2c) << 8);
    sVar2 = uVar3 - *puVar4;
    if (0x8000 < sVar2) {
      sVar2 = sVar2 + 1;
    }
    if (sVar2 < -0x8000) {
      sVar2 = sVar2 + -1;
    }
    iVar8 = (int)sVar2;
    if (iVar8 < 0) {
      iVar8 = -iVar8;
    }
    if (0x3fff < iVar8) {
      uVar3 = uVar3 + 0x8000;
    }
    FUN_80139910(puVar4,uVar3);
    dVar13 = (double)*(float *)(puVar4 + 0x4c);
    if (dVar13 <= (double)lbl_803E313C) {
LAB_801411bc:
      bVar9 = true;
    }
    else {
      if ((puVar10[0x15] & 0x800) == 0) {
        uVar5 = FUN_80017ae8();
        if ((uVar5 & 0xff) != 0) {
          puVar10[0x15] = puVar10[0x15] | 0x800;
          iVar8 = 0;
          puVar12 = puVar10;
          do {
            puVar6 = FUN_80017aa4(0x24,0x4f0);
            *(undefined *)(puVar6 + 2) = 2;
            *(undefined *)((int)puVar6 + 5) = 1;
            puVar6[0xd] = (short)iVar8;
            uVar7 = FUN_80017ae4(dVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 puVar6,5,*(undefined *)(puVar4 + 0x56),0xffffffff,
                                 *(uint **)(puVar4 + 0x18),param_14,param_15,param_16);
            puVar12[0x1c0] = uVar7;
            puVar12 = puVar12 + 1;
            iVar8 = iVar8 + 1;
            dVar13 = extraout_f1;
          } while (iVar8 < 7);
          FUN_80006824((uint)puVar4,0x3db);
          FUN_800068d0((uint)puVar4,0x3dc);
        }
        goto LAB_801411bc;
      }
      if ((((code *)puVar10[0x1c9] != (code *)0x0) &&
          (iVar8 = (*(code *)puVar10[0x1c9])(puVar10[9],1), iVar8 == 0)) ||
         (*(float *)(puVar4 + 0x4c) <= lbl_803E3194)) goto LAB_801411bc;
      puVar10[0x15] = puVar10[0x15] & 0xfffff7ff;
      puVar10[0x15] = puVar10[0x15] | 0x1000;
      iVar8 = 0;
      puVar12 = puVar10;
      do {
        FUN_801778d0(puVar12[0x1c0]);
        puVar12 = puVar12 + 1;
        iVar8 = iVar8 + 1;
      } while (iVar8 < 7);
      FUN_800068cc();
      iVar8 = *(int *)(puVar4 + 0x5c);
      if (((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < (short)puVar4[0x50] || ((short)puVar4[0x50] < 0x29)) &&
          (bVar9 = FUN_800067f0((int)puVar4,0x10), !bVar9)))) {
        FUN_80039468(puVar4,iVar8 + 0x3a8,0x29d,0,0xffffffff,0);
      }
      bVar9 = false;
    }
    if (!bVar9) {
      *(undefined *)((int)puVar10 + 10) = 8;
      puVar10[0x1ca] = lbl_803E3188;
    }
    break;
  case 6:
    FUN_80146fa0();
    dVar13 = (double)*(float *)(puVar4 + 0x4c);
    if (dVar13 <= (double)lbl_803E313C) {
LAB_8014149c:
      bVar9 = true;
    }
    else {
      if ((puVar10[0x15] & 0x800) == 0) {
        uVar5 = FUN_80017ae8();
        if ((uVar5 & 0xff) != 0) {
          puVar10[0x15] = puVar10[0x15] | 0x800;
          iVar8 = 0;
          puVar12 = puVar10;
          do {
            puVar6 = FUN_80017aa4(0x24,0x4f0);
            *(undefined *)(puVar6 + 2) = 2;
            *(undefined *)((int)puVar6 + 5) = 1;
            puVar6[0xd] = (short)iVar8;
            uVar7 = FUN_80017ae4(dVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 puVar6,5,*(undefined *)(puVar4 + 0x56),0xffffffff,
                                 *(uint **)(puVar4 + 0x18),param_14,param_15,param_16);
            puVar12[0x1c0] = uVar7;
            puVar12 = puVar12 + 1;
            iVar8 = iVar8 + 1;
            dVar13 = extraout_f1_00;
          } while (iVar8 < 7);
          FUN_80006824((uint)puVar4,0x3db);
          FUN_800068d0((uint)puVar4,0x3dc);
        }
        goto LAB_8014149c;
      }
      if ((((code *)puVar10[0x1c9] != (code *)0x0) &&
          (iVar8 = (*(code *)puVar10[0x1c9])(puVar10[9],1), iVar8 == 0)) ||
         (*(float *)(puVar4 + 0x4c) <= lbl_803E3194)) goto LAB_8014149c;
      puVar10[0x15] = puVar10[0x15] & 0xfffff7ff;
      puVar10[0x15] = puVar10[0x15] | 0x1000;
      iVar8 = 0;
      puVar12 = puVar10;
      do {
        FUN_801778d0(puVar12[0x1c0]);
        puVar12 = puVar12 + 1;
        iVar8 = iVar8 + 1;
      } while (iVar8 < 7);
      FUN_800068cc();
      iVar8 = *(int *)(puVar4 + 0x5c);
      if ((((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) &&
          ((0x2f < (short)puVar4[0x50] || ((short)puVar4[0x50] < 0x29)))) &&
         (bVar9 = FUN_800067f0((int)puVar4,0x10), !bVar9)) {
        FUN_80039468(puVar4,iVar8 + 0x3a8,0x29d,0,0xffffffff,0);
      }
      bVar9 = false;
    }
    if (!bVar9) {
      *(undefined *)(puVar10 + 2) = 1;
      *(undefined *)((int)puVar10 + 10) = 0;
      fVar1 = lbl_803E306C;
      puVar10[0x1c7] = lbl_803E306C;
      puVar10[0x1c8] = fVar1;
      puVar10[0x15] = puVar10[0x15] & 0xffffffef;
      puVar10[0x15] = puVar10[0x15] & 0xfffeffff;
      puVar10[0x15] = puVar10[0x15] & 0xfffdffff;
      puVar10[0x15] = puVar10[0x15] & 0xfffbffff;
      *(undefined *)((int)puVar10 + 0xd) = 0xff;
    }
    break;
  case 8:
    FUN_80146fa0();
    puVar10[0x1ca] = (float)puVar10[0x1ca] - lbl_803DC074;
    if ((float)puVar10[0x1ca] <= lbl_803E306C) {
      FUN_8013d8f0((double)lbl_803E3118,(short *)puVar4,(int)puVar10,(float *)(puVar10[0x1c8] + 8)
                   ,'\x01');
      FUN_80139a48();
      iVar8 = FUN_800db47c((float *)(puVar4 + 0xc),(undefined *)0x0);
      if (iVar8 != 0) {
        *(undefined *)(puVar10 + 2) = 1;
        *(undefined *)((int)puVar10 + 10) = 0;
        fVar1 = lbl_803E306C;
        puVar10[0x1c7] = lbl_803E306C;
        puVar10[0x1c8] = fVar1;
        puVar10[0x15] = puVar10[0x15] & 0xffffffef;
        puVar10[0x15] = puVar10[0x15] & 0xfffeffff;
        puVar10[0x15] = puVar10[0x15] & 0xfffdffff;
        puVar10[0x15] = puVar10[0x15] & 0xfffbffff;
        *(undefined *)((int)puVar10 + 0xd) = 0xff;
      }
    }
  }
  FUN_80286888();
  return;
}


/*
 * --INFO--
 *
 * Function: fn_8014089C
 * EN v1.0 Address: 0x8014089C
 * EN v1.0 Size: 320b
 */
#pragma scheduling off
int fn_8014089C(int p) {
    int count;
    f32 d;
    f32 bestDist;
    uint best;
    int i;
    int *list;

    best = 0;
    list = (int *)ObjGroup_GetObjects(3, &count);
    for (i = 0; (s16)i < count; i++) {
        d = (f32)getXZDistance((float *)(*list + 0x18), (float *)(p + 0x71c));
        if (best == 0) {
            if (*(int *)(p + 0x730) == fn_800DBCFC((float *)(*list + 0x18), (void *)0x0)) {
                bestDist = d;
                best = *list;
            }
        } else if (d < bestDist) {
            if (*(int *)(p + 0x730) == fn_800DBCFC((float *)(*list + 0x18), (void *)0x0)) {
                bestDist = d;
                best = *list;
            }
        }
        list++;
    }
    if (best == 0) {
        return 0;
    }
    *(int *)(p + 0x72c) = best;
    if (*(uint *)(p + 0x28) != (best + 0x18)) {
        *(int *)(p + 0x28) = best + 0x18;
        *(u32 *)(p + 0x54) = *(u32 *)(p + 0x54) & 0xfffffbff;
        *(u16 *)(p + 0xd2) = 0;
    }
    *(u8 *)(p + 0xa) = 4;
    return 1;
}
#pragma scheduling on

extern int trickyDebugPrint(const char *fmt, ...);
extern int trickyFn_8013b368(int p1, int p2, f32 f);
extern int fn_800DAFDC(float *pos, int p2, int p3);
extern int fn_8013D5A4(int p1, int p2, void *target, int p4, f32 f);
extern int fn_80139A8C(int p1, void *p2);
extern void fn_80139930(int p1, s16 angle);
extern void objAnimFn_8013a3f0(int obj, int p2, f32 f, int p4);
extern void *Obj_AllocObjectSetup(int p1, int p2);
extern int Obj_SetupObject(void *setup, int p2, int p3, int p4, void *p5);
extern int Sfx_PlayFromObject(int obj, int sfxId);
extern int Sfx_AddLoopedObjectSound(int obj, int sfxId);
extern int Sfx_RemoveLoopedObjectSound(int obj, int sfxId);
extern int Sfx_IsPlayingFromObjectChannel(int obj, int chan);
extern int Obj_IsLoadingLocked(void);
extern void objSetAnimSpeedTo1(void *obj);
extern void objAudioFn_800393f8(int obj, void *p2, int p3, int p4, int p5, int p6);

extern char lbl_8031D2E8[];
extern void **lbl_803DCA9C;
extern f32 timeDelta;
extern double fn_80293E80(double);
extern double sin(double);
extern int getAngle(f32 x, f32 z);
extern int randomGetRange(int lo, int hi);
extern f32 getXZDistance(float *a, float *b);
extern void *ObjGroup_GetObjects(int group, int *count);
extern f32 lbl_803E23EC;
extern f32 lbl_803E23F4;
extern f32 lbl_803E2410;
extern f32 lbl_803E2414;
extern f32 lbl_803E2420;
extern f32 lbl_803E243C;
extern f32 lbl_803E2440;
extern f32 lbl_803E2444;
extern f32 lbl_803E2454;
extern f32 lbl_803E2458;
extern f64 lbl_803E2460;
extern f32 lbl_803E247C;
extern f32 lbl_803E24C4;
extern f32 lbl_803E24D0;
extern f32 lbl_803E24D8;
extern f32 lbl_803E23DC;
extern f32 lbl_803E23E4;
extern f32 lbl_803E2418;
extern f32 lbl_803E2488;
extern f32 lbl_803E24AC;
extern f32 lbl_803E24F8;
extern f32 lbl_803E2504;

/*
 * --INFO--
 *
 * Function: fn_801409DC
 * EN v1.0 Address: 0x801409DC
 * EN v1.0 Size: 2224b
 */
#pragma scheduling off
void fn_801409DC(int p1, int p2) {
    char *strBase = lbl_8031D2E8;
    int i;
    void **slot;
    void *setup;
    void *state;
    void *target;
    int dieFlag;

    switch (*(u8 *)(p2 + 0xa)) {
    case 0:
        trickyDebugPrint(strBase + 0x700);
        *(int *)(p2 + 0x71c) = fn_800DAFDC((float *)(*(int *)(p2 + 0x24) + 0x18), -1, 4);
        if (*(u8 *)(*(int *)(p2 + 0x71c) + 0x3) != 0) {
            if (*(uint *)(p2 + 0x28) != (uint)(*(int *)(p2 + 0x71c) + 0x8)) {
                *(int *)(p2 + 0x28) = *(int *)(p2 + 0x71c) + 0x8;
                *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) & 0xfffffbff;
                *(u16 *)(p2 + 0xd2) = 0;
            }
            *(u8 *)(p2 + 0xa) = 1;
        } else {
            *(int *)(p2 + 0x720) = (*(int (**)(int))((char *)*lbl_803DCA9C + 0x1c))(*(int *)(*(int *)(p2 + 0x71c) + 0x1c));
            if (*(uint *)(p2 + 0x28) != (uint)(*(int *)(p2 + 0x720) + 0x8)) {
                *(int *)(p2 + 0x28) = *(int *)(p2 + 0x720) + 0x8;
                *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) & 0xfffffbff;
                *(u16 *)(p2 + 0xd2) = 0;
            }
            *(u8 *)(p2 + 0xa) = 3;
        }
        trickyFn_8013b368(p1, p2, lbl_803E2488);
        break;
    case 3:
        trickyDebugPrint(strBase + 0x70c);
        trickyFn_8013b368(p1, p2, lbl_803E2488);
        if ((u8)*(u8 *)(*(int *)(p2 + 0x720) + 0x3) == fn_800DBCFC((float *)(p1 + 0x18), (void *)0x0)) {
            *(u8 *)(p2 + 0x9) = 1;
            *(u8 *)(p2 + 0xa) = 4;
        }
        break;
    case 4:
        trickyDebugPrint(strBase + 0x720);
        target = (void *)(*(int *)(p2 + 0x71c) + 0x8);
        fn_8013D5A4(p1, p2, target, 1, lbl_803E2488);
        fn_80139A8C(p1, target);
        if (fn_800DBCFC((float *)(p1 + 0x18), (void *)0x0) == 0) {
            *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) | 0x10;
            *(u8 *)(p2 + 0xa) = 5;
        }
        break;
    case 5:
        trickyDebugPrint(strBase + 0x734);
        target = (void *)(*(int *)(p2 + 0x71c) + 0x8);
        fn_8013D5A4(p1, p2, target, 1, lbl_803E2488);
        if (fn_80139A8C(p1, target) == 0) {
            objAnimFn_8013a3f0(p1, 0x1a, lbl_803E23E4, 0x4000000);
            *(u8 *)(p2 + 0xa) = 7;
            (*(u8 *)*(int *)p2) -= 4;
        }
        break;
    case 7:
        trickyDebugPrint(strBase + 0x744);
        {
            s16 srcAng = (s16)((s32)(s8)*(u8 *)(*(int *)(p2 + 0x71c) + 0x2c) << 8);
            s16 cur = (s16)*(u16 *)p1;
            s16 delta = (s16)(srcAng - cur);
            if (delta > 0x8000) {
                delta = delta + 1;
            }
            if (delta < -0x8000) {
                delta = delta - 1;
            }
            {
                int absDelta = (s32)delta;
                if (absDelta < 0) absDelta = -absDelta;
                if (absDelta >= 0x4000) {
                    srcAng = srcAng + 0x8000;
                }
            }
            fn_80139930(p1, srcAng);
        }
        if ((double)*(f32 *)(p1 + 0x98) <= (double)lbl_803E24AC) {
            dieFlag = 1;
        } else {
            if ((*(u32 *)(p2 + 0x54) & 0x800) == 0) {
                if ((u8)Obj_IsLoadingLocked() != 0) {
                    *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) | 0x800;
                    slot = (void **)p2;
                    for (i = 0; i < 7; i++) {
                        setup = Obj_AllocObjectSetup(0x24, 0x4f0);
                        *(u8 *)((char *)setup + 0x4) = 2;
                        *(u8 *)((char *)setup + 0x5) = 1;
                        *(s16 *)((char *)setup + 0x1a) = (s16)i;
                        slot[0x700 / 4] = (void *)Obj_SetupObject(setup, 5, *(s8 *)(p1 + 0xac), -1, *(void **)(p1 + 0x30));
                        slot++;
                    }
                    Sfx_PlayFromObject(p1, 0x3db);
                    Sfx_AddLoopedObjectSound(p1, 0x3dc);
                }
                dieFlag = 1;
            } else {
                int (*cb)(int, int) = *(int (**)(int, int))(p2 + 0x724);
                if (cb != NULL && cb(*(int *)(p2 + 0x24), 1) == 0) {
                    dieFlag = 1;
                } else if (*(f32 *)(p1 + 0x98) <= lbl_803E2504) {
                    dieFlag = 1;
                } else {
                    *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) & ~0x800;
                    *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) | 0x1000;
                    slot = (void **)p2;
                    for (i = 0; i < 7; i++) {
                        objSetAnimSpeedTo1(slot[0x700 / 4]);
                        slot++;
                    }
                    Sfx_RemoveLoopedObjectSound(p1, 0x3dc);
                    state = *(void **)(p1 + 0xb8);
                    if (((*(u8 *)((char *)state + 0x58) >> 6) & 1) == 0) {
                        s16 a0 = *(s16 *)(p1 + 0xa0);
                        if (a0 >= 0x30 || a0 < 0x29) {
                            if (Sfx_IsPlayingFromObjectChannel(p1, 0x10) == 0) {
                                objAudioFn_800393f8(p1, (char *)state + 0x3a8, 0x29d, 0, -1, 0);
                            }
                        }
                    }
                    dieFlag = 0;
                }
            }
        }
        if (dieFlag == 0) {
            *(u8 *)(p2 + 0xa) = 8;
            *(f32 *)(p2 + 0x728) = lbl_803E24F8;
        }
        break;
    case 1:
        trickyDebugPrint(strBase + 0x750);
        {
            int r = trickyFn_8013b368(p1, p2, lbl_803E2488);
            if (r == 0) {
                *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) | 0x10;
                *(u8 *)(p2 + 0xa) = 2;
            } else if (r == 2) {
                *(u8 *)(p2 + 0x8) = 1;
                *(u8 *)(p2 + 0xa) = 0;
                *(f32 *)(p2 + 0x71c) = lbl_803E23DC;
                *(f32 *)(p2 + 0x720) = lbl_803E23DC;
                *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) & ~0x10;
                *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) & ~0x10000;
                *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) & ~0x20000;
                *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) & ~0x40000;
                *(u8 *)(p2 + 0xd) = 0xff;
            }
        }
        break;
    case 2:
        trickyDebugPrint(strBase + 0x764);
        target = (void *)(*(int *)(p2 + 0x24) + 0x18);
        fn_8013D5A4(p1, p2, target, 1, lbl_803E2418);
        if (fn_80139A8C(p1, target) == 0) {
            objAnimFn_8013a3f0(p1, 0x1a, lbl_803E23E4, 0x4000000);
            *(u8 *)(p2 + 0xa) = 6;
            (*(u8 *)*(int *)p2) -= 4;
        }
        break;
    case 6:
        trickyDebugPrint(strBase + 0x778);
        if ((double)*(f32 *)(p1 + 0x98) <= (double)lbl_803E24AC) {
            dieFlag = 1;
        } else {
            if ((*(u32 *)(p2 + 0x54) & 0x800) == 0) {
                if ((u8)Obj_IsLoadingLocked() != 0) {
                    *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) | 0x800;
                    slot = (void **)p2;
                    for (i = 0; i < 7; i++) {
                        setup = Obj_AllocObjectSetup(0x24, 0x4f0);
                        *(u8 *)((char *)setup + 0x4) = 2;
                        *(u8 *)((char *)setup + 0x5) = 1;
                        *(s16 *)((char *)setup + 0x1a) = (s16)i;
                        slot[0x700 / 4] = (void *)Obj_SetupObject(setup, 5, *(s8 *)(p1 + 0xac), -1, *(void **)(p1 + 0x30));
                        slot++;
                    }
                    Sfx_PlayFromObject(p1, 0x3db);
                    Sfx_AddLoopedObjectSound(p1, 0x3dc);
                }
                dieFlag = 1;
            } else {
                int (*cb)(int, int) = *(int (**)(int, int))(p2 + 0x724);
                if (cb != NULL && cb(*(int *)(p2 + 0x24), 1) == 0) {
                    dieFlag = 1;
                } else if (*(f32 *)(p1 + 0x98) <= lbl_803E2504) {
                    dieFlag = 1;
                } else {
                    *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) & ~0x800;
                    *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) | 0x1000;
                    slot = (void **)p2;
                    for (i = 0; i < 7; i++) {
                        objSetAnimSpeedTo1(slot[0x700 / 4]);
                        slot++;
                    }
                    Sfx_RemoveLoopedObjectSound(p1, 0x3dc);
                    state = *(void **)(p1 + 0xb8);
                    if (((*(u8 *)((char *)state + 0x58) >> 6) & 1) == 0) {
                        s16 a0 = *(s16 *)(p1 + 0xa0);
                        if (a0 >= 0x30 || a0 < 0x29) {
                            if (Sfx_IsPlayingFromObjectChannel(p1, 0x10) == 0) {
                                objAudioFn_800393f8(p1, (char *)state + 0x3a8, 0x29d, 0, -1, 0);
                            }
                        }
                    }
                    dieFlag = 0;
                }
            }
        }
        if (dieFlag == 0) {
            *(u8 *)(p2 + 0x8) = 1;
            *(u8 *)(p2 + 0xa) = 0;
            *(f32 *)(p2 + 0x71c) = lbl_803E23DC;
            *(f32 *)(p2 + 0x720) = lbl_803E23DC;
            *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) & ~0x10;
            *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) & ~0x10000;
            *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) & ~0x20000;
            *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) & ~0x40000;
            *(u8 *)(p2 + 0xd) = 0xff;
        }
        break;
    case 8:
        trickyDebugPrint(strBase + 0x784);
        *(f32 *)(p2 + 0x728) = *(f32 *)(p2 + 0x728) - timeDelta;
        if (*(f32 *)(p2 + 0x728) <= lbl_803E23DC) {
            target = (void *)(*(int *)(p2 + 0x720) + 0x8);
            fn_8013D5A4(p1, p2, target, 1, lbl_803E2488);
            fn_80139A8C(p1, target);
            if (fn_800DBCFC((float *)(p1 + 0x18), (void *)0x0) != 0) {
                *(u8 *)(p2 + 0x8) = 1;
                *(u8 *)(p2 + 0xa) = 0;
                *(f32 *)(p2 + 0x71c) = lbl_803E23DC;
                *(f32 *)(p2 + 0x720) = lbl_803E23DC;
                *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) & ~0x10;
                *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) & ~0x10000;
                *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) & ~0x20000;
                *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) & ~0x40000;
                *(u8 *)(p2 + 0xd) = 0xff;
            }
        }
        break;
    }
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: fn_8013FFB8
 * EN v1.0 Address: 0x8013FFB8
 * EN v1.0 Size: 2276b
 */
#pragma scheduling off
void fn_8013FFB8(int p1, int p2) {
    char *strBase = lbl_8031D2E8;
    int *list;
    int count;
    int i;
    void **slot;
    void *setup;
    void *state;
    int found;

    switch (*(u8 *)(p2 + 0xa)) {
    case 0:
        trickyDebugPrint(strBase + 0x648);
        *(int *)(p2 + 0x730) = fn_800DBCFC((float *)(*(int *)(p2 + 0x28)), (void *)0x0);
        *(f32 *)(p2 + 0x71c) = (f32)(*(f32 *)(*(int *)(p2 + 0x24) + 0x18) - lbl_803E247C *
            fn_80293E80(((double)(int)*(s16 *)*(int *)(p2 + 0x24) * lbl_803E2454) / lbl_803E2458));
        *(f32 *)(p2 + 0x720) = *(f32 *)(*(int *)(p2 + 0x24) + 0x1c);
        *(f32 *)(p2 + 0x724) = (f32)(*(f32 *)(*(int *)(p2 + 0x24) + 0x20) - lbl_803E247C *
            sin(((double)(int)*(s16 *)*(int *)(p2 + 0x24) * lbl_803E2454) / lbl_803E2458));
        *(u8 *)(p2 + 0x734) = 0;
        *(u8 *)(p2 + 0xa) = 1;
        break;
    case 1:
        trickyDebugPrint(strBase + 0x654);
        trickyFn_8013b368(p1, p2, lbl_803E2488);
        if (*(int *)(p2 + 0x730) == fn_800DBCFC((float *)(p1 + 0x18), (void *)0x0)) {
            *(u8 *)(p2 + 0xa) = 2;
        }
        break;
    case 2:
        trickyDebugPrint(strBase + 0x664);
        if (trickyFn_8013b368(p1, p2, lbl_803E2488) == 0) {
            if (*(uint *)(p2 + 0x28) != (uint)(p2 + 0x71c)) {
                *(int *)(p2 + 0x28) = p2 + 0x71c;
                *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) & 0xfffffbff;
                *(u16 *)(p2 + 0xd2) = 0;
            }
            *(u8 *)(p2 + 0xa) = 3;
        } else {
            fn_8014089C(p2);
        }
        break;
    case 3:
        trickyDebugPrint(strBase + 0x674);
        if (trickyFn_8013b368(p1, p2, lbl_803E2488) == 0) {
            if (lbl_803E23DC == *(f32 *)(p2 + 0x2ac)) {
                found = 0;
            } else if (lbl_803E2410 == *(f32 *)(p2 + 0x2b0)) {
                found = 1;
            } else if ((*(f32 *)(p2 + 0x2b4) - *(f32 *)(p2 + 0x2b0)) > lbl_803E2414) {
                found = 1;
            } else {
                found = 0;
            }
            if (found != 0) {
                objAnimFn_8013a3f0(p1, 0x8, lbl_803E243C, 0);
                *(f32 *)(p2 + 0x79c) = lbl_803E2440;
                *(f32 *)(p2 + 0x838) = lbl_803E23DC;
                trickyDebugPrint(strBase + 0x184);
            } else {
                objAnimFn_8013a3f0(p1, 0, lbl_803E2444, 0);
                trickyDebugPrint(strBase + 0x190);
            }
        }
        fn_8014089C(p2);
        break;
    case 4:
        trickyDebugPrint(strBase + 0x684);
        if (trickyFn_8013b368(p1, p2, lbl_803E247C) == 0) {
            *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) | 0x10;
            if (*(u8 *)*(int *)p2 != 0 && *(u8 *)(p2 + 0x734) != 0 && (u8)Obj_IsLoadingLocked() != 0) {
                *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) | 0x800;
                slot = (void **)p2;
                for (i = 0; i < 7; i++) {
                    setup = Obj_AllocObjectSetup(0x24, 0x4f0);
                    *(u8 *)((char *)setup + 0x4) = 2;
                    *(u8 *)((char *)setup + 0x5) = 1;
                    *(s16 *)((char *)setup + 0x1a) = (s16)i;
                    slot[0x700 / 4] = (void *)Obj_SetupObject(setup, 5, *(s8 *)(p1 + 0xac), -1, *(void **)(p1 + 0x30));
                    slot++;
                }
                Sfx_PlayFromObject(p1, 0x3db);
                Sfx_AddLoopedObjectSound(p1, 0x3dc);
            }
            if (*(u8 *)*(int *)p2 != 0 && *(u8 *)(p2 + 0x734) != 0) {
                (*(u8 *)*(int *)p2)--;
                objAnimFn_8013a3f0(p1, 0x34, lbl_803E2444, 0x4000000);
                *(u8 *)(p2 + 0xa) = 5;
            } else {
                objAnimFn_8013a3f0(p1, 0x32, lbl_803E23EC, 0x4000000);
                *(u8 *)(p2 + 0xa) = 6;
            }
        } else {
            if (*(int *)(p2 + 0x730) != fn_800DBCFC((float *)(*(int *)(p2 + 0x28)), (void *)0x0)) {
                if (*(uint *)(p2 + 0x28) != (uint)(*(int *)(p2 + 0x24) + 0x18)) {
                    *(int *)(p2 + 0x28) = *(int *)(p2 + 0x24) + 0x18;
                    *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) & 0xfffffbff;
                    *(u16 *)(p2 + 0xd2) = 0;
                }
                *(u8 *)(p2 + 0xa) = 2;
            }
            break;
        }
        /* fallthrough into case 5 setup? No — case 4 has `b .L_801403D4` (= state 5 prologue). */
        /* Actually case 4 ends with branch to .L_801403D4 (start of case 5). */
        /* But MWCC will see this as fallthrough. */
    case 5:
        trickyDebugPrint(strBase + 0x694);
        if ((double)*(f32 *)(p1 + 0x98) > (double)lbl_803E24D0) {
            *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) & ~0x800;
            *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) | 0x1000;
            slot = (void **)p2;
            for (i = 0; i < 7; i++) {
                objSetAnimSpeedTo1(slot[0x700 / 4]);
                slot++;
            }
            Sfx_RemoveLoopedObjectSound(p1, 0x3dc);
            state = *(void **)(p1 + 0xb8);
            if (((*(u8 *)((char *)state + 0x58) >> 6) & 1) == 0) {
                s16 a0 = *(s16 *)(p1 + 0xa0);
                if (a0 >= 0x30 || a0 < 0x29) {
                    if (Sfx_IsPlayingFromObjectChannel(p1, 0x10) == 0) {
                        objAudioFn_800393f8(p1, (char *)state + 0x3a8, 0x29d, 0, -1, 0);
                    }
                }
            }
            *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) & ~0x10;
            if (fn_8014089C(p2) == 0) {
                if (*(uint *)(p2 + 0x28) != (uint)(*(int *)(p2 + 0x24) + 0x18)) {
                    *(int *)(p2 + 0x28) = *(int *)(p2 + 0x24) + 0x18;
                    *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) & 0xfffffbff;
                    *(u16 *)(p2 + 0xd2) = 0;
                }
                *(u8 *)(p2 + 0xa) = 2;
            }
        }
        break;
    case 6:
        trickyDebugPrint(strBase + 0x6a4);
        if ((double)*(f32 *)(p1 + 0x98) > (double)lbl_803E24D0) {
            objAnimFn_8013a3f0(p1, 0x33, lbl_803E2444, 0x4000000);
            *(f32 *)(p2 + 0x728) = lbl_803E23DC;
            state = *(void **)(p1 + 0xb8);
            if (((*(u8 *)((char *)state + 0x58) >> 6) & 1) == 0) {
                s16 a0 = *(s16 *)(p1 + 0xa0);
                if (a0 >= 0x30 || a0 < 0x29) {
                    if (Sfx_IsPlayingFromObjectChannel(p1, 0x10) == 0) {
                        objAudioFn_800393f8(p1, (char *)state + 0x3a8, 0x299, 0x100, -1, 0);
                    }
                }
            }
            *(u8 *)(p2 + 0xa) = 7;
        } else {
            int *li = (int *)ObjGroup_GetObjects(3, &count);
            int target = *(int *)(p2 + 0x72c);
            found = 0;
            for (i = 0; (s16)i < count; i++) {
                if (*li == target) {
                    found = 1;
                    break;
                }
                li++;
            }
            if (found != 0) {
                int targ = *(int *)(*(int *)(p1 + 0xb8) + 0x28);
                fn_80139930(p1, (s16)getAngle(
                    -(*(f32 *)targ - *(f32 *)(p1 + 0x18)),
                    -(*(f32 *)(targ + 0x8) - *(f32 *)(p1 + 0x20))));
            }
        }
        break;
    case 7:
        trickyDebugPrint(strBase + 0x6b8);
        if (randomGetRange(0, 10) == 0) {
            state = *(void **)(p1 + 0xb8);
            if (((*(u8 *)((char *)state + 0x58) >> 6) & 1) == 0) {
                s16 a0 = *(s16 *)(p1 + 0xa0);
                if (a0 >= 0x30 || a0 < 0x29) {
                    if (Sfx_IsPlayingFromObjectChannel(p1, 0x10) == 0) {
                        objAudioFn_800393f8(p1, (char *)state + 0x3a8, 0x299, 0x100, -1, 0);
                    }
                }
            }
        }
        *(f32 *)(p2 + 0x728) = *(f32 *)(p2 + 0x728) + timeDelta;
        {
            int closeOrTimeout = 0;
            if ((double)*(f32 *)(p2 + 0x728) > (double)lbl_803E24D8) {
                closeOrTimeout = 1;
            } else if ((double)getXZDistance((float *)*(int *)(p2 + 0x28), (float *)(p1 + 0x18)) > (double)lbl_803E24C4) {
                closeOrTimeout = 1;
            }
            if (closeOrTimeout) {
                int *li = (int *)ObjGroup_GetObjects(3, &count);
                int target = *(int *)(p2 + 0x72c);
                found = 0;
                for (i = 0; (s16)i < count; i++) {
                    if (*li == target) { found = 1; break; }
                    li++;
                }
                if (found == 0) {
                    objAnimFn_8013a3f0(p1, 0x32, lbl_803E23F4, 0x4000000);
                    *(u8 *)(p2 + 0xa) = 8;
                    break;
                }
            }
            {
                int targ = *(int *)(*(int *)(p1 + 0xb8) + 0x28);
                fn_80139930(p1, (s16)getAngle(
                    -(*(f32 *)targ - *(f32 *)(p1 + 0x18)),
                    -(*(f32 *)(targ + 0x8) - *(f32 *)(p1 + 0x20))));
            }
        }
        break;
    case 8:
        trickyDebugPrint(strBase + 0x6c8);
        if ((double)*(f32 *)(p1 + 0x98) > (double)lbl_803E2420) {
            *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) & ~0x10;
            if (fn_8014089C(p2) == 0) {
                if (*(uint *)(p2 + 0x28) != (uint)(*(int *)(p2 + 0x24) + 0x18)) {
                    *(int *)(p2 + 0x28) = *(int *)(p2 + 0x24) + 0x18;
                    *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) & 0xfffffbff;
                    *(u16 *)(p2 + 0xd2) = 0;
                }
                *(u8 *)(p2 + 0xa) = 2;
            }
        }
        break;
    }
}
#pragma scheduling reset

/* Trivial 4b 0-arg blr leaves. */
void fn_8014128C(void) {}
