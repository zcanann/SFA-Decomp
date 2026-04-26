#include "ghidra_import.h"
#include "main/dll/cannon.h"

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

extern undefined4* DAT_803dd71c;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e306c;
extern f32 FLOAT_803e3074;
extern f32 FLOAT_803e307c;
extern f32 FLOAT_803e3084;
extern f32 FLOAT_803e30a0;
extern f32 FLOAT_803e30a4;
extern f32 FLOAT_803e30a8;
extern f32 FLOAT_803e30b0;
extern f32 FLOAT_803e30cc;
extern f32 FLOAT_803e30d0;
extern f32 FLOAT_803e30d4;
extern f32 FLOAT_803e310c;
extern f32 FLOAT_803e3118;
extern f32 FLOAT_803e313c;
extern f32 FLOAT_803e3154;
extern f32 FLOAT_803e3160;
extern f32 FLOAT_803e3168;
extern f32 FLOAT_803e3188;
extern f32 FLOAT_803e3194;

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
    FUN_8013b368((double)FLOAT_803e3118,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 puVar4,puVar10,iVar11,param_12,param_13,param_14,param_15,param_16);
    break;
  case 1:
    FUN_80146fa0();
    iVar8 = FUN_8013b368((double)FLOAT_803e3118,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,puVar4,puVar10,param_11,param_12,param_13,param_14,param_15,
                         param_16);
    if (iVar8 == 0) {
      puVar10[0x15] = puVar10[0x15] | 0x10;
      *(undefined *)((int)puVar10 + 10) = 2;
    }
    else if (iVar8 == 2) {
      *(undefined *)(puVar10 + 2) = 1;
      *(undefined *)((int)puVar10 + 10) = 0;
      fVar1 = FLOAT_803e306c;
      puVar10[0x1c7] = FLOAT_803e306c;
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
    FUN_8013d8f0((double)FLOAT_803e30a8,(short *)puVar4,(int)puVar10,(float *)(puVar10[9] + 0x18),
                 '\x01');
    iVar8 = FUN_80139a48();
    if (iVar8 == 0) {
      FUN_80139a4c((double)FLOAT_803e3074,(int)puVar4,0x1a,0x4000000);
      *(undefined *)((int)puVar10 + 10) = 6;
      *(char *)*puVar10 = *(char *)*puVar10 + -4;
    }
    break;
  case 3:
    FUN_80146fa0();
    FUN_8013b368((double)FLOAT_803e3118,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 puVar4,puVar10,param_11,param_12,param_13,param_14,param_15,param_16);
    uVar5 = FUN_800db47c((float *)(puVar4 + 0xc),(undefined *)0x0);
    if (*(byte *)(puVar10[0x1c8] + 3) == uVar5) {
      *(undefined *)((int)puVar10 + 9) = 1;
      *(undefined *)((int)puVar10 + 10) = 4;
    }
    break;
  case 4:
    FUN_80146fa0();
    FUN_8013d8f0((double)FLOAT_803e3118,(short *)puVar4,(int)puVar10,(float *)(puVar10[0x1c7] + 8),
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
    FUN_8013d8f0((double)FLOAT_803e3118,(short *)puVar4,(int)puVar10,(float *)(puVar10[0x1c7] + 8),
                 '\x01');
    iVar8 = FUN_80139a48();
    if (iVar8 != 0) break;
    FUN_80139a4c((double)FLOAT_803e3074,(int)puVar4,0x1a,0x4000000);
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
    if (dVar13 <= (double)FLOAT_803e313c) {
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
         (*(float *)(puVar4 + 0x4c) <= FLOAT_803e3194)) goto LAB_801411bc;
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
      puVar10[0x1ca] = FLOAT_803e3188;
    }
    break;
  case 6:
    FUN_80146fa0();
    dVar13 = (double)*(float *)(puVar4 + 0x4c);
    if (dVar13 <= (double)FLOAT_803e313c) {
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
         (*(float *)(puVar4 + 0x4c) <= FLOAT_803e3194)) goto LAB_8014149c;
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
      fVar1 = FLOAT_803e306c;
      puVar10[0x1c7] = FLOAT_803e306c;
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
    puVar10[0x1ca] = (float)puVar10[0x1ca] - FLOAT_803dc074;
    if ((float)puVar10[0x1ca] <= FLOAT_803e306c) {
      FUN_8013d8f0((double)FLOAT_803e3118,(short *)puVar4,(int)puVar10,(float *)(puVar10[0x1c8] + 8)
                   ,'\x01');
      FUN_80139a48();
      iVar8 = FUN_800db47c((float *)(puVar4 + 0xc),(undefined *)0x0);
      if (iVar8 != 0) {
        *(undefined *)(puVar10 + 2) = 1;
        *(undefined *)((int)puVar10 + 10) = 0;
        fVar1 = FLOAT_803e306c;
        puVar10[0x1c7] = FLOAT_803e306c;
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
