#include "ghidra_import.h"
#include "main/mapEvent.h"
#include "main/dll/DR/DRpushcart.h"

#define SFXsp_sa_def01 243

extern undefined4 FUN_80006824();
extern double FUN_80006a38();
extern undefined4 FUN_80006ac8();
extern undefined4 FUN_80006acc();
extern undefined4 FUN_80006b50();
extern undefined4 FUN_80006b54();
extern undefined4 FUN_80006b74();
extern int FUN_80006b7c();
extern undefined4 FUN_80006bb4();
extern uint FUN_80006c00();
extern undefined4 FUN_80006c88();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern int FUN_800176d0();
extern uint FUN_80017730();
extern u32 randomGetRange(int min, int max);
extern int FUN_8001792c();
extern undefined4 FUN_80017a54();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_8002fc3c();
extern undefined4 ObjGroup_FindNearestObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 FUN_80039520();
extern undefined4 FUN_8003b280();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80053c98();
extern undefined4 FUN_800632e8();
extern void gxSetPeControl_ZCompLoc_();
extern void gxSetZMode_();
extern undefined4 FUN_80081028();
extern undefined4 FUN_80081030();
extern undefined4 FUN_80081038();
extern undefined4 FUN_800810f4();
extern int FUN_801149b8();
extern undefined4 FUN_801149bc();
extern void dll_2E_func06();
extern undefined4 FUN_80114b10();
extern undefined4 FUN_801150ac();
extern undefined4 FUN_8011e800();
extern undefined4 FUN_8011e844();
extern undefined4 FUN_8011e868();
extern undefined4 FUN_8011eb38();
extern undefined4 FUN_801f4f9c();
extern undefined4 FUN_801f4fa0();
extern undefined4 FUN_8025c754();
extern undefined4 FUN_8025cce8();
extern int FUN_80286838();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286884();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined2 FUN_80294d20();
extern undefined4 FUN_80294d28();
extern uint countLeadingZeros();

extern undefined4 DAT_803adcc8;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f4;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803dd734;
extern undefined4 DAT_803de8d8;
extern undefined4* lbl_803DCAB4;
#define gBoneParticleEffectInterface lbl_803DCAB4
extern f64 DOUBLE_803e6698;
extern f64 DOUBLE_803e66f0;
extern f32 lbl_803DC074;
extern f32 lbl_803E59D8;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E6670;
extern f32 lbl_803E6674;
extern f32 lbl_803E6688;
extern f32 lbl_803E66B8;
extern f32 lbl_803E66BC;
extern f32 lbl_803E66C0;
extern f32 lbl_803E66C8;
extern f32 lbl_803E66CC;
extern f32 lbl_803E66D0;
extern f32 lbl_803E66D4;
extern f32 lbl_803E66D8;
extern f32 lbl_803E66DC;
extern f32 lbl_803E66E0;
extern f32 lbl_803E66E4;
extern f32 lbl_803E66E8;
extern f32 lbl_803E66F8;

/*
 * --INFO--
 *
 * Function: FUN_801e76a0
 * EN v1.0 Address: 0x801E76A0
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801E7714
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801e76a0(int param_1)
{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  uVar1 = GameBit_Get(0xcef);
  if (uVar1 == 0) {
    uVar2 = 0;
  }
  else {
    uVar1 = GameBit_Get(0xad3);
    if (uVar1 == 0) {
      GameBit_Set(0xad3,1);
      iVar3 = *(int *)(iVar3 + 0x9b4);
      (**(code **)(**(int **)(iVar3 + 0x68) + 0x24))(iVar3,1,2);
    }
    uVar2 = 2;
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_801e7724
 * EN v1.0 Address: 0x801E7724
 * EN v1.0 Size: 1032b
 * EN v1.1 Address: 0x801E7794
 * EN v1.1 Size: 1096b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_801e7724(int param_1,undefined4 param_2,int param_3)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  uint uVar5;
  char cVar6;
  int iVar7;
  int iVar8;
  char local_18;
  undefined auStack_17 [7];
  
  iVar7 = *(int *)(param_1 + 0xb8);
  if (param_3 == 0x14) {
    FUN_80006bb4(0,auStack_17,&local_18);
    if (local_18 < '\0') {
      *(short *)(iVar7 + 0x9d0) = *(short *)(iVar7 + 0x9d0) + -1;
      FUN_80006824(0,SFXsp_sa_def01);
    }
    else if ('\0' < local_18) {
      *(short *)(iVar7 + 0x9d0) = *(short *)(iVar7 + 0x9d0) + 1;
      FUN_80006824(0,SFXsp_sa_def01);
    }
    if (*(short *)(iVar7 + 0x9c8) < *(short *)(iVar7 + 0x9d0)) {
      *(short *)(iVar7 + 0x9d0) = *(short *)(iVar7 + 0x9c8);
    }
    iVar3 = (int)*(short *)(iVar7 + 0x9cc) << 1;
    if (iVar3 < *(short *)(iVar7 + 0x9d0)) {
      *(short *)(iVar7 + 0x9d0) = (short)iVar3;
    }
    else {
      iVar3 = (int)*(short *)(iVar7 + 0x9cc) >> 1;
      if (*(short *)(iVar7 + 0x9d0) < iVar3) {
        *(short *)(iVar7 + 0x9d0) = (short)iVar3;
      }
    }
    iVar8 = (int)*(short *)(iVar7 + 0x9d0);
    piVar4 = (int *)FUN_80039520(param_1,8);
    iVar3 = iVar8 >> 0x1f;
    iVar1 = iVar8 / 10 + iVar3;
    *piVar4 = (iVar8 + (iVar1 - (iVar1 >> 0x1f)) * -10) * 0x100;
    piVar4 = (int *)FUN_80039520(param_1,7);
    iVar1 = iVar8 / 10 + iVar3;
    iVar1 = iVar1 - (iVar1 >> 0x1f);
    iVar2 = iVar1 / 10 + (iVar1 >> 0x1f);
    *piVar4 = (iVar1 + (iVar2 - (iVar2 >> 0x1f)) * -10) * 0x100;
    iVar3 = iVar8 / 100 + iVar3;
    iVar3 = iVar3 - (iVar3 >> 0x1f);
    if (9 < iVar3) {
      iVar3 = 9;
    }
    piVar4 = (int *)FUN_80039520(param_1,6);
    *piVar4 = iVar3 << 8;
  }
  else if (param_3 == 0x17) {
    FUN_80006bb4(0,auStack_17,&local_18);
    if (local_18 < '\0') {
      *(char *)(iVar7 + 0x9d5) = *(char *)(iVar7 + 0x9d5) + -1;
      FUN_80006824(0,SFXsp_sa_def01);
    }
    else if ('\0' < local_18) {
      *(char *)(iVar7 + 0x9d5) = *(char *)(iVar7 + 0x9d5) + '\x01';
      FUN_80006824(0,SFXsp_sa_def01);
    }
    if (*(short *)(iVar7 + 0x9c8) < (short)(ushort)*(byte *)(iVar7 + 0x9d5)) {
      *(char *)(iVar7 + 0x9d5) = (char)*(short *)(iVar7 + 0x9c8);
    }
    if (*(byte *)(iVar7 + 0x9d5) < 0xb) {
      if (*(byte *)(iVar7 + 0x9d5) == 0) {
        *(undefined *)(iVar7 + 0x9d5) = 1;
      }
    }
    else {
      *(undefined *)(iVar7 + 0x9d5) = 10;
    }
    uVar5 = (uint)*(byte *)(iVar7 + 0x9d5);
    piVar4 = (int *)FUN_80039520(param_1,8);
    *piVar4 = (uVar5 % 10) * 0x100;
    piVar4 = (int *)FUN_80039520(param_1,7);
    *piVar4 = ((uVar5 / 10) % 10) * 0x100;
    uVar5 = uVar5 / 100;
    if (9 < uVar5) {
      uVar5 = 9;
    }
    piVar4 = (int *)FUN_80039520(param_1,6);
    *piVar4 = uVar5 << 8;
    uVar5 = FUN_80006c00(0);
    if ((uVar5 & 0x200) != 0) {
      *(byte *)(iVar7 + 0x9d4) = *(byte *)(iVar7 + 0x9d4) | 0x10;
      (**(code **)(*DAT_803dd6cc + 8))(0x1e,1);
      return 1;
    }
  }
  uVar5 = FUN_80006c00(0);
  if ((uVar5 & 0x100) == 0) {
    uVar5 = 0;
  }
  else {
    if (*(short *)(iVar7 + 0x9d0) < *(short *)(iVar7 + 0x9ce)) {
      if (*(byte *)(iVar7 + 0x9d2) < 2) {
        cVar6 = '\0';
      }
      else {
        cVar6 = '\x02';
      }
    }
    else {
      cVar6 = '\x01';
    }
    if (param_3 == 0x15) {
      if (cVar6 == '\x01') {
        (**(code **)(**(int **)(*(int *)(iVar7 + 0x9b4) + 0x68) + 0x48))();
      }
      uVar5 = countLeadingZeros(1 - cVar6);
      uVar5 = uVar5 >> 5;
    }
    else {
      if (param_3 < 0x15) {
        if (0x13 < param_3) {
          if (cVar6 == '\0') {
            *(char *)(iVar7 + 0x9d2) = *(char *)(iVar7 + 0x9d2) + '\x01';
          }
          uVar5 = countLeadingZeros((int)cVar6);
          return uVar5 >> 5;
        }
      }
      else if (param_3 < 0x17) {
        uVar5 = countLeadingZeros(2 - cVar6);
        return uVar5 >> 5;
      }
      uVar5 = 0;
    }
  }
  return uVar5;
}

/*
 * --INFO--
 *
 * Function: FUN_801e7b2c
 * EN v1.0 Address: 0x801E7B2C
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x801E7BDC
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e7b2c(int param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if ((*(byte *)(iVar1 + 0x9d4) & 2) == 0) {
    FUN_8011e800(0);
  }
  else {
    FUN_80006b54(0x11,0x1e);
    FUN_80006b50();
    FUN_8011eb38(1);
    GameBit_Set(0x626,1);
    (**(code **)(**(int **)(*(int *)(iVar1 + 0x9b4) + 0x68) + 0x4c))
              (*(int *)(iVar1 + 0x9b4),*(undefined *)(iVar1 + 0x9d5));
    (**(code **)(*DAT_803dd6f4 + 4))(0,0xf5,0,0,0);
  }
  *(undefined *)(iVar1 + 0x9d4) = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e7be4
 * EN v1.0 Address: 0x801E7BE4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801E7C90
 * EN v1.1 Size: 1452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e7be4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,char param_12,
                 undefined4 param_13,int param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801e7be8
 * EN v1.0 Address: 0x801E7BE8
 * EN v1.0 Size: 340b
 * EN v1.1 Address: 0x801E823C
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_801e7be8(ushort *param_1,int param_2,int param_3)
{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  double dVar5;
  
  fVar1 = *(float *)(param_2 + 0xc) - *(float *)(param_1 + 6);
  fVar2 = *(float *)(param_2 + 0x14) - *(float *)(param_1 + 10);
  dVar5 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
  if ((double)lbl_803E66BC < dVar5) {
    uVar3 = FUN_80017730();
    if (param_3 == 0) {
      iVar4 = (uVar3 & 0xffff) - (uint)*param_1;
      if (0x8000 < iVar4) {
        iVar4 = iVar4 + -0xffff;
      }
      if (iVar4 < -0x8000) {
        iVar4 = iVar4 + 0xffff;
      }
      if (iVar4 < 0x2001) {
        if (iVar4 < -0x2000) {
          iVar4 = iVar4 + 0x2000;
        }
        else {
          iVar4 = 0;
        }
      }
      else {
        iVar4 = iVar4 + -0x2000;
      }
      *param_1 = (ushort)(int)((f32)(s32)(iVar4 >> 3) * lbl_803DC074 +
                              (float)((double)CONCAT44(0x43300000,(int)(short)*param_1 ^ 0x80000000)
                                     - DOUBLE_803e6698));
    }
    else {
      *param_1 = (ushort)uVar3;
    }
  }
  return dVar5;
}

#pragma scheduling off
#pragma peephole off
void fn_801E7DC8(int p1, int p2, int count)
{
  extern u8 Obj_IsLoadingLocked(void);
  extern void hitDetectFn_800658a4(int, int *, int, f32, f32, f32);
  extern int Obj_AllocObjectSetup(int, int);
  extern void Obj_SetupObject(int, int, int, int, int);
  extern int *gMapEventInterface;
  int i;
  int local;
  int o;

  if (Obj_IsLoadingLocked() == 0) return;

  ((MapEventInterface *)*gMapEventInterface)->setAnimEvent((s32)(s8)*(u8 *)(p1 + 0xac), 6, 1);

  hitDetectFn_800658a4(p1, &local, 0, *(f32 *)(p1 + 0xc), *(f32 *)(p1 + 0x10), *(f32 *)(p1 + 0x14));

  for (i = 0; i < count; i++) {
    o = Obj_AllocObjectSetup(36, 1151);
    *(f32 *)(o + 8) = *(f32 *)(p1 + 0xc);
    *(f32 *)(o + 12) = *(f32 *)(p1 + 0x10);
    *(f32 *)(o + 16) = *(f32 *)(p1 + 0x14);
    *(u8 *)(o + 24) = (u8)(s8)randomGetRange(-128, 127);
    *(s16 *)(o + 26) = (s16)(s32)(*(f32 *)(p1 + 0x10) - *(f32 *)&local);
    *(u8 *)(o + 5) = 1;
    *(u8 *)(o + 7) = 255;
    *(u8 *)(o + 4) = 16;
    *(u8 *)(o + 6) = 6;
    *(int *)(o + 20) = *(int *)(p2 + 0x9b4);
    Obj_SetupObject(o, 5, (s32)(s8)*(u8 *)(p1 + 0xac), -1, *(int *)(p1 + 0x30));
  }

  for (i = 0; i < count; i++) {
    o = Obj_AllocObjectSetup(36, 1151);
    *(f32 *)(o + 8) = *(f32 *)(p1 + 0xc);
    *(f32 *)(o + 12) = *(f32 *)(p1 + 0x10);
    *(f32 *)(o + 16) = *(f32 *)(p1 + 0x14);
    *(u8 *)(o + 24) = (u8)(s8)randomGetRange(-128, 127);
    *(s16 *)(o + 26) = (s16)(s32)(*(f32 *)(p1 + 0x10) - *(f32 *)&local);
    *(u8 *)(o + 5) = 1;
    *(u8 *)(o + 7) = 255;
    *(u8 *)(o + 4) = 16;
    *(u8 *)(o + 6) = 6;
    *(u8 *)(o + 25) = 1;
    *(int *)(o + 20) = *(int *)(p2 + 0x9b4);
    Obj_SetupObject(o, 5, (s32)(s8)*(u8 *)(p1 + 0xac), -1, *(int *)(p1 + 0x30));
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_801e7d3c
 * EN v1.0 Address: 0x801E7D3C
 * EN v1.0 Size: 688b
 * EN v1.1 Address: 0x801E83B8
 * EN v1.1 Size: 508b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e7d3c(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)
{
  int iVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  undefined2 *puVar5;
  int iVar6;
  double dVar7;
  double dVar8;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined8 uVar9;
  float local_28 [2];
  longlong local_20;
  
  uVar9 = FUN_80286840();
  iVar3 = (int)((ulonglong)uVar9 >> 0x20);
  uVar4 = FUN_80017ae8();
  if ((uVar4 & 0xff) != 0) {
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(iVar3 + 0xac),6,1);
    dVar7 = (double)*(float *)(iVar3 + 0x10);
    dVar8 = (double)*(float *)(iVar3 + 0x14);
    FUN_800632e8((double)*(float *)(iVar3 + 0xc),dVar7,dVar8,iVar3,local_28,0);
    for (iVar6 = 0; iVar6 < param_3; iVar6 = iVar6 + 1) {
      puVar5 = FUN_80017aa4(0x24,0x47f);
      *(undefined4 *)(puVar5 + 4) = *(undefined4 *)(iVar3 + 0xc);
      *(undefined4 *)(puVar5 + 6) = *(undefined4 *)(iVar3 + 0x10);
      *(undefined4 *)(puVar5 + 8) = *(undefined4 *)(iVar3 + 0x14);
      uVar4 = randomGetRange(0xffffff80,0x7f);
      *(char *)(puVar5 + 0xc) = (char)uVar4;
      fVar2 = *(float *)(iVar3 + 0x10);
      iVar1 = (int)((double)fVar2 - (double)local_28[0]);
      local_20 = (longlong)iVar1;
      puVar5[0xd] = (short)iVar1;
      *(undefined *)((int)puVar5 + 5) = 1;
      *(undefined *)((int)puVar5 + 7) = 0xff;
      *(undefined *)(puVar5 + 2) = 0x10;
      *(undefined *)(puVar5 + 3) = 6;
      *(undefined4 *)(puVar5 + 10) = *(undefined4 *)((int)uVar9 + 0x9b4);
      FUN_80017ae4((double)fVar2,dVar7,dVar8,in_f4,in_f5,in_f6,in_f7,in_f8,puVar5,5,
                   *(undefined *)(iVar3 + 0xac),0xffffffff,*(uint **)(iVar3 + 0x30),param_6,param_7,
                   param_8);
    }
    for (iVar6 = 0; iVar6 < param_3; iVar6 = iVar6 + 1) {
      puVar5 = FUN_80017aa4(0x24,0x47f);
      *(undefined4 *)(puVar5 + 4) = *(undefined4 *)(iVar3 + 0xc);
      *(undefined4 *)(puVar5 + 6) = *(undefined4 *)(iVar3 + 0x10);
      *(undefined4 *)(puVar5 + 8) = *(undefined4 *)(iVar3 + 0x14);
      uVar4 = randomGetRange(0xffffff80,0x7f);
      *(char *)(puVar5 + 0xc) = (char)uVar4;
      fVar2 = *(float *)(iVar3 + 0x10);
      iVar1 = (int)((double)fVar2 - (double)local_28[0]);
      local_20 = (longlong)iVar1;
      puVar5[0xd] = (short)iVar1;
      *(undefined *)((int)puVar5 + 5) = 1;
      *(undefined *)((int)puVar5 + 7) = 0xff;
      *(undefined *)(puVar5 + 2) = 0x10;
      *(undefined *)(puVar5 + 3) = 6;
      *(undefined *)((int)puVar5 + 0x19) = 1;
      *(undefined4 *)(puVar5 + 10) = *(undefined4 *)((int)uVar9 + 0x9b4);
      FUN_80017ae4((double)fVar2,dVar7,dVar8,in_f4,in_f5,in_f6,in_f7,in_f8,puVar5,5,
                   *(undefined *)(iVar3 + 0xac),0xffffffff,*(uint **)(iVar3 + 0x30),param_6,param_7,
                   param_8);
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: shopkeeper_render
 * EN v1.0 Address: 0x801E7FEC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801E85B4
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void Stack_Free();

void shopkeeper_free(int param_1)
{
  Stack_Free(*(undefined4 *)(*(int *)(param_1 + 0xb8) + 0x9b0));
  return;
}

/*
 * --INFO--
 *
 * Function: shopkeeper_render
 * EN v1.0 Address: 0x801E8014
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x801E85DC
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void shopkeeper_render(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
    int iVar1 = *(int *)(param_1 + 0xb8);
    float local_18[4];
    local_18[0] = lbl_803E59D8;
    if (*(s16 *)(iVar1 + 0x274) != 7 && visible != 0) {
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)
            (param_1, param_2, param_3, param_4, param_5, lbl_803E59D8);
        dll_2E_func06(param_1, iVar1 + 0x35c, 0);
    }
    if ((*(u8 *)(iVar1 + 0x9d4) & 0x20) != 0) {
        (*(void (*)(int, int, float *, int, int))(*(int *)(*gBoneParticleEffectInterface + 0xc)))(param_1, 0x7ef, local_18, 0x50, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_801e80b0
 * EN v1.0 Address: 0x801E80B0
 * EN v1.0 Size: 452b
 * EN v1.1 Address: 0x801E8680
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e80b0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)
{
  int iVar1;
  undefined4 uVar2;
  undefined2 uVar3;
  int iVar4;
  float local_18 [3];
  
  iVar1 = FUN_80017a98();
  iVar4 = *(int *)(param_9 + 0x5c);
  local_18[0] = lbl_803E66B8;
  *(byte *)(iVar4 + 0x9d4) = *(byte *)(iVar4 + 0x9d4) & 0xdf;
  if ((double)lbl_803E6674 < (double)*(float *)(iVar4 + 0x9c4)) {
    FUN_80006c88((double)*(float *)(iVar4 + 0x9c4),param_2,param_3,param_4,param_5,param_6,param_7,
                 param_8,0x433);
    *(float *)(iVar4 + 0x9c4) = *(float *)(iVar4 + 0x9c4) - lbl_803DC074;
    if (*(float *)(iVar4 + 0x9c4) < lbl_803E6674) {
      *(float *)(iVar4 + 0x9c4) = lbl_803E6674;
    }
  }
  if ((*(byte *)(iVar4 + 0x9d4) & 4) != 0) {
    FUN_801e7be8(param_9,iVar1,1);
  }
  *(undefined4 *)(param_9 + 4) = *(undefined4 *)(*(int *)(param_9 + 0x28) + 4);
  if (*(int *)(iVar4 + 0x9b4) == 0) {
    uVar2 = ObjGroup_FindNearestObject(9,param_9,local_18);
    *(undefined4 *)(iVar4 + 0x9b4) = uVar2;
  }
  uVar3 = FUN_80294d20(iVar1);
  *(undefined2 *)(iVar4 + 0x9c8) = uVar3;
  (**(code **)(*DAT_803dd70c + 8))
            ((double)lbl_803DC074,(double)lbl_803DC074,param_9,iVar4,&DAT_803adcc8,&DAT_803de8d8
            );
  FUN_801150ac();
  FUN_8003b280((int)param_9,iVar4 + 0x980);
  *(undefined *)(param_9 + 0x1b) = *(undefined *)(iVar4 + 0x9d6);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e8274
 * EN v1.0 Address: 0x801E8274
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801E87C4
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e8274(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801e8278
 * EN v1.0 Address: 0x801E8278
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x801E891C
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e8278(int param_1)
{
  if (*(char *)(param_1 + 0x37) == -1) {
    FUN_8025cce8(0,1,0,5);
  }
  else {
    FUN_8025cce8(1,4,1,5);
  }
  gxSetZMode_(1,3,0);
  gxSetPeControl_ZCompLoc_(1);
  FUN_8025c754(7,0,0,7,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e8300
 * EN v1.0 Address: 0x801E8300
 * EN v1.0 Size: 532b
 * EN v1.1 Address: 0x801E89A0
 * EN v1.1 Size: 688b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e8300(void)
{
  float fVar1;
  bool bVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  undefined4 uVar8;
  byte bVar9;
  int iVar10;
  double in_f31;
  double dVar11;
  double in_ps31_1;
  float local_88;
  float local_84;
  float local_80;
  int local_7c;
  undefined8 local_50;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  iVar3 = FUN_80286838();
  iVar10 = *(int *)(iVar3 + 0xb8);
  bVar2 = false;
  if ((*(byte *)(iVar10 + 0xe8) >> 6 & 1) == 0) {
    FUN_800810f4((double)lbl_803E66C8,(double)lbl_803E66D0,iVar3,5,1,1,0x14,0,0);
  }
  else {
    FUN_800810f4((double)lbl_803E66C8,(double)lbl_803E66CC,iVar3,5,1,1,0x14,0,0);
  }
  piVar4 = (int *)FUN_80017a54(iVar3);
  iVar5 = FUN_8001792c(*piVar4,0);
  *(undefined *)(iVar5 + 0x43) = 0x7f;
  FUN_8003b818(iVar3);
  for (bVar9 = 0; bVar9 < 10; bVar9 = bVar9 + 1) {
    iVar5 = iVar10 + (uint)bVar9 * 4;
    if (*(float **)(iVar5 + 0x98) == (float *)0x0) {
      if ((!bVar2) && (iVar6 = FUN_800176d0(), iVar6 == 0)) {
        local_88 = *(float *)(iVar3 + 0xc);
        local_84 = *(float *)(iVar3 + 0x10);
        local_80 = *(float *)(iVar3 + 0x14);
        fVar1 = lbl_803E66DC;
        if ((*(byte *)(iVar10 + 0xe8) >> 6 & 1) != 0) {
          fVar1 = lbl_803E66D8;
        }
        dVar11 = (double)fVar1;
        local_7c = iVar3;
        uVar7 = randomGetRange(0,2000);
        local_88 = (float)(dVar11 * (double)(f32)(s32)(uVar7 - 1000) + (double)local_88);
        uVar7 = randomGetRange(0,2000);
        uStack_44 = uVar7 - 1000 ^ 0x80000000;
        local_48 = 0x43300000;
        local_84 = (float)(dVar11 * (f64)(f32)(s32)uStack_44 + (double)local_84);
        uVar7 = randomGetRange(0,2000);
        uStack_3c = uVar7 - 1000 ^ 0x80000000;
        local_40 = 0x43300000;
        local_80 = (float)(dVar11 * (f64)(f32)(s32)uStack_3c + (double)local_80);
        uVar8 = FUN_80081030((double)lbl_803E66E0,(double)lbl_803E66E4,iVar3 + 0xc,&local_88,
                             0x14,0x40,0);
        *(undefined4 *)(iVar5 + 0x98) = uVar8;
        *(float *)(iVar5 + 0xc0) = lbl_803E66E8;
        bVar2 = true;
      }
    }
    else {
      FUN_80081028(*(float **)(iVar5 + 0x98));
      iVar6 = FUN_800176d0();
      if (iVar6 == 0) {
        *(float *)(iVar5 + 0xc0) = *(float *)(iVar5 + 0xc0) + lbl_803DC074;
        iVar6 = (int)(lbl_803E66D4 + *(float *)(iVar5 + 0xc0));
        local_50 = (double)(longlong)iVar6;
        *(short *)(*(int *)(iVar5 + 0x98) + 0x20) = (short)iVar6;
        if (0x14 < *(ushort *)(*(uint *)(iVar5 + 0x98) + 0x20)) {
          FUN_80081038(*(uint *)(iVar5 + 0x98));
          *(undefined4 *)(iVar5 + 0x98) = 0;
        }
      }
    }
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e8514
 * EN v1.0 Address: 0x801E8514
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x801E8C50
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e8514(int param_1)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (((*(byte *)(iVar2 + 0x97) >> 6 & 1) == 0) &&
     (iVar1 = (**(code **)(**(int **)(*(int *)(iVar2 + 0x90) + 0x68) + 0x2c))
                        (*(int *)(iVar2 + 0x90),*(undefined *)(*(int *)(param_1 + 0x4c) + 0x19)),
     iVar1 != 0)) {
    *(byte *)(iVar2 + 0x97) = *(byte *)(iVar2 + 0x97) & 0x7f | 0x80;
  }
  FUN_8011e800(0);
  (**(code **)(**(int **)(*(int *)(iVar2 + 0x90) + 0x68) + 0x40))(*(int *)(iVar2 + 0x90),0xffffffff)
  ;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e85b0
 * EN v1.0 Address: 0x801E85B0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801E8CE4
 * EN v1.1 Size: 452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801e85b0(undefined2 *param_1,undefined4 param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801e85b8
 * EN v1.0 Address: 0x801E85B8
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x801E8EA8
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e85b8(int param_1)
{
  uint uVar1;
  byte bVar2;
  int iVar3;
  
  (**(code **)(*DAT_803dd6f8 + 0x14))();
  if (*(short *)(param_1 + 0x46) == 0x468) {
    iVar3 = *(int *)(param_1 + 0xb8);
    for (bVar2 = 0; bVar2 < 10; bVar2 = bVar2 + 1) {
      uVar1 = *(uint *)(iVar3 + (uint)bVar2 * 4 + 0x98);
      if (uVar1 != 0) {
        FUN_80081038(uVar1);
      }
    }
    ObjGroup_RemoveObject(param_1,0x4f);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e8658
 * EN v1.0 Address: 0x801E8658
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x801E8F48
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e8658(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    if (*(short *)(param_1 + 0x46) == 0x468) {
      FUN_801e8300();
    }
    else {
      FUN_8003b818(param_1);
    }
  }
  return;
}

#pragma scheduling off
#pragma peephole off
int fn_801E86F4(int obj, int p2, int p3)
{
  extern void fn_801E8660(void);
  extern void ObjAnim_AdvanceCurrentMove(int obj, f32 a, f32 b, int x);
  extern void fn_801F4D54(int obj, int sub);
  extern void fn_801F4ECC(int obj, int sub);
  extern f32 Curve_EvalBSpline(int p, f32 t, int m);
  extern int getAngle(f32 a, f32 b);
  extern int *gPartfxInterface;
  extern f32 lbl_803E5A30;
  extern f32 lbl_803E5A60;
  extern f32 timeDelta;
  int sub = *(int *)(obj + 0xb8);

  *(int *)(p3 + 0xe8) = (int)&fn_801E8660;
  *(s16 *)(p3 + 0x6e) = (s16)(*(s16 *)(p3 + 0x6e) & ~4);
  *(s16 *)(p3 + 0x70) = (s16)(*(s16 *)(p3 + 0x70) & ~4);

  if (*(int *)(*(int *)(obj + 0x7c) + (s32)(s8)*(u8 *)(obj + 0xad) * 4) != 0) {
    ObjAnim_AdvanceCurrentMove(obj, lbl_803E5A60, timeDelta, 0);
  }

  switch (*(s16 *)(obj + 0x46)) {
  case 1127: {
    f32 t = *(f32 *)(sub + 0x40);
    if (t > lbl_803E5A30) {
      u32 v;
      *(f32 *)(sub + 0x40) = t - lbl_803E5A30;
      v = *(u8 *)(sub + 0x68);
      if (v >= 4) {
        *(u8 *)(sub + 0x68) = v + 1;
      } else {
        fn_801F4D54(obj, sub);
      }
      fn_801F4ECC(obj, sub);
    }
  }
  {
    *(f32 *)(obj + 0xc) = Curve_EvalBSpline(sub + 4, *(f32 *)(sub + 0x40), 0);
    *(f32 *)(obj + 0x10) = Curve_EvalBSpline(sub + 0x14, *(f32 *)(sub + 0x40), 0);
    *(f32 *)(obj + 0x14) = Curve_EvalBSpline(sub + 0x24, *(f32 *)(sub + 0x40), 0);
    *(f32 *)(sub + 0x40) = *(f32 *)(sub + 0x44) * timeDelta + *(f32 *)(sub + 0x40);
    *(s16 *)(obj + 0) = (s16)getAngle(
        *(f32 *)(obj + 0xc) - *(f32 *)(obj + 0x80),
        *(f32 *)(obj + 0x14) - *(f32 *)(obj + 0x88));
    (**(void (**)(int, int, int, int, int, int))((char *)(*gPartfxInterface) + 0x8))(obj, 415, 0, 1, -1, 0);
    (**(void (**)(int, int, int, int, int, int))((char *)(*gPartfxInterface) + 0x8))(obj, 416, 0, 1, -1, 0);
  }
  break;
  }
  return 0;
}

#pragma peephole reset
#pragma scheduling reset


/* Trivial 4b 0-arg blr leaves. */
void shopkeeper_hitDetect(void) {}
void shopkeeper_release(void) {}
void shopitem_hitDetect(void) {}
void shopitem_release(void) {}
void shopitem_initialise(void) {}
void spscarab_render(void) {}
void spscarab_hitDetect(void) {}

/* 8b "li r3, N; blr" returners. */
int shopkeeper_getExtraSize(void) { return 0x9d8; }
int shopkeeper_getObjectTypeId(void) { return 0x0; }
int shopitem_getExtraSize(void) { return 0xec; }
int shopitem_getObjectTypeId(void) { return 0x0; }
int spscarab_getExtraSize(void) { return 0x14; }
int spscarab_getObjectTypeId(void) { return 0x0; }

extern void Sfx_RemoveLoopedObjectSound(int x, int y);
#pragma scheduling off
#pragma peephole off
void spscarab_free(int x) { Sfx_RemoveLoopedObjectSound(x, 0x406); }
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E5A30;
extern void objRenderFn_8003b8f4(f32);
extern void fn_801E83B0(int obj, int, int, int, int);

#pragma scheduling off
#pragma peephole off
void shopitem_render(int obj, int p2, int p3, int p4, int p5, s8 visible) {
    s32 v = visible;
    if (v != 0) {
        if (*(s16 *)(obj + 0x46) == 0x468) {
            fn_801E83B0(obj, 0, 0, 0, 0);
        } else {
            objRenderFn_8003b8f4(lbl_803E5A30);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int *gExpgfxInterface;
#pragma scheduling off
#pragma peephole off
void shopitem_free(int obj) {
    (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x14)))(obj);
    if (*(s16 *)(obj + 0x46) == 0x468) {
        ObjGroup_RemoveObject(obj, 0x4F);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void *lbl_803AD068[8];
extern void *lbl_803DDC58;
extern void DRlaserturret_startLinkedTarget(int);
extern void DRlaserturret_updateTracking(int);
extern void DRlaserturret_updateIdle(int);
extern void TREX_Lazerwall_updateTimedChallenge(int);
extern void TREX_Lazerwall_waitForStartBit(int);
extern void TREX_Lazerwall_popQueuedState(int);
extern void fn_801E66EC(int);
extern void fn_801E66E4(int);
extern void fn_801E66DC(int);

extern void GXSetBlendMode(int type, int src, int dst, int op);
extern void gxSetZMode_(u32 a, int b, u32 c);
extern void gxSetPeControl_ZCompLoc_(u32 a);
extern void GXSetAlphaCompare(int comp0, u8 ref0, int op, int comp1, u8 ref1);

#pragma scheduling off
#pragma peephole off
void fn_801E832C(int obj) {
    if (*(u8 *)(obj + 0x37) == 0xFF) {
        GXSetBlendMode(0, 1, 0, 5);
    } else {
        GXSetBlendMode(1, 4, 1, 5);
    }
    gxSetZMode_(1, 3, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void shopkeeper_initialise(void) {
    lbl_803AD068[0] = (void *)DRlaserturret_startLinkedTarget;
    lbl_803AD068[1] = (void *)DRlaserturret_updateTracking;
    lbl_803AD068[2] = (void *)DRlaserturret_updateIdle;
    lbl_803AD068[3] = (void *)TREX_Lazerwall_updateTimedChallenge;
    lbl_803AD068[4] = (void *)TREX_Lazerwall_waitForStartBit;
    lbl_803AD068[5] = (void *)TREX_Lazerwall_popQueuedState;
    lbl_803AD068[6] = (void *)fn_801E66EC;
    lbl_803AD068[7] = (void *)fn_801E66E4;
    lbl_803DDC58 = (void *)fn_801E66DC;
}
#pragma peephole reset
#pragma scheduling reset

extern void hudFn_8011f38c(int);
extern void *Obj_GetPlayerObject(void);
extern f32 lbl_803E5A20;
extern f32 timeDelta;
extern f32 lbl_803E59DC;
extern void gameTextShow(int);
extern u32 ObjGroup_FindNearestObject(int kind, int obj, f32 *out);
extern int playerGetMoney(void *player);
extern void characterDoEyeAnims(int obj, int p2);
extern void dll_2E_func03(int, int);
extern f32 shopKeeperRotateFn_801e7c4c(s16 *obj, void *player, int mode);
extern int *gPlayerInterface;

typedef struct {
    u8 bit80 : 1;
    u8 bit40 : 1;
    u8 bit20 : 1;
    u8 bit10 : 1;
    u8 bit08 : 1;
    u8 bit04 : 1;
    u8 bit02 : 1;
    u8 bit01 : 1;
} BitsAt9D4;

#pragma scheduling off
#pragma peephole off
void shopkeeper_update(int obj) {
    void *player;
    int state;
    f32 dist;
    player = Obj_GetPlayerObject();
    state = *(int *)(obj + 0xB8);
    dist = lbl_803E5A20;
    *(u8 *)(state + 0x9D4) &= ~0x20;
    if (*(f32 *)(state + 0x9C4) > lbl_803E59DC) {
        gameTextShow(0x433);
        *(f32 *)(state + 0x9C4) = *(f32 *)(state + 0x9C4) - timeDelta;
        if (*(f32 *)(state + 0x9C4) < lbl_803E59DC) {
            *(f32 *)(state + 0x9C4) = lbl_803E59DC;
        }
    }
    if ((*(u8 *)(state + 0x9D4) & 0x04) != 0) {
        shopKeeperRotateFn_801e7c4c((s16 *)obj, player, 1);
    }
    *(f32 *)(obj + 8) = *(f32 *)(*(int *)(obj + 0x50) + 4);
    if (*(void **)(state + 0x9B4) == NULL) {
        *(int *)(state + 0x9B4) = ObjGroup_FindNearestObject(9, obj, &dist);
    }
    *(s16 *)(state + 0x9C8) = (s16)playerGetMoney(player);
    ((void (*)(int, int, void *, void *, f32, f32))(*(int *)((int)*gPlayerInterface + 8)))
        (obj, state, lbl_803AD068, &lbl_803DDC58, timeDelta, timeDelta);
    dll_2E_func03(obj, state + 0x35C);
    characterDoEyeAnims(obj, state + 0x980);
    *(u8 *)(obj + 0x36) = *(u8 *)(state + 0x9D6);
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E59F0;
extern f32 lbl_803E5A28;
extern void *allocModelStruct_800139e8(int, int);
extern void dll_2E_func05(int, int, int, int, int);
extern int fn_801E76A0(int obj, int p2, u8 *data, s8 advance);
extern void *Obj_GetActiveModel(int);
extern void ObjModel_SetPostRenderCallback(void *, void *);
extern void ObjGroup_AddObject(int, int);
extern void fn_801F4C28(int, int);
extern int fn_801E86F4(int, int, int);
extern int *gPartfxInterface;

#pragma scheduling off
#pragma peephole off
void shopitem_init(int obj, int data) {
    int state = *(int *)(obj + 0xB8);
    *(u16 *)(obj + 0xB0) |= 0x2000;
    *(void (**)(int))(obj + 0xBC) = (void (*)(int))fn_801E86F4;
    *(s8 *)(obj + 0xAD) = (s8)*(s8 *)(data + 0x18);
    *(s16 *)obj = (s16)((*(u8 *)(data + 0x1A)) << 8);
    *(s16 *)(obj + 2) = (s16)((*(u8 *)(data + 0x1B)) << 8);
    if ((s32)*(s8 *)(obj + 0xAD) >= (s32)*(s8 *)(*(int *)(obj + 0x50) + 0x55)) {
        *(s8 *)(obj + 0xAD) = 0;
    }
    switch (*(s16 *)(obj + 0x46)) {
    case 0x467:
        fn_801F4C28(obj, state);
        break;
    case 0x462:
        (*(int (*)(int, int, int, int, int, int))(*(int *)(*gPartfxInterface + 0x8)))(obj, 0x3F1, 0, 4, -1, 0);
        break;
    case 0x468:
        ObjModel_SetPostRenderCallback(Obj_GetActiveModel(obj), (void *)fn_801E832C);
        ObjGroup_AddObject(obj, 0x4F);
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void shopkeeper_init(int obj) {
    int state = *(int *)(obj + 0xB8);
    *(u16 *)(obj + 0xB0) |= 0x2000;
    *(void (**)(int))(obj + 0xBC) = (void (*)(int))fn_801E76A0;
    *(u32 *)(*(int *)(obj + 0x64) + 0x30) |= 0x810;
    *(f32 *)(state + 0x9B8) = lbl_803E59F0 * (f32)(s32)randomGetRange(0xF, 0x23);
    *(void **)(state + 0x9B0) = allocModelStruct_800139e8(4, 4);
    *(u8 *)(state + 0x9D6) = 0xFF;
    *(f32 *)(state + 0x9C4) = lbl_803E5A28;
    dll_2E_func05(obj, state + 0x35C, -0x1C71, 0x3555, 2);
    *(u8 *)(state + 0x96D) |= 0x12;
}
#pragma peephole reset
#pragma scheduling reset

typedef struct {
    u8 flag_80 : 1;
    u8 flag_40 : 1;
    u8 _rest : 6;
} PushcartState97;

#pragma scheduling off
#pragma peephole off
void fn_801E8660(int obj) {
    int state = *(int *)(obj + 0xB8);
    int def = *(int *)(obj + 0x4C);
    PushcartState97 *b = (PushcartState97 *)(state + 0x97);
    if (b->flag_40 == 0) {
        int *vptr = *(int **)(state + 0x90);
        int *cls = **(int ***)((char *)vptr + 0x68);
        if ((*(int (*)(int *, int))cls[0x2C / 4])(vptr, *(u8 *)(def + 0x19)) != 0) {
            b->flag_80 = 1;
        }
    }
    hudFn_8011f38c(0);
    {
        int *vptr2 = *(int **)(state + 0x90);
        int *cls2 = **(int ***)((char *)vptr2 + 0x68);
        (*(void (*)(int *, int))cls2[0x40 / 4])(vptr2, -1);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E5A60;
extern f32 lbl_803E5A64;
extern f32 lbl_803E5A68;
extern void ObjMsg_SendToObject(void *to, int msg, int obj, void *data);
extern void forceAButtonIcon(int icon);
extern void showHelpText(int textId);
extern void buttonDisable(int a, int b);
extern int *gObjectTriggerInterface;
extern void objRenderFn_80041018(int obj);
extern f32 Curve_EvalBSpline(int p, f32 t, int m);

#pragma scheduling off
#pragma peephole off
void shopitem_update(int obj)
{
    int def = *(int *)(obj + 0x4C);
    void *player = Obj_GetPlayerObject();
    int state = *(int *)(obj + 0xB8);
    f32 range = lbl_803E5A64;
    PushcartState97 *b = (PushcartState97 *)(state + 0x97);
    int money;
    int price;

    if (b->flag_40) {
        *(s16 *)(obj + 6) = (s16)(*(s16 *)(obj + 6) | 0x4000);
        *(u16 *)(obj + 0xB0) = (u16)(*(u16 *)(obj + 0xB0) | 0x8000);
        *(u8 *)(obj + 0xAF) |= 8;
    } else if (b->flag_80) {
        *(s16 *)(state + 0x88) = -1;
        ObjMsg_SendToObject(Obj_GetPlayerObject(), 0x7000A, obj, (void *)(state + 0x88));
        b->flag_80 = 0;
        b->flag_40 = 1;
    } else {
        if (*(u32 *)(state + 0x90) == 0) {
            int item;
            *(int *)(state + 0x90) = ObjGroup_FindNearestObject(9, obj, &range);
            item = *(int *)(state + 0x90);
            if ((u32)item != 0) {
                if ((*(int (**)(int, int))((char *)**(int ***)(item + 0x68) + 0x28))(item, *(u8 *)(def + 0x19)) == 0
                    || (*(int (**)(int, int))((char *)**(int ***)(*(int *)(state + 0x90) + 0x68) + 0x2C))(*(int *)(state + 0x90), *(u8 *)(def + 0x19)) != 0) {
                    b->flag_40 = 1;
                    *(s16 *)(obj + 6) = (s16)(*(s16 *)(obj + 6) | 0x4000);
                    *(u16 *)(obj + 0xB0) = (u16)(*(u16 *)(obj + 0xB0) | 0x8000);
                    *(u8 *)(obj + 0xAF) |= 8;
                }
                *(s16 *)(state + 0x94) = (s16)(*(int (**)(int, int))((char *)**(int ***)(*(int *)(state + 0x90) + 0x68) + 0x3C))(*(int *)(state + 0x90), *(u8 *)(def + 0x19));
            }
        } else {
            if (*(u8 *)(obj + 0xAF) & 4) {
                forceAButtonIcon(0x12);
                showHelpText(*(s16 *)(state + 0x94));
            }
            if (*(u8 *)(obj + 0xAF) & 1) {
                money = playerGetMoney(player);
                price = (*(int (**)(int, int))((char *)**(int ***)(*(int *)(state + 0x90) + 0x68) + 0x38))(*(int *)(state + 0x90), *(u8 *)(def + 0x19));
                (*(int (**)(int, int))((char *)**(int ***)(*(int *)(state + 0x90) + 0x68) + 0x40))(*(int *)(state + 0x90), *(u8 *)(def + 0x19));
                switch (*(s16 *)(obj + 0x46)) {
                case 0x467:
                    *(f32 *)(obj + 0x10) = lbl_803E5A68 + *(f32 *)(*(int *)(obj + 0x4C) + 0xC);
                    break;
                }
                if (money >= price) {
                    hudFn_8011f38c(3);
                    (*(void (**)(int, int, int))(*(int *)gObjectTriggerInterface + 0x48))(0, obj, -1);
                } else {
                    (*(void (**)(int, int, int))(*(int *)gObjectTriggerInterface + 0x48))(1, obj, -1);
                }
                buttonDisable(0, 0x100);
            }
            switch (*(s16 *)(obj + 0x46)) {
            case 0x467: {
                f32 t = *(f32 *)(state + 0x40);
                if (t > lbl_803E5A30) {
                    u32 v;
                    *(f32 *)(state + 0x40) = t - lbl_803E5A30;
                    v = *(u8 *)(state + 0x68);
                    if (v >= 4) {
                        *(u8 *)(state + 0x68) = v + 1;
                    } else {
                        fn_801F4D54(obj, state);
                    }
                    fn_801F4ECC(obj, state);
                }
                *(f32 *)(obj + 0xC) = Curve_EvalBSpline(state + 4, *(f32 *)(state + 0x40), 0);
                *(f32 *)(obj + 0x10) = Curve_EvalBSpline(state + 0x14, *(f32 *)(state + 0x40), 0);
                *(f32 *)(obj + 0x14) = Curve_EvalBSpline(state + 0x24, *(f32 *)(state + 0x40), 0);
                *(f32 *)(state + 0x40) = *(f32 *)(state + 0x44) * timeDelta + *(f32 *)(state + 0x40);
                *(s16 *)(obj + 0) = (s16)getAngle(
                    *(f32 *)(obj + 0xC) - *(f32 *)(obj + 0x80),
                    *(f32 *)(obj + 0x14) - *(f32 *)(obj + 0x88));
                (**(void (**)(int, int, int, int, int, int))((char *)(*gPartfxInterface) + 0x8))(obj, 0x19F, 0, 1, -1, 0);
                (**(void (**)(int, int, int, int, int, int))((char *)(*gPartfxInterface) + 0x8))(obj, 0x1A0, 0, 1, -1, 0);
                break;
            }
            }
        }
        if (*(s16 *)(obj + 0x46) != 0x464 && *(s16 *)(obj + 0x46) != 0x467) {
            ObjAnim_AdvanceCurrentMove(obj, lbl_803E5A60, timeDelta, 0);
        }
        if ((*(u8 *)(obj + 0xAF) & 8) == 0) {
            objRenderFn_80041018(obj);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E59D8;
extern void DRlaserturret_startTimedChallenge(int);
extern void DRlaserturret_handlePromptChoice(int);
extern void setAButtonIcon(int icon);
extern void setBButtonIcon(int icon);
extern void warpToMap(int mapId, int flag);
extern int getCurUiDll(void);
extern int *getDLL16(void);
extern void playerAddMoney(void *player, int amount);
extern void *objFindTexture(int obj, int target, int p3);
extern int *gScreenTransitionInterface;
extern int dll_2E_func07(int obj, u8 *data, int p3, int p4, int p5);

#pragma scheduling off
#pragma peephole off
int fn_801E76A0(int obj, int p2, u8 *data, s8 advance)
{
    int state;
    int state2;
    void *player;
    int slot;
    int i;
    int digit;
    int hundreds;
    int *tex;
    f32 range;
    f32 speed;

    state = state2 = *(int *)(obj + 0xB8);
    player = Obj_GetPlayerObject();
    range = lbl_803E59D8;
    *(u8 *)(state + 0x9D4) &= ~0x20;
    if (*(u8 *)(state + 0x9D4) & 0x10) {
        if ((*(int (**)(void))(*(int *)gScreenTransitionInterface + 0x14))() != 0) {
            (*(void (**)(int, int))(*(int *)gScreenTransitionInterface + 0xC))(0x1E, 1);
            (*(void (**)(int))(*(int *)gObjectTriggerInterface + 0x4C))(*(s8 *)(data + 0x57));
        }
        return 0;
    }
    if (dll_2E_func07(obj, data, state + 0x35C, 0, 0) != 0) {
        return 1;
    }
    *(void (**)(int))(data + 0xE8) = DRlaserturret_startTimedChallenge;
    *(s16 *)(data + 0x6E) = (s16)(*(s16 *)(data + 0x6E) & ~0x20);
    speed = lbl_803E59DC;
    *(f32 *)(state2 + 0x280) = speed;
    *(u8 *)(state + 0x9D4) |= 4;
    if (advance != 0) {
        ObjAnim_AdvanceCurrentMove(obj, speed, timeDelta, 0);
    }
    if (*(s16 *)(obj + 0xB4) == -1) {
        if (*(s8 *)(data + 0x56) != 0) {
            slot = (*(int (**)(int))((char *)**(int ***)(*(int *)(state + 0x9B4) + 0x68) + 0x44))(*(int *)(state + 0x9B4));
            if (slot != -1) {
                *(s16 *)(state + 0x9CC) = (s16)(*(int (**)(int, int))((char *)**(int ***)(*(int *)(state + 0x9B4) + 0x68) + 0x38))(*(int *)(state + 0x9B4), slot);
                *(s16 *)(state + 0x9CE) = (s16)(*(int (**)(int, int))((char *)**(int ***)(*(int *)(state + 0x9B4) + 0x68) + 0x30))(*(int *)(state + 0x9B4), slot);
                *(s16 *)(state + 0x9D0) = *(s16 *)(state + 0x9CC);
                *(u8 *)(state + 0x9D2) = 0;
                digit = *(s16 *)(state + 0x9CC);
                tex = (int *)objFindTexture(obj, 8, 0);
                *tex = (digit % 10) * 0x100;
                tex = (int *)objFindTexture(obj, 7, 0);
                *tex = ((digit / 10) % 10) * 0x100;
                hundreds = digit / 100;
                if (hundreds > 9) {
                    hundreds = 9;
                }
                tex = (int *)objFindTexture(obj, 6, 0);
                *tex = hundreds << 8;
            }
            *(u8 *)(data + 0x56) = 0;
            *(void (**)(int))(data + 0xEC) = DRlaserturret_handlePromptChoice;
        }
        if ((*(int (**)(int))((char *)**(int ***)(*(int *)(state + 0x9B4) + 0x68) + 0x44))(*(int *)(state + 0x9B4)) != -1) {
            setAButtonIcon(0x12);
            setBButtonIcon(0xA);
        }
    }
    for (i = 0; i < *(u8 *)(data + 0x8B); i++) {
        switch (*(u8 *)(data + i + 0x81)) {
        case 1:
            fn_801E7DC8(obj, state, *(u8 *)(state + 0x9D5));
            *(u8 *)(state + 0x9D4) |= 2;
            break;
        case 2:
            (*(void (**)(int, int, int))(*(int *)gPlayerInterface + 0x14))(obj, state2, 3);
            (*(void (**)(int, int, f32 *, int, int))(*(int *)lbl_803DCAB4 + 0xC))(obj, 0x7EF, &range, 0x50, 0);
            *(u8 *)(state + 0x9D6) = 0;
            break;
        case 3:
            (*(void (**)(int, int, int))(*(int *)gPlayerInterface + 0x14))(obj, state2, 2);
            *(u8 *)(state + 0x9D4) |= 0x20;
            *(u8 *)(state + 0x9D6) = 0xFF;
            break;
        case 4:
            if (*(s16 *)((char *)player + 0x46) == 0) {
                warpToMap(0xF, 0);
            } else {
                warpToMap(0xE, 0);
            }
            break;
        case 5:
            if (getCurUiDll() == 0x10) {
                tex = getDLL16();
                (*(void (**)(int))(*tex + 0x10))(0);
            }
            break;
        case 6:
            if (getCurUiDll() == 0x10) {
                tex = getDLL16();
                (*(void (**)(int))(*tex + 0x10))(2);
            }
            break;
        case 7:
            if (getCurUiDll() == 0x10) {
                tex = getDLL16();
                (*(void (**)(int))(*tex + 0x10))(4);
            }
            break;
        case 9:
            playerAddMoney(player, *(u8 *)(state + 0x9D5));
            break;
        case 10:
            playerAddMoney(player, -(int)*(u8 *)(state + 0x9D5));
            break;
        case 0xB:
            (*(void (**)(int, int, f32 *, int, int))(*(int *)lbl_803DCAB4 + 0xC))(obj, 0x7EF, &range, 0x50, 0);
            break;
        case 0xC:
            *(u8 *)(state + 0x9D5) = 1;
            digit = *(u8 *)(state + 0x9D5);
            tex = (int *)objFindTexture(obj, 8, 0);
            *tex = (digit % 10) * 0x100;
            tex = (int *)objFindTexture(obj, 7, 0);
            *tex = ((digit / 10) % 10) * 0x100;
            digit = digit / 100;
            if (digit > 9) {
                digit = 9;
            }
            tex = (int *)objFindTexture(obj, 6, 0);
            *tex = digit << 8;
            break;
        }
    }
    *(u8 *)(obj + 0x36) = *(u8 *)(state + 0x9D6);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern f32 sqrtf(f32 x);
extern f32 lbl_803E5A24;

#pragma scheduling off
#pragma peephole off
f32 shopKeeperRotateFn_801e7c4c(s16 *obj, void *player, int mode)
{
    f32 dx;
    f32 dz;
    f32 dist;
    u32 angle;
    int diff;

    dx = *(f32 *)((char *)player + 0xC) - *(f32 *)((char *)obj + 0xC);
    dz = *(f32 *)((char *)player + 0x14) - *(f32 *)((char *)obj + 0x14);
    dist = sqrtf(dx * dx + dz * dz);
    if (dist != lbl_803E59DC) {
        dx /= dist;
        dz /= dist;
    }
    if (dist > lbl_803E5A24) {
        angle = (u16)getAngle(dx, dz);
        if (mode != 0) {
            *obj = (s16)angle;
        } else {
            diff = angle - (u16)*obj;
            if (diff > 0x8000) {
                diff -= 0xFFFF;
            }
            if (diff < -0x8000) {
                diff += 0xFFFF;
            }
            if (diff > 0x2000) {
                diff -= 0x2000;
            } else if (diff < -0x2000) {
                diff += 0x2000;
            } else {
                diff = 0;
            }
            *obj = (s16)(int)((f32)(diff >> 3) * timeDelta + (f32)*obj);
        }
    }
    return dist;
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E5A34;
extern f32 lbl_803E5A38;
extern f32 lbl_803E5A3C;
extern f32 lbl_803E5A40;
extern f32 lbl_803E5A44;
extern f32 lbl_803E5A48;
extern f32 lbl_803E5A4C;
extern f32 lbl_803E5A50;
extern void objfx_spawnDirectionalBurst(int obj, int a, f32 radius, int c, int d, int e, f32 scale, int g, int h);
extern int ObjModel_GetRenderOp(int model, int idx);
extern void renderFn_8008f904(void);
extern int getHudHiddenFrameCount(void);
extern void mm_free_(int p);
extern int fn_8008FB20(f32 *start, void *end, f32 a, f32 b, int c, int d, int e);

typedef struct ShopSparkleSpawn {
    f32 x;
    f32 y;
    f32 z;
    int owner;
} ShopSparkleSpawn;

typedef struct PushcartStateE8 {
    u8 flag_80 : 1;
    u8 flag_40 : 1;
    u8 _rest : 6;
} PushcartStateE8;

#pragma scheduling off
#pragma peephole off
void fn_801E83B0(int obj, int p2, int p3, int p4, int p5)
{
    int state = *(int *)(obj + 0xB8);
    u8 spawned = 0;
    ShopSparkleSpawn v;
    PushcartStateE8 *b = (PushcartStateE8 *)(state + 0xE8);
    u8 i;
    int slot;
    f32 scale;

    if (b->flag_40) {
        objfx_spawnDirectionalBurst(obj, 5, lbl_803E5A30, 1, 1, 0x14, lbl_803E5A34, 0, 0);
    } else {
        objfx_spawnDirectionalBurst(obj, 5, lbl_803E5A30, 1, 1, 0x14, lbl_803E5A38, 0, 0);
    }
    *(u8 *)(ObjModel_GetRenderOp(*(int *)Obj_GetActiveModel(obj), 0) + 0x43) = 0x7F;
    ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E5A30);
    for (i = 0; i < 10; i++) {
        slot = state + i * 4;
        if (*(int *)(slot + 0x98) != 0) {
            renderFn_8008f904();
            if (getHudHiddenFrameCount() == 0) {
                *(f32 *)(slot + 0xC0) += timeDelta;
                *(u16 *)(*(int *)(slot + 0x98) + 0x20) = (u16)(int)(lbl_803E5A3C + *(f32 *)(slot + 0xC0));
                if (*(u16 *)(*(int *)(slot + 0x98) + 0x20) > 0x14) {
                    mm_free_(*(int *)(slot + 0x98));
                    *(int *)(slot + 0x98) = 0;
                }
            }
        } else {
            if (spawned == 0 && getHudHiddenFrameCount() == 0) {
                v.owner = obj;
                v.x = *(f32 *)(obj + 0xC);
                v.y = *(f32 *)(obj + 0x10);
                v.z = *(f32 *)(obj + 0x14);
                if (v.owner == obj) {
                    if (b->flag_40) {
                        scale = lbl_803E5A40;
                    } else {
                        scale = lbl_803E5A44;
                    }
                    v.x = scale * (f32)(int)(randomGetRange(0, 2000) - 1000) + v.x;
                    v.y = scale * (f32)(int)(randomGetRange(0, 2000) - 1000) + v.y;
                    v.z = scale * (f32)(int)(randomGetRange(0, 2000) - 1000) + v.z;
                }
                *(int *)(slot + 0x98) = fn_8008FB20((f32 *)(obj + 0xC), &v, lbl_803E5A48, lbl_803E5A4C, 0x14, 0x40, 0);
                *(f32 *)(slot + 0xC0) = lbl_803E5A50;
                spawned = 1;
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
