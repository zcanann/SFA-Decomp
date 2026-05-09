#include "ghidra_import.h"
#include "main/dll/cup1C3.h"

extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006818();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern void* FUN_800069a8();
extern int FUN_80006a64();
extern undefined8 FUN_80006a68();
extern byte FUN_80006b44();
extern undefined4 FUN_80006b4c();
extern undefined4 FUN_80006b50();
extern undefined4 FUN_80006b54();
extern uint FUN_80006bf8();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern uint FUN_80017760();
extern uint FUN_80017a98();
extern int FUN_80017b00();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 FUN_8003b818();
extern uint FUN_8028683c();
extern undefined4 FUN_80286888();
extern double FUN_80293900();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dcbd0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e5da8;
extern f32 lbl_803DC074;
extern f32 lbl_803E5D78;
extern f32 lbl_803E5D7C;
extern f32 lbl_803E5D80;
extern f32 lbl_803E5D84;
extern f32 lbl_803E5D88;
extern f32 lbl_803E5D8C;
extern f32 lbl_803E5D90;
extern f32 lbl_803E5D94;
extern f32 lbl_803E5D98;
extern f32 lbl_803E5D9C;
extern f32 lbl_803E5DA0;
extern f32 lbl_803E5DB8;
extern f32 lbl_803E5DBC;
extern f32 lbl_803E5DC0;
extern f32 lbl_803E5DC4;
extern f32 lbl_803E5DC8;
extern f32 lbl_803E5DCC;

/*
 * --INFO--
 *
 * Function: FUN_801c9660
 * EN v1.0 Address: 0x801C9660
 * EN v1.0 Size: 2276b
 * EN v1.1 Address: 0x801C9C14
 * EN v1.1 Size: 1500b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c9660(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  uint uVar2;
  uint uVar3;
  byte bVar6;
  int iVar4;
  uint uVar5;
  int *piVar7;
  int iVar8;
  double in_f28;
  double dVar9;
  double in_f29;
  double dVar10;
  double in_f30;
  double dVar11;
  double in_f31;
  double dVar12;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  int local_78;
  int local_74 [3];
  undefined8 local_68;
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
  uVar2 = FUN_8028683c();
  piVar7 = *(int **)(uVar2 + 0xb8);
  uVar3 = FUN_80017a98();
  FUN_80006818((double)lbl_803E5D78,uVar2,0x3af,10);
  FUN_800068c4(uVar2,0x3af);
  *(undefined *)(param_11 + 0x56) = 0;
  for (iVar8 = 0; iVar8 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar8 = iVar8 + 1) {
    if (*(char *)(param_11 + iVar8 + 0x81) == '\x01') {
      FUN_80006b54(0x1d,0x3c);
      FUN_80006b50();
      *(byte *)(piVar7 + 8) = *(byte *)(piVar7 + 8) & 0xbf;
      *(uint *)(*(int *)(uVar2 + 100) + 0x30) = *(uint *)(*(int *)(uVar2 + 100) + 0x30) | 4;
    }
  }
  if ((*(byte *)(piVar7 + 8) >> 6 & 1) == 0) {
    if (*piVar7 == 0) {
      iVar8 = FUN_80017b00(local_74,&local_78);
      while ((local_74[0] < local_78 &&
             (*piVar7 = *(int *)(iVar8 + local_74[0] * 4), *(short *)(*piVar7 + 0x46) != 0x20f))) {
        local_74[0] = local_74[0] + 1;
      }
    }
    if (*piVar7 != 0) {
      dVar10 = (double)lbl_803E5D80;
      dVar12 = (double)lbl_803E5D90;
      dVar9 = (double)lbl_803E5D98;
      dVar11 = DOUBLE_803e5da8;
      for (iVar8 = 0; iVar8 < (int)(uint)DAT_803dc070; iVar8 = iVar8 + 1) {
        bVar6 = FUN_80006b44();
        if (bVar6 != 0) {
          FUN_80006824(uVar2,0x1d4);
          *(byte *)(piVar7 + 8) = *(byte *)(piVar7 + 8) & 0x7f;
          *(byte *)(piVar7 + 8) = *(byte *)(piVar7 + 8) & 0xbf | 0x40;
          (**(code **)(*DAT_803dd6d4 + 0x58))(param_11,0xbd);
        }
        uVar5 = FUN_80006bf8(0);
        if ((uVar5 & 0x100) != 0) {
          piVar7[1] = (int)((float)piVar7[1] + lbl_803E5D7C);
        }
        if (dVar10 < (double)(float)piVar7[1]) {
          piVar7[1] = (int)(float)dVar10;
        }
        local_74[2] = piVar7[4] ^ 0x80000000;
        local_74[1] = 0x43300000;
        iVar4 = (int)((float)((double)CONCAT44(0x43300000,local_74[2]) - dVar11) + (float)piVar7[1])
        ;
        local_68 = (double)(longlong)iVar4;
        piVar7[4] = iVar4;
        if (0x7ef3 < piVar7[4]) {
          FUN_80006b4c();
          FUN_80006824(uVar2,0x1d4);
          FUN_800305f8((double)lbl_803E5D84,param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8,uVar3,0,0,param_12,param_13,param_14,param_15,param_16);
          *(byte *)(piVar7 + 8) = *(byte *)(piVar7 + 8) & 0x7f | 0x80;
          *(byte *)(piVar7 + 8) = *(byte *)(piVar7 + 8) & 0xbf | 0x40;
          piVar7[4] = 0x7ef4;
          (**(code **)(*DAT_803dd6d4 + 0x58))(param_11,0xbd);
          goto LAB_801ca1b0;
        }
        (**(code **)(*DAT_803dd6d4 + 0x74))(piVar7[6]);
        if (piVar7[4] < 0) {
          piVar7[4] = 0;
          if ((float)piVar7[1] < lbl_803E5D84) {
            piVar7[1] = (int)lbl_803E5D84;
          }
          piVar7[5] = piVar7[4];
          if (lbl_803E5D88 < (float)piVar7[1]) {
            piVar7[1] = (int)((float)piVar7[1] - lbl_803E5D8C);
          }
          goto LAB_801ca1b0;
        }
        if (dVar12 < (double)(float)piVar7[1]) {
          piVar7[1] = (int)(float)((double)(float)piVar7[1] - (double)lbl_803E5D94);
        }
        local_68 = (double)CONCAT44(0x43300000,piVar7[4] ^ 0x80000000);
        local_74[2] = piVar7[5] ^ 0x80000000;
        local_74[1] = 0x43300000;
        param_2 = (double)lbl_803DC074;
        iVar4 = FUN_8002fc3c((double)(float)((double)((float)(local_68 - dVar11) -
                                                     (float)((double)CONCAT44(0x43300000,local_74[2]
                                                                             ) - dVar11)) / dVar9),
                             param_2);
        if ((iVar4 != 0) && (*(float *)(uVar3 + 0x98) < lbl_803E5D84)) {
          *(float *)(uVar3 + 0x98) = lbl_803E5D9C + *(float *)(uVar3 + 0x98);
        }
        if (*piVar7 != 0) {
          local_68 = (double)CONCAT44(0x43300000,piVar7[4] ^ 0x80000000);
          local_74[2] = piVar7[5] ^ 0x80000000;
          local_74[1] = 0x43300000;
          param_2 = (double)lbl_803DC074;
          iVar4 = FUN_8002fc3c((double)(-((float)(local_68 - DOUBLE_803e5da8) -
                                         (float)((double)CONCAT44(0x43300000,local_74[2]) -
                                                DOUBLE_803e5da8)) / lbl_803E5D98),param_2);
          if (iVar4 != 0) {
            fVar1 = *(float *)(*piVar7 + 0x98);
            if (fVar1 < lbl_803E5D84) {
              *(float *)(*piVar7 + 0x98) = lbl_803E5D9C + fVar1;
            }
          }
        }
        piVar7[5] = piVar7[4];
      }
      piVar7[3] = (int)((float)piVar7[3] - lbl_803DC074);
      if ((float)piVar7[3] < lbl_803E5D84) {
        if (lbl_803E5D84 <= (float)piVar7[1]) {
          uVar5 = FUN_80017760(0x78,0xf0);
          local_68 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          piVar7[3] = (int)(float)(local_68 - DOUBLE_803e5da8);
        }
        else {
          uVar5 = FUN_80017760(0x28,100);
          local_68 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          piVar7[3] = (int)(float)(local_68 - DOUBLE_803e5da8);
        }
        FUN_80006824(uVar3,0x13a);
      }
      piVar7[2] = (int)((float)piVar7[2] - lbl_803DC074);
      if ((float)piVar7[2] < lbl_803E5D84) {
        if ((float)piVar7[1] <= lbl_803E5D84) {
          uVar3 = FUN_80017760(0x78,0xf0);
          local_68 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
          piVar7[2] = (int)(float)(local_68 - DOUBLE_803e5da8);
        }
        else {
          uVar3 = FUN_80017760(0x28,100);
          local_68 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
          piVar7[2] = (int)(float)(local_68 - DOUBLE_803e5da8);
        }
        FUN_80006824(uVar2,0x4a3);
      }
      fVar1 = lbl_803E5DA0 * (float)piVar7[1];
      if (fVar1 < lbl_803E5D84) {
        fVar1 = -fVar1;
      }
      iVar8 = (int)fVar1;
      local_68 = (double)(longlong)iVar8;
      if (100 < iVar8) {
        iVar8 = 100;
      }
      FUN_80006818((double)lbl_803E5D78,uVar2,0x3af,(byte)iVar8);
    }
  }
LAB_801ca1b0:
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c9f44
 * EN v1.0 Address: 0x801C9F44
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801CA1F0
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c9f44(void)
{
  FUN_80006b4c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c9f64
 * EN v1.0 Address: 0x801C9F64
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801CA210
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c9f64(int param_1)
{
  FUN_8003b818(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c9f84
 * EN v1.0 Address: 0x801C9F84
 * EN v1.0 Size: 348b
 * EN v1.1 Address: 0x801CA234
 * EN v1.1 Size: 484b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c9f84(uint param_1)
{
  short sVar1;
  uint uVar2;
  undefined4 uVar3;
  undefined4 *puVar4;
  
  puVar4 = *(undefined4 **)(param_1 + 0xb8);
  uVar2 = FUN_80017690(0x16a);
  if (uVar2 == 0) {
    *(undefined2 *)((int)puVar4 + 0x1e) = 0;
    *puVar4 = 0;
    FUN_80017698(0x16c,0);
  }
  else {
    sVar1 = *(short *)((int)puVar4 + 0x1e);
    if (sVar1 == 0) {
      *(uint *)(*(int *)(param_1 + 100) + 0x30) =
           *(uint *)(*(int *)(param_1 + 100) + 0x30) & 0xfffffffb;
      *(undefined2 *)((int)puVar4 + 0x1e) = 1;
    }
    else if (sVar1 == 2) {
      *(undefined2 *)((int)puVar4 + 0x1e) = 3;
      uVar3 = (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
      puVar4[6] = uVar3;
    }
    else if (sVar1 == 1) {
      if (DAT_803dcbd0 != '\0') {
        DAT_803dcbd0 = 0;
        FUN_80006824(param_1,0x1d4);
      }
      *(undefined2 *)((int)puVar4 + 0x1e) = 2;
      DAT_803dcbd0 = '\x01';
    }
    else if (sVar1 == 3) {
      *(uint *)(*(int *)(param_1 + 100) + 0x30) =
           *(uint *)(*(int *)(param_1 + 100) + 0x30) & 0xfffffffb;
      if (*(char *)(puVar4 + 8) < '\0') {
        FUN_80017698(0x16b,1);
      }
      else {
        FUN_80017698(0x16c,1);
      }
      FUN_8000680c(param_1,0x7f);
      *(byte *)(puVar4 + 8) = *(byte *)(puVar4 + 8) & 0xbf | 0x40;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: dbsh_symbol_getExtraSize
 * EN v1.0 Address: 0x801C9C34
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dbsh_symbol_getExtraSize(void)
{
  return 0x24;
}

extern void gameTimerStop(void);

/*
 * --INFO--
 *
 * Function: dbsh_symbol_free
 * EN v1.0 Address: 0x801C9C3C
 * EN v1.0 Size: 32b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dbsh_symbol_free(void)
{
  gameTimerStop();
}

/*
 * --INFO--
 *
 * Function: FUN_801ca0e0
 * EN v1.0 Address: 0x801CA0E0
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x801CA418
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ca0e0(undefined4 param_1)
{
  (**(code **)(*DAT_803dd6fc + 0x18))();
  (**(code **)(*DAT_803dd6f8 + 0x18))(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ca13c
 * EN v1.0 Address: 0x801CA13C
 * EN v1.0 Size: 596b
 * EN v1.1 Address: 0x801CA46C
 * EN v1.1 Size: 588b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ca13c(int param_1)
{
  float fVar1;
  undefined2 *puVar2;
  int iVar3;
  uint uVar4;
  char in_r8;
  int iVar5;
  double dVar6;
  undefined8 uVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined4 auStack_68 [2];
  short asStack_60 [4];
  short asStack_58 [4];
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  undefined auStack_2c [12];
  float local_20;
  float local_1c;
  float local_18;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  if (in_r8 == '\0') {
    *(undefined2 *)(iVar5 + 4) = 0;
    *(undefined *)(iVar5 + 10) = 0;
  }
  else if (*(char *)(iVar5 + 0xc) != '\0') {
    *(undefined *)(iVar5 + 10) = 1;
    puVar2 = FUN_800069a8();
    local_38 = *(float *)(puVar2 + 6) - *(float *)(param_1 + 0xc);
    local_34 = *(float *)(puVar2 + 8) - *(float *)(param_1 + 0x10);
    local_30 = *(float *)(puVar2 + 10) - *(float *)(param_1 + 0x14);
    dVar6 = FUN_80293900((double)(local_30 * local_30 + local_38 * local_38 + local_34 * local_34));
    if ((double)lbl_803E5DB8 < dVar6) {
      fVar1 = (float)((double)lbl_803E5DBC / dVar6);
      local_38 = local_38 * fVar1;
      dVar12 = (double)local_38;
      local_34 = local_34 * fVar1;
      dVar11 = (double)local_34;
      local_30 = local_30 * fVar1;
      dVar10 = (double)local_30;
      dVar6 = (double)lbl_803E5DC0;
      local_44 = (float)(dVar6 * dVar12) + *(float *)(param_1 + 0xc);
      local_40 = (float)(dVar6 * dVar11) + *(float *)(param_1 + 0x10);
      local_3c = (float)(dVar6 * dVar10) + *(float *)(param_1 + 0x14);
      dVar6 = (double)lbl_803E5DC4;
      dVar9 = (double)(float)(dVar6 * dVar12);
      dVar8 = (double)(float)(dVar6 * dVar11);
      local_50 = (float)(dVar9 + (double)*(float *)(puVar2 + 6));
      local_4c = (float)(dVar8 + (double)*(float *)(puVar2 + 8));
      local_48 = (float)(dVar6 * dVar10) + *(float *)(puVar2 + 10);
      FUN_80006a68(&local_44,asStack_58);
      uVar7 = FUN_80006a68(&local_50,asStack_60);
      iVar3 = FUN_80006a64(uVar7,dVar8,dVar9,dVar10,dVar11,dVar12,in_f7,in_f8,asStack_58,asStack_60,
                           auStack_68,(undefined *)0x0,0);
      if (iVar3 == 0) {
        *(undefined *)(iVar5 + 10) = 0;
        (**(code **)(*DAT_803dd6f8 + 0x14))(param_1);
      }
    }
    if (*(short *)(iVar5 + 4) < 1) {
      if (*(char *)(iVar5 + 10) != '\0') {
        local_20 = lbl_803E5DC8;
        local_1c = lbl_803E5DCC;
        local_18 = lbl_803E5DC8;
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x1f7,auStack_2c,0x12,0xffffffff,0);
      }
      uVar4 = FUN_80017760(0xfffffff6,10);
      *(short *)(iVar5 + 4) = (short)uVar4 + 0x3c;
    }
    else {
      *(ushort *)(iVar5 + 4) = *(short *)(iVar5 + 4) - (ushort)DAT_803dc070;
    }
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void fn_801CA104(void) {}

/* 8b "li r3, N; blr" returners. */
int fn_801C9E54(void) { return 0x10; }
int fn_801C9E5C(void) { return 0x1; }

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E5104;
extern void objRenderFn_8003b8f4(f32);
#pragma scheduling off
#pragma peephole off
void dbsh_symbol_render(void) { objRenderFn_8003b8f4(lbl_803E5104); }
#pragma peephole reset
#pragma scheduling reset
