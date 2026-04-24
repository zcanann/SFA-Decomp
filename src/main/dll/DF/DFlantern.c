#include "ghidra_import.h"
#include "main/dll/DF/DFlantern.h"

extern uint FUN_80020078();
extern int FUN_80021884();
extern undefined4 FUN_8002e1f4();
extern undefined4 FUN_800372f8();
extern undefined4 FUN_800395a4();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_80054484();
extern undefined4 FUN_80054ed0();
extern undefined4 FUN_801c158c();
extern int FUN_801c17ec();
extern undefined4 FUN_801c21a4();
extern double FUN_80293900();
extern undefined4 FUN_80294964();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dcba8;
extern undefined4 DAT_803dcbb0;
extern undefined4 DAT_803dcbb8;
extern undefined4 DAT_803dcbc0;
extern f32 FLOAT_803e5a94;
extern f32 FLOAT_803e5abc;
extern f32 FLOAT_803e5ac0;
extern f32 FLOAT_803e5ac8;
extern f32 FLOAT_803e5acc;
extern f32 FLOAT_803e5ad0;

/*
 * --INFO--
 *
 * Function: FUN_801c282c
 * EN v1.0 Address: 0x801C282C
 * EN v1.0 Size: 1244b
 * EN v1.1 Address: 0x801C282C
 * EN v1.1 Size: 824b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c282c(int param_1)
{
  float fVar1;
  short sVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  int local_78;
  int local_74;
  
  iVar6 = *(int *)(param_1 + 0x4c);
  if ((*(byte *)(iVar6 + 0x18) & 1) != 0) {
    if (**(int **)(param_1 + 0xb8) == 0) {
      piVar3 = (int *)FUN_8002e1f4(&local_78,&local_74);
      local_78 = 0;
      iVar5 = 0;
      while ((local_78 < local_74 && (iVar5 == 0))) {
        iVar4 = *piVar3;
        if ((*(short *)(iVar4 + 0x44) == 0x36) &&
           ((uint)*(byte *)(iVar6 + 0x18) == *(byte *)(*(int *)(iVar4 + 0x4c) + 0x18) - 1)) {
          iVar5 = iVar4;
        }
        piVar3 = piVar3 + 1;
        local_78 = local_78 + 1;
      }
      if (iVar5 == 0) {
        return;
      }
      **(int **)(iVar5 + 0xb8) = param_1;
      piVar3 = *(int **)(param_1 + 0xb8);
      *piVar3 = iVar5;
      dVar9 = (double)(*(float *)(iVar5 + 0xc) - *(float *)(param_1 + 0xc));
      dVar10 = (double)(*(float *)(iVar5 + 0x10) - *(float *)(param_1 + 0x10));
      dVar12 = (double)(*(float *)(iVar5 + 0x14) - *(float *)(param_1 + 0x14));
      dVar7 = FUN_80293900((double)(float)(dVar12 * dVar12 +
                                          (double)(float)(dVar9 * dVar9 +
                                                         (double)(float)(dVar10 * dVar10))));
      iVar4 = FUN_80021884();
      sVar2 = (short)iVar4;
      if (0x8000 < sVar2) {
        sVar2 = sVar2 + 1;
      }
      if (sVar2 < -0x8000) {
        sVar2 = sVar2 + -1;
      }
      *(short *)(piVar3 + 6) = sVar2;
      dVar8 = (double)FLOAT_803e5a94;
      iVar6 = FUN_801c17ec(dVar8,dVar8,dVar8,dVar9,dVar10,dVar12,dVar7,
                           (double)*(float *)(&DAT_803dcbb8 + (uint)*(byte *)(iVar6 + 0x1b) * 4));
      piVar3[0xb] = iVar6;
      piVar3[1] = *(int *)(param_1 + 0xc);
      piVar3[3] = *(int *)(param_1 + 0x14);
      piVar3[2] = *(int *)(iVar5 + 0xc);
      piVar3[4] = *(int *)(iVar5 + 0x14);
      fVar1 = (float)piVar3[1];
      if ((float)piVar3[2] < fVar1) {
        piVar3[1] = piVar3[2];
        piVar3[2] = (int)fVar1;
      }
      fVar1 = (float)piVar3[3];
      if ((float)piVar3[4] < fVar1) {
        piVar3[3] = piVar3[4];
        piVar3[4] = (int)fVar1;
      }
      fVar1 = FLOAT_803e5abc;
      piVar3[1] = (int)((float)piVar3[1] - FLOAT_803e5abc);
      piVar3[3] = (int)((float)piVar3[3] - fVar1);
      piVar3[2] = (int)((float)piVar3[2] + fVar1);
      piVar3[4] = (int)((float)piVar3[4] + fVar1);
      dVar14 = (double)*(float *)(param_1 + 0xc);
      dVar13 = (double)*(float *)(param_1 + 0x10);
      dVar11 = (double)*(float *)(param_1 + 0x14);
      dVar7 = (double)*(float *)(iVar5 + 0xc);
      dVar9 = (double)*(float *)(iVar5 + 0x10);
      dVar10 = (double)*(float *)(iVar5 + 0x14);
      dVar12 = (double)(float)((double)FLOAT_803e5ac0 + dVar13);
      dVar8 = (double)(float)(dVar12 * (double)(float)(dVar11 - dVar10) +
                             (double)(float)(dVar13 * (double)(float)(dVar10 - dVar11) +
                                            (double)(float)(dVar9 * (double)(float)(dVar11 - dVar11)
                                                           )));
      dVar10 = (double)(float)(dVar11 * (double)(float)(dVar14 - dVar7) +
                              (double)(float)(dVar11 * (double)(float)(dVar7 - dVar14) +
                                             (double)(float)(dVar10 * (double)(float)(dVar14 - 
                                                  dVar14))));
      dVar9 = (double)(float)(dVar14 * (double)(float)(dVar13 - dVar9) +
                             (double)(float)(dVar14 * (double)(float)(dVar9 - dVar12) +
                                            (double)(float)(dVar7 * (double)(float)(dVar12 - dVar13)
                                                           )));
      dVar7 = FUN_80293900((double)(float)(dVar9 * dVar9 +
                                          (double)(float)(dVar8 * dVar8 +
                                                         (double)(float)(dVar10 * dVar10))));
      if ((double)FLOAT_803e5a94 < dVar7) {
        dVar8 = (double)(float)(dVar8 / dVar7);
        dVar10 = (double)(float)(dVar10 / dVar7);
        dVar9 = (double)(float)(dVar9 / dVar7);
      }
      piVar3[7] = (int)(float)dVar8;
      piVar3[8] = (int)(float)dVar10;
      piVar3[9] = (int)(float)dVar9;
      piVar3[10] = (int)-(float)(dVar11 * dVar9 +
                                (double)(float)(dVar14 * dVar8 + (double)(float)(dVar13 * dVar10)));
    }
    FUN_801c158c();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c2b64
 * EN v1.0 Address: 0x801C2D08
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801C2B64
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c2b64(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801c2be8
 * EN v1.0 Address: 0x801C2D0C
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x801C2BE8
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c2be8(void)
{
  int iVar1;
  
  iVar1 = 0;
  do {
    FUN_80054484();
    iVar1 = iVar1 + 1;
  } while (iVar1 < 2);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c2c34
 * EN v1.0 Address: 0x801C2D44
 * EN v1.0 Size: 276b
 * EN v1.1 Address: 0x801C2C34
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c2c34(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  iVar2 = 0;
  puVar4 = (undefined4 *)&DAT_803dcba8;
  puVar3 = (undefined4 *)&DAT_803dcbb0;
  do {
    uVar1 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*puVar4,
                         param_10,param_11,param_12,param_13,param_14,param_15,param_16);
    *puVar3 = uVar1;
    puVar4 = puVar4 + 1;
    puVar3 = puVar3 + 1;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 2);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c2c94
 * EN v1.0 Address: 0x801C2E58
 * EN v1.0 Size: 272b
 * EN v1.1 Address: 0x801C2C94
 * EN v1.1 Size: 336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801c2c94(int param_1)
{
  uint uVar1;
  int *piVar2;
  int iVar3;
  short *psVar4;
  double dVar5;
  
  psVar4 = *(short **)(param_1 + 0xb8);
  if (*(char *)((int)psVar4 + 3) == '\x01') {
    piVar2 = (int *)FUN_800395a4(param_1,0);
    if (piVar2 != (int *)0x0) {
      iVar3 = *piVar2 + (uint)DAT_803dc070 * 0x10;
      if (0x100 < iVar3) {
        iVar3 = 0x100;
        *(undefined *)((int)psVar4 + 3) = 2;
      }
      *piVar2 = iVar3;
    }
  }
  else if (*(char *)((int)psVar4 + 3) == '\0') {
    uVar1 = FUN_80020078((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x22));
    if (uVar1 != 0) {
      *(undefined *)((int)psVar4 + 3) = 1;
    }
  }
  else {
    piVar2 = (int *)FUN_800395a4(param_1,0);
    if (piVar2 != (int *)0x0) {
      *psVar4 = *psVar4 + (ushort)DAT_803dc070 * 800;
      dVar5 = (double)FUN_80294964();
      *piVar2 = (int)-(FLOAT_803e5acc * (float)((double)FLOAT_803e5ad0 - dVar5) - FLOAT_803e5ac8);
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801c2de4
 * EN v1.0 Address: 0x801C2F68
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801C2DE4
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c2de4(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c2e1c
 * EN v1.0 Address: 0x801C2F90
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801C2E1C
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c2e1c(int param_1,int param_2)
{
}
