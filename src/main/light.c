#include "ghidra_import.h"
#include "main/light.h"
#include "main/unknown/autos/placeholder_8002F604.h"

extern bool FUN_800067f0();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern void* FUN_800069a8();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006ba8();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_8001771c();
extern undefined4 FUN_80017a78();
extern int FUN_80017a98();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80041ff8();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80044404();
extern undefined4 FUN_80053c98();
extern undefined4 FUN_8008112c();
extern undefined4 FUN_801f5070();
extern undefined4 FUN_80247e94();
extern undefined4 FUN_80247eb8();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_80247ef8();
extern uint FUN_80286838();
extern uint FUN_8028683c();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();

extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de940;
extern f64 DOUBLE_803e6d90;
extern f64 DOUBLE_803e6da8;
extern f64 DOUBLE_803e6dc8;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e6d84;
extern f32 FLOAT_803e6d98;
extern f32 FLOAT_803e6da0;
extern f32 FLOAT_803e6db0;
extern f32 FLOAT_803e6db4;
extern f32 FLOAT_803e6db8;
extern f32 FLOAT_803e6dbc;

/*
 * --INFO--
 *
 * Function: FUN_801fb9f4
 * EN v1.0 Address: 0x801FB9F4
 * EN v1.0 Size: 732b
 * EN v1.1 Address: 0x801FBA6C
 * EN v1.1 Size: 772b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fb9f4(void)
{
  uint uVar1;
  int iVar2;
  uint uVar3;
  short sVar4;
  short sVar5;
  short sVar6;
  short sVar7;
  char cVar8;
  int iVar9;
  int iVar10;
  
  uVar1 = FUN_80286838();
  iVar10 = *(int *)(uVar1 + 0x4c);
  iVar9 = *(int *)(uVar1 + 0xb8);
  iVar2 = FUN_80017a98();
  *(byte *)(uVar1 + 0xaf) = *(byte *)(uVar1 + 0xaf) | 8;
  if (iVar2 != 0) {
    uVar3 = FUN_80017690(0x507);
    sVar4 = (short)uVar3;
    uVar3 = FUN_80017690(0x508);
    sVar5 = (short)uVar3;
    uVar3 = FUN_80017690(0x509);
    sVar6 = (short)uVar3;
    uVar3 = FUN_80017690(0x50a);
    sVar7 = (short)uVar3;
    cVar8 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(uVar1 + 0xac));
    if (cVar8 == '\x02') {
      sVar4 = 1;
      sVar5 = 1;
      sVar6 = 1;
      sVar7 = 1;
    }
    if ((((sVar4 != 0) && (sVar5 != 0)) && (sVar6 != 0)) &&
       (((sVar7 != 0 && (*(short *)(iVar9 + 10) == 0)) && (uVar3 = FUN_80017690(0x4ee), uVar3 == 0))
       )) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(4,uVar1,0xffffffff);
      FUN_80017698(0x4ee,1);
    }
    if (((char)*(byte *)(iVar9 + 0x1c) < '\0') ||
       (((*(byte *)(iVar9 + 0x1c) >> 6 & 1) != 0 && (*(short *)(iVar9 + 10) == 0)))) {
      *(float *)(uVar1 + 0x10) = *(float *)(iVar10 + 0xc) + FLOAT_803e6d84;
      *(byte *)(iVar9 + 0x1c) = *(byte *)(iVar9 + 0x1c) & 0x7f;
      *(byte *)(iVar9 + 0x1c) = *(byte *)(iVar9 + 0x1c) & 0xbf;
      *(undefined2 *)(iVar9 + 10) = 4;
    }
    sVar4 = *(short *)(iVar9 + 10);
    if (sVar4 != 0) {
      if (((sVar4 == 4) || (3 < sVar4)) || (sVar4 < 3)) {
        *(byte *)(uVar1 + 0xaf) = *(byte *)(uVar1 + 0xaf) & 0xf7;
        if ((*(byte *)(uVar1 + 0xaf) & 1) == 0) {
          uVar3 = FUN_80017690((int)*(short *)(iVar9 + 0xe));
          if (uVar3 != 0) {
            *(undefined2 *)(iVar9 + 10) = 3;
            *(undefined4 *)(uVar1 + 0x10) = *(undefined4 *)(iVar10 + 0xc);
          }
        }
        else {
          FUN_80006ba8(0,0x100);
          (**(code **)(*DAT_803dd6d4 + 0x48))(1,uVar1,0xffffffff);
          *(undefined2 *)(iVar9 + 10) = 3;
          FUN_80006824(uVar1,0x113);
          FUN_8000680c(uVar1,8);
          FUN_80017698((int)*(short *)(iVar9 + 0xe),1);
        }
      }
      else {
        *(byte *)(uVar1 + 0xaf) = *(byte *)(uVar1 + 0xaf) & 0xf7;
        if ((*(byte *)(uVar1 + 0xaf) & 1) == 0) {
          uVar3 = FUN_80017690((int)*(short *)(iVar9 + 0xe));
          if (uVar3 == 0) {
            *(undefined2 *)(iVar9 + 10) = 4;
            *(float *)(uVar1 + 0x10) = *(float *)(iVar10 + 0xc) + FLOAT_803e6d84;
          }
        }
        else {
          FUN_80006ba8(0,0x100);
          (**(code **)(*DAT_803dd6d4 + 0x48))(0,uVar1,0xffffffff);
          *(undefined2 *)(iVar9 + 10) = 4;
          FUN_80006824(uVar1,0x113);
          FUN_8000680c(uVar1,8);
          FUN_80017698((int)*(short *)(iVar9 + 0xe),0);
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
 * Function: FUN_801fbcd0
 * EN v1.0 Address: 0x801FBCD0
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801FBD70
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fbcd0(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fbd04
 * EN v1.0 Address: 0x801FBD04
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801FBDA0
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fbd04(int param_1)
{
  FUN_8003b818(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fbd24
 * EN v1.0 Address: 0x801FBD24
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x801FBDC4
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fbd24(int param_1)
{
  uint uVar1;
  
  uVar1 = (uint)*(short *)(*(int *)(param_1 + 0xb8) + 0xc);
  if ((uVar1 == 0xffffffff) || (uVar1 = FUN_80017690(uVar1), uVar1 != 0)) {
    if ((*(byte *)(param_1 + 0xaf) & 8) != 0) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) ^ 8;
    }
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fbd90
 * EN v1.0 Address: 0x801FBD90
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x801FBE38
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fbd90(uint param_1)
{
  short sVar1;
  
  FUN_80017a98();
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x3b7) {
    FUN_801fb9f4();
  }
  else if (sVar1 == 0x3bf) {
    FUN_801f5070(param_1);
  }
  else if (sVar1 == 0x53f) {
    FUN_801f5070(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fbdf4
 * EN v1.0 Address: 0x801FBDF4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801FBEA0
 * EN v1.1 Size: 340b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fbdf4(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801fbdf8
 * EN v1.0 Address: 0x801FBDF8
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801FBFF4
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fbdf8(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fbe2c
 * EN v1.0 Address: 0x801FBE2C
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x801FC02C
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fbe2c(uint param_1)
{
  int iVar1;
  bool bVar2;
  double dVar3;
  
  iVar1 = FUN_80017a98();
  dVar3 = (double)FUN_8001771c((float *)(iVar1 + 0x18),(float *)(param_1 + 0x18));
  bVar2 = FUN_800067f0(param_1,0x40);
  if (bVar2) {
    if (dVar3 < (double)FLOAT_803e6d98) {
      FUN_80006824(param_1,0x110);
    }
  }
  else if ((double)FLOAT_803e6d98 <= dVar3) {
    FUN_8000680c(param_1,0x40);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fbed8
 * EN v1.0 Address: 0x801FBED8
 * EN v1.0 Size: 660b
 * EN v1.1 Address: 0x801FC100
 * EN v1.1 Size: 684b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fbed8(int param_1)
{
  byte bVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  short *psVar5;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  psVar5 = *(short **)(param_1 + 0xb8);
  uVar3 = FUN_80017690((int)*psVar5);
  if (uVar3 != 0) {
    *(undefined *)(psVar5 + 1) = 6;
  }
  fVar2 = FLOAT_803e6da0;
  bVar1 = *(byte *)(psVar5 + 1);
  if (bVar1 == 3) {
    if (*(float *)(iVar4 + 0x10) - FLOAT_803e6da0 < *(float *)(param_1 + 0x14)) {
      *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) - FLOAT_803dc074;
      fVar2 = *(float *)(iVar4 + 0x10) - fVar2;
      if (*(float *)(param_1 + 0x14) <= fVar2) {
        *(float *)(param_1 + 0x14) = fVar2;
        *(undefined *)(psVar5 + 1) = 1;
        psVar5[2] = 0x14;
      }
    }
  }
  else if (bVar1 < 3) {
    if (bVar1 == 1) {
      if (psVar5[2] == 0) {
        if (*(char *)((int)psVar5 + 3) == '\0') {
          if (*(float *)(param_1 + 0x14) == *(float *)(iVar4 + 0x10) - FLOAT_803e6da0) {
            *(undefined *)(psVar5 + 1) = 2;
          }
          if (*(float *)(param_1 + 0x14) == FLOAT_803e6da0 + *(float *)(iVar4 + 0x10)) {
            *(undefined *)(psVar5 + 1) = 3;
          }
        }
        else {
          if (*(float *)(param_1 + 0x14) == *(float *)(iVar4 + 0x10) - FLOAT_803e6da0) {
            *(undefined *)(psVar5 + 1) = 4;
          }
          if (*(float *)(param_1 + 0x14) == FLOAT_803e6da0 + *(float *)(iVar4 + 0x10)) {
            *(undefined *)(psVar5 + 1) = 5;
          }
        }
      }
      else {
        psVar5[2] = psVar5[2] - (short)(int)FLOAT_803dc074;
        if (psVar5[2] < 1) {
          psVar5[2] = 0;
        }
      }
    }
    else if (bVar1 == 0) {
      uVar3 = FUN_80017690((int)*psVar5);
      if (uVar3 == 0) {
        *(undefined *)(psVar5 + 1) = 3;
      }
    }
    else if (*(float *)(param_1 + 0x14) < FLOAT_803e6da0 + *(float *)(iVar4 + 0x10)) {
      *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) + FLOAT_803dc074;
      fVar2 = fVar2 + *(float *)(iVar4 + 0x10);
      if (fVar2 <= *(float *)(param_1 + 0x14)) {
        *(float *)(param_1 + 0x14) = fVar2;
        *(undefined *)(psVar5 + 1) = 1;
        psVar5[2] = 0x14;
      }
    }
  }
  else if (bVar1 == 6) {
    fVar2 = *(float *)(param_1 + 0x14);
    if (*(float *)(iVar4 + 0x10) <= fVar2) {
      if (fVar2 <= *(float *)(iVar4 + 0x10)) {
        uVar3 = FUN_80017690((int)*psVar5);
        if (uVar3 == 0) {
          *(undefined *)(psVar5 + 1) = 3;
        }
      }
      else {
        *(float *)(param_1 + 0x14) = fVar2 - FLOAT_803dc074;
        if (*(float *)(param_1 + 0x14) <= *(float *)(iVar4 + 0x10)) {
          *(float *)(param_1 + 0x14) = *(float *)(iVar4 + 0x10);
        }
      }
    }
    else {
      *(float *)(param_1 + 0x14) = fVar2 + FLOAT_803dc074;
      if (*(float *)(iVar4 + 0x10) <= *(float *)(param_1 + 0x14)) {
        *(float *)(param_1 + 0x14) = *(float *)(iVar4 + 0x10);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fc16c
 * EN v1.0 Address: 0x801FC16C
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801FC3AC
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fc16c(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fc1a0
 * EN v1.0 Address: 0x801FC1A0
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x801FC3DC
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fc1a0(int param_1)
{
  char in_r8;
  
  if ((in_r8 != '\0') && (*(char *)(*(int *)(param_1 + 0xb8) + 3) != 'c')) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fc1d8
 * EN v1.0 Address: 0x801FC1D8
 * EN v1.0 Size: 1412b
 * EN v1.1 Address: 0x801FC420
 * EN v1.1 Size: 1424b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fc1d8(void)
{
  uint uVar1;
  char cVar2;
  byte bVar3;
  float fVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  short *psVar9;
  undefined8 local_20;
  
  uVar5 = FUN_8028683c();
  psVar9 = *(short **)(uVar5 + 0xb8);
  cVar2 = *(char *)((int)psVar9 + 3);
  if (cVar2 == '\n') {
    uVar6 = FUN_80017690((int)*psVar9);
    if (uVar6 != 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,uVar5,0xffffffff);
    }
  }
  else {
    fVar4 = *(float *)(uVar5 + 0xc);
    uVar6 = (uint)fVar4;
    uVar1 = (uint)*(float *)(uVar5 + 0x14);
    uVar7 = (uint)*(float *)(*(int *)(uVar5 + 0x4c) + 8);
    uVar8 = (uint)*(float *)(*(int *)(uVar5 + 0x4c) + 0x10);
    if (cVar2 != 'c') {
      if (*(short *)(uVar5 + 0x46) == 0x3c0) {
        FUN_801fbed8(uVar5);
      }
      else {
        bVar3 = *(byte *)(psVar9 + 1);
        if (bVar3 == 3) {
          if ((cVar2 == '\x03') && (uVar7 = uVar7 - 0x3c, (int)uVar7 < (int)uVar6)) {
            *(float *)(uVar5 + 0xc) = fVar4 - FLOAT_803dc074;
            if ((int)*(float *)(uVar5 + 0xc) <= (int)uVar7) {
              local_20 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              *(float *)(uVar5 + 0xc) = (float)(local_20 - DOUBLE_803e6da8);
              *(undefined *)(psVar9 + 1) = 1;
              psVar9[2] = 200;
            }
          }
          else {
            uVar8 = uVar8 - 0x3c;
            if (((int)uVar8 < (int)uVar1) &&
               (*(float *)(uVar5 + 0x14) = *(float *)(uVar5 + 0x14) - FLOAT_803dc074,
               (int)*(float *)(uVar5 + 0x14) <= (int)uVar8)) {
              local_20 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
              *(float *)(uVar5 + 0x14) = (float)(local_20 - DOUBLE_803e6da8);
              *(undefined *)(psVar9 + 1) = 1;
              psVar9[2] = 200;
            }
          }
        }
        else if (bVar3 < 3) {
          if (bVar3 == 1) {
            if (psVar9[2] == 0) {
              if (cVar2 == '\0') {
                if (uVar1 == uVar8 - 0x3c) {
                  *(undefined *)(psVar9 + 1) = 2;
                  FUN_80006824(uVar5,0x115);
                }
                if (uVar1 == uVar8) {
                  *(undefined *)(psVar9 + 1) = 3;
                  FUN_80006824(uVar5,0x115);
                }
              }
              else if (cVar2 == '\x03') {
                if (uVar6 == uVar7 - 0x3c) {
                  *(undefined *)(psVar9 + 1) = 2;
                  FUN_80006824(uVar5,0x115);
                }
                if (uVar6 == uVar7) {
                  *(undefined *)(psVar9 + 1) = 3;
                  FUN_80006824(uVar5,0x115);
                }
              }
              else {
                if (uVar1 == uVar8 + 0x3c) {
                  *(undefined *)(psVar9 + 1) = 4;
                  FUN_80006824(uVar5,0x115);
                }
                if (uVar1 == uVar8) {
                  *(undefined *)(psVar9 + 1) = 5;
                  FUN_80006824(uVar5,0x115);
                }
              }
            }
            else {
              psVar9[2] = psVar9[2] - (short)(int)FLOAT_803dc074;
              if (psVar9[2] < 1) {
                psVar9[2] = 0;
              }
            }
          }
          else if (bVar3 == 0) {
            uVar5 = FUN_80017690((int)*psVar9);
            if (uVar5 != 0) {
              *(undefined *)(psVar9 + 1) = 1;
            }
          }
          else if ((cVar2 == '\x03') && ((int)uVar6 < (int)uVar7)) {
            *(float *)(uVar5 + 0xc) = fVar4 + FLOAT_803dc074;
            if ((int)uVar7 <= (int)*(float *)(uVar5 + 0xc)) {
              local_20 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              *(float *)(uVar5 + 0xc) = (float)(local_20 - DOUBLE_803e6da8);
              *(undefined *)(psVar9 + 1) = 1;
            }
          }
          else if (((int)uVar1 < (int)uVar8) &&
                  (*(float *)(uVar5 + 0x14) = *(float *)(uVar5 + 0x14) + FLOAT_803dc074,
                  (int)uVar8 <= (int)*(float *)(uVar5 + 0x14))) {
            local_20 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
            *(float *)(uVar5 + 0x14) = (float)(local_20 - DOUBLE_803e6da8);
            *(undefined *)(psVar9 + 1) = 1;
          }
        }
        else if (bVar3 == 5) {
          if ((cVar2 == '\x03') && (uVar7 = uVar7 + 0x3c, (int)uVar6 < (int)uVar7)) {
            *(float *)(uVar5 + 0xc) = fVar4 + FLOAT_803dc074;
            if ((int)uVar7 <= (int)*(float *)(uVar5 + 0xc)) {
              local_20 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              *(float *)(uVar5 + 0xc) = (float)(local_20 - DOUBLE_803e6da8);
              *(undefined *)(psVar9 + 1) = 1;
              psVar9[2] = 200;
            }
          }
          else {
            uVar8 = uVar8 + 0x3c;
            if (((int)uVar1 < (int)uVar8) &&
               (*(float *)(uVar5 + 0x14) = *(float *)(uVar5 + 0x14) + FLOAT_803dc074,
               (int)uVar8 <= (int)*(float *)(uVar5 + 0x14))) {
              local_20 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
              *(float *)(uVar5 + 0x14) = (float)(local_20 - DOUBLE_803e6da8);
              *(undefined *)(psVar9 + 1) = 1;
              psVar9[2] = 200;
            }
          }
        }
        else if (bVar3 < 5) {
          if ((cVar2 == '\x03') && ((int)uVar7 < (int)uVar6)) {
            *(float *)(uVar5 + 0xc) = fVar4 - FLOAT_803dc074;
            if ((int)*(float *)(uVar5 + 0xc) <= (int)uVar7) {
              local_20 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              *(float *)(uVar5 + 0xc) = (float)(local_20 - DOUBLE_803e6da8);
              *(undefined *)(psVar9 + 1) = 1;
            }
          }
          else if (((int)uVar8 < (int)uVar1) &&
                  (*(float *)(uVar5 + 0x14) = *(float *)(uVar5 + 0x14) - FLOAT_803dc074,
                  (int)*(float *)(uVar5 + 0x14) <= (int)uVar8)) {
            local_20 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
            *(float *)(uVar5 + 0x14) = (float)(local_20 - DOUBLE_803e6da8);
            *(undefined *)(psVar9 + 1) = 1;
          }
        }
      }
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fc75c
 * EN v1.0 Address: 0x801FC75C
 * EN v1.0 Size: 488b
 * EN v1.1 Address: 0x801FC9B0
 * EN v1.1 Size: 396b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fc75c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  undefined2 *puVar1;
  uint uVar2;
  short *psVar3;
  double dVar4;
  float afStack_28 [7];
  
  psVar3 = *(short **)(param_9 + 0xb8);
  puVar1 = FUN_800069a8();
  if ((-1 < *(char *)(psVar3 + 1)) && (uVar2 = FUN_80017690((int)*psVar3), uVar2 != 0)) {
    FUN_80006824(0,0x109);
    FUN_80006824(param_9,0x10d);
    FUN_80006824(param_9,0x494);
    *(byte *)(psVar3 + 1) = *(byte *)(psVar3 + 1) & 0x7f | 0x80;
  }
  if (*(char *)(psVar3 + 1) < '\0') {
    dVar4 = (double)FLOAT_803dc074;
    ObjAnim_AdvanceCurrentMove((double)FLOAT_803e6db0,dVar4,param_9,(float *)0x0);
    if ((*(byte *)(psVar3 + 1) >> 6 & 1) == 0) {
      if (FLOAT_803e6db4 <= *(float *)(param_9 + 0x98)) {
        FUN_80247eb8((float *)(puVar1 + 6),(float *)(param_9 + 0xc),afStack_28);
        FUN_80247ef8(afStack_28,afStack_28);
        FUN_80247edc((double)FLOAT_803e6db8,afStack_28,afStack_28);
        FUN_80247e94((float *)(param_9 + 0xc),afStack_28,(float *)(param_9 + 0xc));
        *(undefined4 *)(param_9 + 0x18) = *(undefined4 *)(param_9 + 0xc);
        *(undefined4 *)(param_9 + 0x1c) = *(undefined4 *)(param_9 + 0x10);
        *(undefined4 *)(param_9 + 0x20) = *(undefined4 *)(param_9 + 0x14);
        FUN_8008112c((double)FLOAT_803e6dbc,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,1,1,0,0,0,0,0);
        *(byte *)(psVar3 + 1) = *(byte *)(psVar3 + 1) & 0xbf | 0x40;
        *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) | 0x4000;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fc944
 * EN v1.0 Address: 0x801FC944
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801FCB3C
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fc944(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fc978
 * EN v1.0 Address: 0x801FC978
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801FCB6C
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fc978(int param_1)
{
  FUN_8003b818(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fc998
 * EN v1.0 Address: 0x801FC998
 * EN v1.0 Size: 604b
 * EN v1.1 Address: 0x801FCB94
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fc998(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  uint uVar1;
  short *psVar2;
  
  if (*(short *)(param_9 + 0x46) == 999) {
    psVar2 = *(short **)(param_9 + 0xb8);
    if ((-1 < *(char *)(psVar2 + 1)) && (uVar1 = FUN_80017690((int)*psVar2), uVar1 != 0)) {
      FUN_80006824(0,0x109);
      FUN_80006824(param_9,0x10d);
      FUN_80006824(param_9,0x494);
      FUN_80017a78(param_9,1);
      *(byte *)(psVar2 + 1) = *(byte *)(psVar2 + 1) & 0x7f | 0x80;
    }
  }
  else {
    FUN_801fc75c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fcbf4
 * EN v1.0 Address: 0x801FCBF4
 * EN v1.0 Size: 216b
 * EN v1.1 Address: 0x801FCC3C
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fcbf4(undefined2 *param_1,int param_2)
{
  uint uVar1;
  short *psVar2;
  
  psVar2 = *(short **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[2] = (short)((int)*(char *)(param_2 + 0x19) << 8);
  param_1[1] = *(undefined2 *)(param_2 + 0x1c);
  *psVar2 = *(short *)(param_2 + 0x1e);
  uVar1 = FUN_80017690((int)*psVar2);
  if (uVar1 != 0) {
    ObjAnim_SetMoveProgress((double)FLOAT_803e6db4,(int)param_1);
    *(byte *)(psVar2 + 1) = *(byte *)(psVar2 + 1) & 0x7f | 0x80;
    *(byte *)(psVar2 + 1) = *(byte *)(psVar2 + 1) & 0xbf | 0x40;
    param_1[3] = param_1[3] | 0x4000;
  }
  if ((param_1[0x23] == 999) && (*(char *)(psVar2 + 1) < '\0')) {
    *(undefined *)((int)param_1 + 0xad) = 1;
  }
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fcccc
 * EN v1.0 Address: 0x801FCCCC
 * EN v1.0 Size: 1016b
 * EN v1.1 Address: 0x801FCD2C
 * EN v1.1 Size: 644b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801fcccc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  char cVar2;
  undefined4 uVar1;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined8 extraout_f1;
  undefined8 uVar7;
  undefined8 extraout_f1_00;
  
  iVar6 = *(int *)(param_9 + 0xb8);
  *(undefined2 *)(param_11 + 0x70) = 0xffff;
  *(undefined *)(param_11 + 0x56) = 0;
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar5 = iVar5 + 1) {
    if ((*(short *)(iVar6 + 8) == 0xd) && (*(char *)(param_11 + iVar5 + 0x81) == '\x14')) {
      FUN_80017698(0x500,0);
      FUN_80017698(0xd72,1);
      FUN_80017698(0xd44,1);
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),1,1);
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),2,1);
      iVar4 = *DAT_803dd72c;
      (**(code **)(iVar4 + 0x50))((int)*(char *)(param_9 + 0xac),0x16,1);
      cVar2 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_9 + 0xac));
      if (cVar2 == '\x01') {
        uVar7 = extraout_f1;
        FUN_80042b9c(0,0,1);
        uVar1 = FUN_80044404(0x46);
        FUN_80042bec(uVar1,1);
        uVar1 = FUN_80044404(4);
        FUN_80042bec(uVar1,0);
        FUN_80041ff8(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x46);
        iVar3 = *DAT_803dd72c;
        uVar7 = (**(code **)(iVar3 + 0x44))(0x12,2);
        FUN_80053c98(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x7c,'\0',iVar3,
                     iVar4,param_13,param_14,param_15,param_16);
      }
      else {
        cVar2 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_9 + 0xac));
        if (cVar2 == '\x02') {
          uVar7 = extraout_f1_00;
          FUN_80042b9c(0,0,1);
          uVar1 = FUN_80044404(0x46);
          FUN_80042bec(uVar1,1);
          uVar1 = FUN_80044404(4);
          FUN_80042bec(uVar1,0);
          FUN_80041ff8(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x46);
          (**(code **)(*DAT_803dd72c + 0x44))(0xb,4);
          iVar3 = *DAT_803dd72c;
          uVar7 = (**(code **)(iVar3 + 0x44))(8,6);
          FUN_80053c98(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x7c,'\0',iVar3
                       ,iVar4,param_13,param_14,param_15,param_16);
        }
      }
    }
    *(undefined *)(param_11 + iVar5 + 0x81) = 0;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801fd0c4
 * EN v1.0 Address: 0x801FD0C4
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801FCFB0
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fd0c4(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fd0ec
 * EN v1.0 Address: 0x801FD0EC
 * EN v1.0 Size: 796b
 * EN v1.1 Address: 0x801FCFE4
 * EN v1.1 Size: 688b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fd0ec(int param_1)
{
  byte bVar1;
  int iVar2;
  uint uVar3;
  float *pfVar4;
  double dVar5;
  
  iVar2 = FUN_80017a98();
  pfVar4 = *(float **)(param_1 + 0xb8);
  uVar3 = (uint)*(short *)((int)pfVar4 + 6);
  if (uVar3 != 0xffffffff) {
    if (*(char *)((int)pfVar4 + 0xd) != '\0') {
      uVar3 = FUN_80017690(uVar3);
      if (uVar3 != 0) {
        return;
      }
      FUN_80017698((int)*(short *)((int)pfVar4 + 6),1);
      *(undefined *)((int)pfVar4 + 0xd) = 1;
      return;
    }
    uVar3 = FUN_80017690(uVar3);
    if (uVar3 != 0) {
      *(undefined *)((int)pfVar4 + 0xd) = 1;
      return;
    }
  }
  if (*(char *)((int)pfVar4 + 0xd) == '\0') {
    bVar1 = *(byte *)((int)pfVar4 + 0xe);
    if (bVar1 == 3) {
      dVar5 = (double)FUN_8001771c((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
      if (((dVar5 < (double)*pfVar4) && ((int)*(short *)(pfVar4 + 1) != 0xffffffff)) &&
         (uVar3 = FUN_80017690((int)*(short *)(pfVar4 + 1)), uVar3 == 0)) {
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
        FUN_80017698((int)*(short *)(pfVar4 + 1),1);
        *(undefined *)((int)pfVar4 + 0xd) = 1;
      }
    }
    else if (bVar1 < 3) {
      if (bVar1 == 1) {
        if (((int)*(short *)(pfVar4 + 1) != 0xffffffff) &&
           (uVar3 = FUN_80017690((int)*(short *)(pfVar4 + 1)), uVar3 != 0)) {
          (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
          *(undefined *)((int)pfVar4 + 0xd) = 1;
        }
      }
      else if (bVar1 == 0) {
        dVar5 = (double)FUN_8001771c((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
        if (dVar5 < (double)*pfVar4) {
          (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
          *(undefined *)((int)pfVar4 + 0xd) = 1;
        }
      }
      else {
        dVar5 = (double)FUN_8001771c((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
        if (((dVar5 < (double)*pfVar4) && ((int)*(short *)(pfVar4 + 1) != 0xffffffff)) &&
           (uVar3 = FUN_80017690((int)*(short *)(pfVar4 + 1)), uVar3 != 0)) {
          (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
          *(undefined *)((int)pfVar4 + 0xd) = 1;
        }
      }
    }
    else if (bVar1 == 5) {
      if (((int)*(short *)(pfVar4 + 1) != 0xffffffff) &&
         (uVar3 = FUN_80017690((int)*(short *)(pfVar4 + 1)), uVar3 != 0)) {
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
      }
    }
    else if (((bVar1 < 5) && ((int)*(short *)(pfVar4 + 1) != 0xffffffff)) &&
            (uVar3 = FUN_80017690((int)*(short *)(pfVar4 + 1)), uVar3 == 0)) {
      (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
      FUN_80017698((int)*(short *)(pfVar4 + 1),1);
      *(undefined *)((int)pfVar4 + 0xd) = 1;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fd408
 * EN v1.0 Address: 0x801FD408
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801FD294
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fd408(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801fd40c
 * EN v1.0 Address: 0x801FD40C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801FD330
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fd40c(undefined4 param_1)
{
}
