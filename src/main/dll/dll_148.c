#include "ghidra_import.h"
#include "main/dll/dll_148.h"

extern bool FUN_800067f8();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006810();
extern undefined4 FUN_80006824();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_8001771c();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 FUN_800360d4();
extern undefined4 FUN_800360f0();
extern int FUN_80037008();
extern undefined4 FUN_8003735c();
extern int FUN_80039520();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80135814();
extern undefined4 FUN_8017b130();
extern uint FUN_80286830();
extern uint FUN_8028683c();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286888();
extern int FUN_80294c0c();

extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e4408;
extern f64 DOUBLE_803e4428;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e43f0;
extern f32 FLOAT_803e43f4;
extern f32 FLOAT_803e43f8;
extern f32 FLOAT_803e43fc;
extern f32 FLOAT_803e4400;
extern f32 FLOAT_803e4410;
extern f32 FLOAT_803e4418;
extern f32 FLOAT_803e441c;
extern f32 FLOAT_803e4420;

/*
 * --INFO--
 *
 * Function: pressureswitchfb_update
 * EN v1.0 Address: 0x8017ADB4
 * EN v1.0 Size: 1540b
 * EN v1.1 Address: 0x8017B2F8
 * EN v1.1 Size: 1604b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void pressureswitchfb_update(void)
{
  char cVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  undefined4 *puVar10;
  byte bVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  char *pcVar15;
  int iVar16;
  int iVar17;
  double dVar18;
  float local_58;
  undefined auStack_54 [4];
  undefined2 local_50;
  undefined2 local_4e;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  undefined4 local_38;
  uint uStack_34;
  
  uVar6 = FUN_80286830();
  iVar16 = *(int *)(uVar6 + 0x4c);
  pcVar15 = *(char **)(uVar6 + 0xb8);
  if (pcVar15[0x84] < '\0') {
    if (((byte)pcVar15[0x84] >> 5 & 1) == 0) {
      *(byte *)(uVar6 + 0xaf) = *(byte *)(uVar6 + 0xaf) | 8;
    }
    else {
      *(byte *)(uVar6 + 0xaf) = *(byte *)(uVar6 + 0xaf) & 0xf7;
    }
  }
  else {
    *(byte *)(uVar6 + 0xaf) = *(byte *)(uVar6 + 0xaf) | 8;
  }
  if (((int)*(short *)(iVar16 + 0x20) == 0xffffffff) ||
     (uVar7 = FUN_80017690((int)*(short *)(iVar16 + 0x20)), uVar7 != 0)) {
    cVar1 = *pcVar15;
    *pcVar15 = cVar1 + -1;
    if ((char)(cVar1 + -1) < '\0') {
      *pcVar15 = '\0';
    }
    local_58 = FLOAT_803e43f0;
    iVar8 = FUN_80037008(5,uVar6,&local_58);
    if (iVar8 != 0) {
      *pcVar15 = '\x05';
    }
    if ('\0' < *(char *)(*(int *)(uVar6 + 0x58) + 0x10f)) {
      iVar17 = 0;
      for (iVar14 = 0; iVar14 < *(char *)(*(int *)(uVar6 + 0x58) + 0x10f); iVar14 = iVar14 + 1) {
        iVar12 = *(int *)(*(int *)(uVar6 + 0x58) + iVar17 + 0x100);
        if ((((*(short *)(iVar12 + 0x44) == 1) || (*(short *)(iVar12 + 0x44) == 2)) ||
            (*(short *)(iVar12 + 0x46) == 0x754)) || (*(short *)(iVar12 + 0x46) == 0x6d)) {
          bVar4 = true;
        }
        else {
          bVar4 = false;
        }
        if ((bVar4) && (iVar12 != iVar8)) {
          uStack_34 = (uint)*(byte *)(iVar16 + 0x1d);
          local_38 = 0x43300000;
          if ((float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e4408) <
              *(float *)(iVar12 + 0x10) - *(float *)(uVar6 + 0x10)) {
            iVar13 = *(int *)(uVar6 + 0xb8);
            uVar7 = 0;
            if (((*(byte *)(iVar13 + 0x84) >> 6 & 1) == 0) ||
               (iVar9 = FUN_80017a98(), iVar12 == iVar9)) {
              for (; (uVar5 = uVar7 & 0xff, *(int *)(iVar13 + uVar5 * 4 + 4) != 0 && (uVar5 != 9));
                  uVar7 = uVar7 + 1) {
              }
              *(int *)(iVar13 + uVar5 * 4 + 4) = iVar12;
              iVar13 = iVar13 + uVar5 * 8;
              *(undefined4 *)(iVar13 + 0x2c) = *(undefined4 *)(iVar12 + 0xc);
              *(undefined4 *)(iVar13 + 0x30) = *(undefined4 *)(iVar12 + 0x14);
            }
          }
        }
        iVar17 = iVar17 + 4;
      }
    }
    iVar8 = *(int *)(uVar6 + 0xb8);
    bVar4 = false;
    for (bVar11 = 0; bVar11 < 10; bVar11 = bVar11 + 1) {
      iVar17 = (uint)bVar11 * 4 + 4;
      iVar14 = *(int *)(iVar8 + iVar17);
      if (iVar14 != 0) {
        iVar12 = iVar8 + (uint)bVar11 * 8;
        if ((*(float *)(iVar12 + 0x2c) == *(float *)(iVar14 + 0xc)) &&
           (*(float *)(iVar12 + 0x30) == *(float *)(iVar14 + 0x14))) {
          bVar4 = true;
        }
        else {
          *(undefined4 *)(iVar8 + iVar17) = 0;
        }
      }
    }
    if (bVar4) {
      *pcVar15 = '\x05';
    }
    bVar4 = false;
    if ((*pcVar15 == '\0') || (((byte)pcVar15[0x84] >> 4 & 1) != 0)) {
      if (((byte)pcVar15[0x84] >> 4 & 1) == 0) {
        if (*(float *)(uVar6 + 0x10) < *(float *)(pcVar15 + 0x7c)) {
          *(float *)(uVar6 + 0x10) =
               *(float *)(pcVar15 + 0x80) * FLOAT_803dc074 + *(float *)(uVar6 + 0x10);
          if (*(float *)(uVar6 + 0x10) <= *(float *)(pcVar15 + 0x7c)) {
            bVar4 = true;
          }
          else {
            *(float *)(uVar6 + 0x10) = *(float *)(pcVar15 + 0x7c);
            FUN_80017698((int)*(short *)(iVar16 + 0x1a),0);
          }
        }
      }
      else {
        uVar7 = FUN_80017690((int)*(short *)(iVar16 + 0x1a));
        if (uVar7 == 0) {
          puVar10 = (undefined4 *)FUN_80039520(uVar6,0);
          if (puVar10 != (undefined4 *)0x0) {
            *puVar10 = 0;
          }
          pcVar15[0x84] = pcVar15[0x84] & 0xef;
          pcVar15[0x84] = pcVar15[0x84] & 0xdfU | 0x20;
        }
      }
    }
    else {
      if (pcVar15[0x84] < '\0') {
        iVar8 = FUN_80017a98();
        iVar8 = FUN_80294c0c(iVar8);
        if (iVar8 != 0) {
          pcVar15[0x84] = pcVar15[0x84] & 0xdf;
        }
      }
      if (((byte)pcVar15[0x84] >> 5 & 1) == 0) {
        uStack_34 = (uint)*(byte *)(iVar16 + 0x1c);
        local_38 = 0x43300000;
        fVar3 = *(float *)(pcVar15 + 0x7c) -
                (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e4408);
        fVar2 = *(float *)(uVar6 + 0x10);
        if (fVar3 <= fVar2) {
          *(float *)(uVar6 + 0x10) = -(*(float *)(pcVar15 + 0x80) * FLOAT_803dc074 - fVar2);
          if (fVar3 <= *(float *)(uVar6 + 0x10)) {
            bVar4 = true;
          }
          else {
            *(float *)(uVar6 + 0x10) = fVar3;
            FUN_80017698((int)*(short *)(iVar16 + 0x1a),1);
            if (pcVar15[0x84] < '\0') {
              puVar10 = (undefined4 *)FUN_80039520(uVar6,0);
              if (puVar10 != (undefined4 *)0x0) {
                *puVar10 = 0x100;
              }
              pcVar15[0x84] = pcVar15[0x84] & 0xefU | 0x10;
            }
          }
        }
        else {
          *(float *)(uVar6 + 0x10) = *(float *)(pcVar15 + 0x80) * FLOAT_803dc074 + fVar2;
          if (fVar3 < *(float *)(uVar6 + 0x10)) {
            *(float *)(uVar6 + 0x10) = fVar3;
          }
          FUN_80017698((int)*(short *)(iVar16 + 0x1a),1);
          if (pcVar15[0x84] < '\0') {
            puVar10 = (undefined4 *)FUN_80039520(uVar6,0);
            if (puVar10 != (undefined4 *)0x0) {
              *puVar10 = 0x100;
            }
            pcVar15[0x84] = pcVar15[0x84] & 0xefU | 0x10;
          }
        }
      }
      else {
        *(float *)(uVar6 + 0x10) =
             *(float *)(pcVar15 + 0x80) * FLOAT_803dc074 + *(float *)(uVar6 + 0x10);
        if (*(float *)(uVar6 + 0x10) <= *(float *)(pcVar15 + 0x7c)) {
          bVar4 = true;
        }
        else {
          *(float *)(uVar6 + 0x10) = *(float *)(pcVar15 + 0x7c);
        }
      }
    }
    if ((((*(ushort *)(uVar6 + 0xb0) & 0x800) != 0) && (((byte)pcVar15[0x84] >> 4 & 1) == 0)) &&
       (pcVar15[0x84] < '\0')) {
      iVar8 = FUN_80017a98();
      dVar18 = (double)FUN_8001771c((float *)(uVar6 + 0x18),(float *)(iVar8 + 0x18));
      if (dVar18 < (double)FLOAT_803e43f4) {
        local_48 = FLOAT_803e43f8;
        local_44 = FLOAT_803e43fc;
        local_40 = FLOAT_803e43f8;
        local_4c = FLOAT_803e4400;
        local_4e = 0x12;
        local_50 = 10;
        iVar8 = 0;
        do {
          (**(code **)(*DAT_803dd708 + 8))(uVar6,0x7c3,auStack_54,2,0xffffffff,0);
          iVar8 = iVar8 + 1;
        } while (iVar8 < 3);
      }
    }
    if (bVar4) {
      FUN_80006824(uVar6,0x61);
    }
    else {
      FUN_8000680c(uVar6,8);
    }
    if (((*(char *)(iVar16 + 0x1e) != '\0') && (iVar8 = FUN_80017a90(), iVar8 != 0)) &&
       ((uVar7 = FUN_80017690((int)*(short *)(iVar16 + 0x1a)), uVar7 == 0 &&
        (*(byte *)(uVar6 + 0xaf) = *(byte *)(uVar6 + 0xaf) & 0xf7,
        (*(byte *)(uVar6 + 0xaf) & 4) != 0)))) {
      (**(code **)(**(int **)(iVar8 + 0x68) + 0x28))(iVar8,uVar6,1,3);
    }
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017b3b8
 * EN v1.0 Address: 0x8017B3B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017B93C
 * EN v1.1 Size: 484b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017b3b8(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8017b3bc
 * EN v1.0 Address: 0x8017B3BC
 * EN v1.0 Size: 768b
 * EN v1.1 Address: 0x8017BB20
 * EN v1.1 Size: 796b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017b3bc(undefined4 param_1,undefined4 param_2,int param_3)
{
  uint uVar1;
  undefined4 *puVar2;
  uint uVar3;
  uint uVar4;
  bool bVar5;
  int iVar6;
  int iVar7;
  ushort *puVar8;
  
  uVar1 = FUN_8028683c();
  puVar8 = *(ushort **)(uVar1 + 0xb8);
  iVar7 = *(int *)(uVar1 + 0x4c);
  if (*(char *)(uVar1 + 0x36) == '\0') {
    FUN_800360d4(uVar1);
  }
  if (*(char *)(*(int *)(uVar1 + 0x50) + 0x59) != '\0') {
    if (((*(byte *)(puVar8 + 3) & 1) != 0) &&
       (puVar2 = (undefined4 *)FUN_80039520(uVar1,0), puVar2 != (undefined4 *)0x0)) {
      *puVar2 = 0x100;
    }
    if (((*(byte *)(puVar8 + 3) & 2) != 0) &&
       (puVar2 = (undefined4 *)FUN_80039520(uVar1,1), puVar2 != (undefined4 *)0x0)) {
      *puVar2 = 0x100;
    }
  }
  if (*(char *)(puVar8 + 2) == '\0') {
    uVar3 = FUN_80017690((int)*(short *)(iVar7 + 0x18));
    bVar5 = false;
    if (((int)*(short *)(iVar7 + 0x22) == 0xffffffff) ||
       (uVar4 = FUN_80017690((int)*(short *)(iVar7 + 0x22)), uVar4 != 0)) {
      bVar5 = true;
    }
    if ((uVar3 != 0) && ((*(byte *)(puVar8 + 3) & 1) == 0)) {
      if (*(char *)(*(int *)(uVar1 + 0x50) + 0x59) != '\0') {
        FUN_80006824(uVar1,0x4b);
      }
      *(byte *)(puVar8 + 3) = *(byte *)(puVar8 + 3) | 1;
    }
    if ((bVar5) && ((*(byte *)(puVar8 + 3) & 2) == 0)) {
      if (*(char *)(*(int *)(uVar1 + 0x50) + 0x59) != '\0') {
        FUN_80006824(uVar1,0x4b);
      }
      *(byte *)(puVar8 + 3) = *(byte *)(puVar8 + 3) | 2;
    }
    if (*(char *)(puVar8 + 3) == '\x03') {
      *(undefined *)(puVar8 + 2) = 2;
      if (*puVar8 != 0) {
        FUN_80006824(uVar1,*puVar8);
      }
    }
  }
  else if ((*(char *)(puVar8 + 2) == '\x01') &&
          (uVar3 = FUN_80017690((int)*(short *)(iVar7 + 0x18)), uVar3 == 0)) {
    *(undefined *)(puVar8 + 2) = 3;
    if (*puVar8 != 0) {
      FUN_80006824(uVar1,*puVar8);
    }
  }
  if (*(char *)(puVar8 + 2) == '\x02') {
    for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar6 = iVar6 + 1) {
      if (*(char *)(param_3 + iVar6 + 0x81) == '\x02') {
        *(undefined *)(puVar8 + 2) = 1;
        if ((int)*(short *)(iVar7 + 0x1a) != 0xffffffff) {
          FUN_80017698((int)*(short *)(iVar7 + 0x1a),1);
        }
        if ((*puVar8 != 0) && (bVar5 = FUN_800067f8(uVar1,*puVar8), bVar5)) {
          FUN_80006810(uVar1,*puVar8);
        }
        if (puVar8[1] != 0) {
          FUN_80006824(uVar1,puVar8[1]);
        }
      }
    }
  }
  else if (*(char *)(puVar8 + 2) == '\x03') {
    for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar6 = iVar6 + 1) {
      if (*(char *)(param_3 + iVar6 + 0x81) == '\x01') {
        *(undefined *)(puVar8 + 2) = 0;
        *(undefined *)(puVar8 + 3) = 0;
        if ((int)*(short *)(iVar7 + 0x1a) != 0xffffffff) {
          FUN_80017698((int)*(short *)(iVar7 + 0x1a),0);
        }
        if ((*puVar8 != 0) && (bVar5 = FUN_800067f8(uVar1,*puVar8), bVar5)) {
          FUN_80006810(uVar1,*puVar8);
        }
        if (puVar8[1] != 0) {
          FUN_80006824(uVar1,puVar8[1]);
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
 * Function: FUN_8017b6bc
 * EN v1.0 Address: 0x8017B6BC
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8017BE3C
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017b6bc(int param_1)
{
  FUN_8003b818(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017b6dc
 * EN v1.0 Address: 0x8017B6DC
 * EN v1.0 Size: 204b
 * EN v1.1 Address: 0x8017BE60
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017b6dc(int param_1)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  iVar2 = *(int *)(param_1 + 0x4c);
  if (*(char *)(iVar3 + 5) != '\0') {
    if ((*(short *)(iVar2 + 0x1c) == 0) || (*(char *)(iVar3 + 4) == '\0')) {
      uVar1 = 0xffffffff;
    }
    else {
      uVar1 = *(byte *)(iVar2 + 0x20) & 0x7f;
      (**(code **)(*DAT_803dd6d4 + 0x54))();
    }
    if (*(char *)(iVar2 + 0x1e) != -1) {
      (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar2 + 0x1e),param_1,uVar1);
    }
    *(undefined *)(iVar3 + 5) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017b7a8
 * EN v1.0 Address: 0x8017B7A8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017BF24
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017b7a8(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8017b7ac
 * EN v1.0 Address: 0x8017B7AC
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x8017C0F4
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017b7ac(int param_1)
{
  uint uVar1;
  int iVar2;
  
  uVar1 = FUN_80017690((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x1e));
  if (uVar1 != 0) {
    iVar2 = FUN_80039520(param_1,0);
    if (iVar2 != 0) {
      *(short *)(iVar2 + 8) = *(short *)(iVar2 + 8) + (short)((int)FLOAT_803dc074 << 3);
      if (0x131e < (int)*(short *)(iVar2 + 8) + (int)FLOAT_803dc074 * 8) {
        *(undefined2 *)(iVar2 + 8) = 0x131f;
      }
      FUN_80135814();
    }
    FUN_800360f0(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017b858
 * EN v1.0 Address: 0x8017B858
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x8017C1B4
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017b858(undefined2 *param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x26);
  iVar1 = FUN_80039520((int)param_1,0);
  if (iVar1 != 0) {
    *(undefined2 *)(iVar1 + 8) = 0x800;
  }
  *param_1 = (short)((int)*(char *)(iVar3 + 0x18) << 8);
  param_1[0x58] = param_1[0x58] | 0x6000;
  FUN_800360d4((int)param_1);
  uVar2 = FUN_80017690((int)*(short *)(iVar3 + 0x1e));
  if (uVar2 != 0) {
    FUN_800360f0((int)param_1);
  }
  return;
}
