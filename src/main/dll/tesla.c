#include "ghidra_import.h"
#include "main/dll/tesla.h"

extern undefined4 FUN_800068c4();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern int FUN_80017a98();
extern int FUN_80017b00();
extern undefined4 FUN_8003b818();
extern uint FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4 DAT_8032a618;
extern undefined4 DAT_8032a619;
extern undefined4 DAT_8032a61a;
extern undefined4 DAT_8032a61b;
extern undefined4 DAT_8032a61c;
extern undefined4 DAT_8032a61d;
extern undefined4 DAT_8032a61e;
extern undefined4 DAT_8032a61f;
extern undefined4 DAT_8032a620;
extern undefined4 DAT_8032a660;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd72c;
extern f64 DOUBLE_803e7098;
extern f64 DOUBLE_803e70c8;
extern f32 lbl_803DC074;
extern f32 lbl_803E7090;
extern f32 lbl_803E7094;
extern f32 lbl_803E70A0;
extern f32 lbl_803E70A4;
extern f32 lbl_803E70A8;
extern f32 lbl_803E70AC;
extern f32 lbl_803E70B0;
extern f32 lbl_803E70B4;
extern f32 lbl_803E70B8;
extern f32 lbl_803E70BC;
extern f32 lbl_803E70C0;
extern f32 lbl_803E70C4;

/*
 * --INFO--
 *
 * Function: FUN_80206968
 * EN v1.0 Address: 0x80206968
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802069B4
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80206968(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020696c
 * EN v1.0 Address: 0x8020696C
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x80206AC4
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020696c(int param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  *(undefined4 *)(iVar1 + 8) = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_802069b4
 * EN v1.0 Address: 0x802069B4
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80206B08
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802069b4(int param_1)
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
 * Function: FUN_802069dc
 * EN v1.0 Address: 0x802069DC
 * EN v1.0 Size: 796b
 * EN v1.1 Address: 0x80206B64
 * EN v1.1 Size: 792b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802069dc(void)
{
  float fVar1;
  float fVar2;
  uint uVar3;
  byte bVar7;
  uint uVar4;
  uint uVar5;
  int iVar6;
  int iVar8;
  ushort uVar9;
  int iVar10;
  int iVar11;
  int local_28;
  int local_24 [9];
  
  uVar3 = FUN_80286840();
  iVar11 = *(int *)(uVar3 + 0x4c);
  iVar10 = *(int *)(uVar3 + 0xb8);
  uVar9 = 0xffff;
  bVar7 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(uVar3 + 0xac));
  if (bVar7 == 2) {
    uVar4 = FUN_80017690(0xe58);
    if (uVar4 != 0) {
      *(float *)(uVar3 + 0x10) = *(float *)(iVar11 + 0xc) - lbl_803E70A4;
      goto LAB_80206e64;
    }
  }
  else if ((bVar7 < 2) && (bVar7 != 0)) {
    if (5 < *(byte *)(iVar10 + 5)) goto LAB_80206e64;
    uVar4 = FUN_80017690(0xe57);
    if (uVar4 != 0) {
      *(float *)(uVar3 + 0x10) = *(float *)(iVar11 + 0xc) - lbl_803E70A4;
      goto LAB_80206e64;
    }
  }
  uVar4 = FUN_80017690(0x5e4);
  uVar5 = FUN_80017690(0x5e5);
  if ((uVar5 != 0) || ((uVar4 & 0xff) != (uint)*(byte *)(iVar10 + 7))) {
    *(undefined *)(iVar10 + 4) = 0;
  }
  *(char *)(iVar10 + 7) = (char)uVar4;
  if (*(int *)(iVar10 + 8) == 0) {
    iVar6 = FUN_80017b00(local_24,&local_28);
    for (; local_24[0] < local_28; local_24[0] = local_24[0] + 1) {
      iVar8 = *(int *)(iVar6 + local_24[0] * 4);
      if (*(short *)(iVar8 + 0x46) == 0x431) {
        *(int *)(iVar10 + 8) = iVar8;
        local_24[0] = local_28;
      }
    }
    if (*(int *)(iVar10 + 8) == 0) goto LAB_80206e64;
  }
  (**(code **)(**(int **)(*(int *)(iVar10 + 8) + 0x68) + 0x20))(*(int *)(iVar10 + 8),&DAT_8032a660);
  *(undefined *)(iVar10 + 6) = (&DAT_8032a660)[*(byte *)(iVar10 + 5)];
  if ((*(char *)(iVar10 + 4) == '\0') ||
     (*(float *)(uVar3 + 0x10) <= *(float *)(iVar11 + 0xc) - lbl_803E70A4)) {
    if (*(char *)(iVar10 + 6) != '\0') {
      if (*(char *)(iVar10 + 4) == '\0') {
        *(undefined4 *)(uVar3 + 0x10) = *(undefined4 *)(iVar11 + 0xc);
      }
      if ((*(char *)(iVar10 + 4) == '\0') && (iVar11 = FUN_80017a98(), iVar11 != 0)) {
        fVar1 = *(float *)(uVar3 + 0x10) - *(float *)(iVar11 + 0x10);
        if (fVar1 < lbl_803E70B0) {
          fVar1 = fVar1 * lbl_803E70AC;
        }
        if (fVar1 < lbl_803E70B4) {
          fVar1 = *(float *)(iVar11 + 0xc) - (*(float *)(uVar3 + 0xc) - lbl_803E70B4);
          fVar2 = *(float *)(uVar3 + 0x14) - *(float *)(iVar11 + 0x14);
          if (fVar2 < lbl_803E70B0) {
            fVar2 = fVar2 * lbl_803E70AC;
          }
          if (fVar2 < lbl_803E70B8) {
            if (fVar1 < lbl_803E70BC) {
              if (fVar1 < lbl_803E70B4) {
                if (fVar1 < lbl_803E70C0) {
                  if (lbl_803E70B0 <= fVar1) {
                    uVar9 = 1;
                  }
                }
                else {
                  uVar9 = 2;
                }
              }
              else {
                uVar9 = 3;
              }
            }
            else {
              uVar9 = 4;
            }
            if (uVar9 == *(byte *)(iVar10 + 6)) {
              *(undefined *)(iVar10 + 4) = 1;
            }
            else {
              FUN_80017698(0x5e5,1);
            }
          }
        }
      }
    }
  }
  else {
    FUN_800068c4(uVar3,0x1c8);
    *(float *)(uVar3 + 0x10) = *(float *)(uVar3 + 0x10) - lbl_803DC074 / lbl_803E70A8;
    fVar1 = *(float *)(iVar11 + 0xc) - lbl_803E70A4;
    if (*(float *)(uVar3 + 0x10) <= fVar1) {
      *(float *)(uVar3 + 0x10) = fVar1;
    }
  }
LAB_80206e64:
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80206cf8
 * EN v1.0 Address: 0x80206CF8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80206E7C
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80206cf8(undefined2 *param_1,int param_2)
{
}
