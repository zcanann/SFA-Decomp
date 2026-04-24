#include "ghidra_import.h"
#include "main/dll/tesla.h"

extern undefined4 FUN_8000da78();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern int FUN_8002bac4();
extern int FUN_8002e1f4();
extern undefined4 FUN_8003b9ec();
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
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e7090;
extern f32 FLOAT_803e7094;
extern f32 FLOAT_803e70a0;
extern f32 FLOAT_803e70a4;
extern f32 FLOAT_803e70a8;
extern f32 FLOAT_803e70ac;
extern f32 FLOAT_803e70b0;
extern f32 FLOAT_803e70b4;
extern f32 FLOAT_803e70b8;
extern f32 FLOAT_803e70bc;
extern f32 FLOAT_803e70c0;
extern f32 FLOAT_803e70c4;

/*
 * --INFO--
 *
 * Function: FUN_802069b4
 * EN v1.0 Address: 0x80206968
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802069B4
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802069b4(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80206ac4
 * EN v1.0 Address: 0x8020696C
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x80206AC4
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80206ac4(int param_1)
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
 * Function: FUN_80206b08
 * EN v1.0 Address: 0x802069B4
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80206B08
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80206b08(int param_1)
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
 * Function: FUN_80206b64
 * EN v1.0 Address: 0x802069DC
 * EN v1.0 Size: 796b
 * EN v1.1 Address: 0x80206B64
 * EN v1.1 Size: 792b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80206b64(void)
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
    uVar4 = FUN_80020078(0xe58);
    if (uVar4 != 0) {
      *(float *)(uVar3 + 0x10) = *(float *)(iVar11 + 0xc) - FLOAT_803e70a4;
      goto LAB_80206e64;
    }
  }
  else if ((bVar7 < 2) && (bVar7 != 0)) {
    if (5 < *(byte *)(iVar10 + 5)) goto LAB_80206e64;
    uVar4 = FUN_80020078(0xe57);
    if (uVar4 != 0) {
      *(float *)(uVar3 + 0x10) = *(float *)(iVar11 + 0xc) - FLOAT_803e70a4;
      goto LAB_80206e64;
    }
  }
  uVar4 = FUN_80020078(0x5e4);
  uVar5 = FUN_80020078(0x5e5);
  if ((uVar5 != 0) || ((uVar4 & 0xff) != (uint)*(byte *)(iVar10 + 7))) {
    *(undefined *)(iVar10 + 4) = 0;
  }
  *(char *)(iVar10 + 7) = (char)uVar4;
  if (*(int *)(iVar10 + 8) == 0) {
    iVar6 = FUN_8002e1f4(local_24,&local_28);
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
     (*(float *)(uVar3 + 0x10) <= *(float *)(iVar11 + 0xc) - FLOAT_803e70a4)) {
    if (*(char *)(iVar10 + 6) != '\0') {
      if (*(char *)(iVar10 + 4) == '\0') {
        *(undefined4 *)(uVar3 + 0x10) = *(undefined4 *)(iVar11 + 0xc);
      }
      if ((*(char *)(iVar10 + 4) == '\0') && (iVar11 = FUN_8002bac4(), iVar11 != 0)) {
        fVar1 = *(float *)(uVar3 + 0x10) - *(float *)(iVar11 + 0x10);
        if (fVar1 < FLOAT_803e70b0) {
          fVar1 = fVar1 * FLOAT_803e70ac;
        }
        if (fVar1 < FLOAT_803e70b4) {
          fVar1 = *(float *)(iVar11 + 0xc) - (*(float *)(uVar3 + 0xc) - FLOAT_803e70b4);
          fVar2 = *(float *)(uVar3 + 0x14) - *(float *)(iVar11 + 0x14);
          if (fVar2 < FLOAT_803e70b0) {
            fVar2 = fVar2 * FLOAT_803e70ac;
          }
          if (fVar2 < FLOAT_803e70b8) {
            if (fVar1 < FLOAT_803e70bc) {
              if (fVar1 < FLOAT_803e70b4) {
                if (fVar1 < FLOAT_803e70c0) {
                  if (FLOAT_803e70b0 <= fVar1) {
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
              FUN_800201ac(0x5e5,1);
            }
          }
        }
      }
    }
  }
  else {
    FUN_8000da78(uVar3,0x1c8);
    *(float *)(uVar3 + 0x10) = *(float *)(uVar3 + 0x10) - FLOAT_803dc074 / FLOAT_803e70a8;
    fVar1 = *(float *)(iVar11 + 0xc) - FLOAT_803e70a4;
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
 * Function: FUN_80206e7c
 * EN v1.0 Address: 0x80206CF8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80206E7C
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80206e7c(undefined2 *param_1,int param_2)
{
}
