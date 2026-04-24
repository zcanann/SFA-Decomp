#include "ghidra_import.h"
#include "main/dll/flybaddie1D7.h"

extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern double FUN_80021794();
extern int FUN_8002ba84();
extern int FUN_8002bac4();
extern int FUN_8002e1ac();
extern undefined4 FUN_80035ff8();
extern undefined4 FUN_80036018();
extern undefined4 FUN_80036e58();
extern void* FUN_80037048();
extern undefined4 FUN_8003709c();
extern undefined4 FUN_800372f8();
extern int FUN_8003809c();
extern undefined4 FUN_80138ca8();
extern double FUN_8014ca48();
extern undefined4 FUN_8014cae4();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80297480();

extern undefined4 DAT_802c2b68;
extern undefined4 DAT_802c2b6c;
extern undefined4 DAT_802c2b70;
extern undefined4 DAT_80327638;
extern undefined4 DAT_80327650;
extern undefined4 DAT_80327654;
extern undefined4 DAT_80327670;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd72c;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e5ef8;
extern f32 FLOAT_803e5efc;
extern f32 FLOAT_803e5f00;
extern f32 FLOAT_803e5f08;
extern f32 FLOAT_803e5f0c;
extern void* PTR_LAB_80327634;

/*
 * --INFO--
 *
 * Function: FUN_801cfdb8
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801CFDB8
 * EN v1.1 Size: 852b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cfdb8(void)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  int *piVar4;
  char cVar7;
  int iVar5;
  byte *pbVar6;
  int iVar8;
  char *pcVar9;
  double dVar10;
  double in_f31;
  double dVar11;
  double in_ps31_1;
  int local_38;
  int local_34 [11];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  iVar1 = FUN_8028683c();
  pcVar9 = *(char **)(iVar1 + 0xb8);
  iVar1 = FUN_8002ba84();
  iVar2 = FUN_8002bac4();
  local_34[0] = DAT_802c2b68;
  local_34[1] = DAT_802c2b6c;
  local_34[2] = DAT_802c2b70;
  if (iVar1 != 0) {
    if (*pcVar9 == '\x01') {
      if ((*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0) {
        *(float *)(pcVar9 + 4) = *(float *)(pcVar9 + 4) + FLOAT_803dc074;
      }
      uVar3 = FUN_80020078(0x4e3);
      if ((uVar3 == 1) && (pbVar6 = (byte *)(**(code **)(*DAT_803dd72c + 0x94))(), 3 < *pbVar6)) {
        FUN_800201ac(0x4e3,0xff);
      }
      if (FLOAT_803e5f00 <= *(float *)(pcVar9 + 4)) {
        *(float *)(pcVar9 + 4) = *(float *)(pcVar9 + 4) - FLOAT_803e5f00;
        uVar3 = FUN_80020078(0x4e3);
        if ((uVar3 == 0xff) && (pbVar6 = (byte *)(**(code **)(*DAT_803dd72c + 0x94))(), *pbVar6 < 4)
           ) {
          FUN_800201ac(0x4e3,1);
        }
      }
    }
    else if (*pcVar9 == '\0') {
      uVar3 = FUN_80020078(0xd11);
      if (uVar3 == 0) {
        uVar3 = FUN_80020078(0x544);
        if (uVar3 != 0) {
          cVar7 = (**(code **)(**(int **)(iVar1 + 0x68) + 0x40))(iVar1);
          if (cVar7 == '\0') {
            FUN_800201ac(0x4e4,0);
            *(float *)(pcVar9 + 4) = FLOAT_803e5ef8;
          }
          iVar8 = 0;
          piVar4 = local_34;
          dVar11 = (double)FLOAT_803e5ef8;
          do {
            iVar5 = FUN_8002e1ac(*piVar4);
            if ((iVar5 != 0) && (dVar10 = FUN_8014ca48(iVar5), dVar11 < dVar10)) {
              (**(code **)(**(int **)(iVar1 + 0x68) + 0x34))(iVar1,1,iVar5);
              break;
            }
            piVar4 = piVar4 + 1;
            iVar8 = iVar8 + 1;
          } while (iVar8 < 3);
          *(float *)(pcVar9 + 4) = *(float *)(pcVar9 + 4) + FLOAT_803dc074;
          if (FLOAT_803e5efc <= *(float *)(pcVar9 + 4)) {
            *(float *)(pcVar9 + 4) = *(float *)(pcVar9 + 4) - FLOAT_803e5efc;
            FUN_80138ca8(iVar1,0x152,0x1000);
          }
        }
        piVar4 = FUN_80037048(3,&local_38);
        for (iVar8 = 0; iVar8 < local_38; iVar8 = iVar8 + 1) {
          if (*(short *)(*piVar4 + 0x46) == 0x13a) {
            dVar11 = FUN_80021794((float *)(*piVar4 + 0x18),(float *)(iVar2 + 0x18));
            dVar10 = FUN_80021794((float *)(*piVar4 + 0x18),(float *)(iVar1 + 0x18));
            if (dVar11 <= dVar10) {
              FUN_8014cae4(*piVar4,iVar2);
            }
            else {
              FUN_8014cae4(*piVar4,iVar1);
            }
          }
          piVar4 = piVar4 + 1;
        }
      }
      else {
        piVar4 = FUN_80037048(3,&local_38);
        for (iVar1 = 0; iVar1 < local_38; iVar1 = iVar1 + 1) {
          if (*(short *)(*piVar4 + 0x46) == 0x13a) {
            FUN_8014cae4(*piVar4,iVar2);
          }
          piVar4 = piVar4 + 1;
        }
        FUN_800201ac(0x4e4,1);
        *pcVar9 = '\x01';
      }
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d010c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801D010C
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d010c(int param_1)
{
  FUN_8003709c(param_1,0x3d);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d013c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801D013C
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d013c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801d018c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801D018C
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d018c(int param_1)
{
  FUN_8003709c(param_1,0x3c);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d01b4
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801D01B4
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d01b4(undefined2 *param_1)
{
  short *psVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  int iVar4;
  int *piVar5;
  float local_18;
  int local_14 [3];
  
  local_18 = FLOAT_803e5f08;
  piVar5 = *(int **)(param_1 + 0x5c);
  if (*piVar5 == 0) {
    puVar2 = FUN_80037048(0x3d,local_14);
    iVar4 = 0;
    puVar3 = puVar2;
    if (0 < local_14[0]) {
      do {
        if ((param_1 != (undefined2 *)*puVar3) &&
           (*(char *)(*(int *)(param_1 + 0x26) + 0x1b) ==
            *(char *)(*(int *)((undefined2 *)*puVar3 + 0x26) + 0x1b))) {
          *piVar5 = puVar2[iVar4];
          return;
        }
        puVar3 = puVar3 + 1;
        iVar4 = iVar4 + 1;
        local_14[0] = local_14[0] + -1;
      } while (local_14[0] != 0);
    }
  }
  else {
    *(undefined4 *)(param_1 + 6) = *(undefined4 *)(*piVar5 + 0xc);
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(*piVar5 + 0x10);
    *(undefined4 *)(param_1 + 10) = *(undefined4 *)(*piVar5 + 0x14);
    *param_1 = *(undefined2 *)*piVar5;
    FUN_80036e58(0x3c,param_1,&local_18);
    if (*(byte *)(*piVar5 + 0x36) < 0xc0) {
      FUN_80035ff8((int)param_1);
      psVar1 = (short *)FUN_8002bac4();
      FUN_80297480(psVar1,(int)param_1);
    }
    else {
      FUN_80036018((int)param_1);
    }
    if ((*(byte *)(*piVar5 + 0x36) < 0xc0) || (local_18 < FLOAT_803e5f0c)) {
      param_1[0x58] = param_1[0x58] | 0x100;
    }
    else {
      param_1[0x58] = param_1[0x58] & 0xfeff;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d0314
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801D0314
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d0314(int param_1)
{
  FUN_800372f8(param_1,0x3c);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d0338
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801D0338
 * EN v1.1 Size: 348b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801d0338(int param_1)
{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  
  iVar1 = FUN_8002e1ac(*(int *)(&DAT_80327638 + (uint)*(byte *)(param_1 + 0xe) * 4));
  iVar2 = FUN_8003809c(iVar1,0x1ee);
  if (iVar2 == 0) {
    if (*(byte *)(param_1 + 0xe) != 0) {
      iVar1 = FUN_8002e1ac((int)(&PTR_LAB_80327634)[*(byte *)(param_1 + 0xe)]);
      iVar2 = FUN_8003809c(iVar1,0x1ee);
      if (iVar2 != 0) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,iVar1,0xffffffff);
        *(undefined *)(param_1 + 4) = 9;
        *(char *)(param_1 + 0xc) =
             (char)*(undefined4 *)(&DAT_80327650 + (uint)*(byte *)(param_1 + 0xe) * 4);
        *(undefined *)(param_1 + 5) = 0;
        return 2;
      }
    }
    uVar3 = 0;
  }
  else {
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,iVar1,0xffffffff);
    *(undefined *)(param_1 + 4) = 9;
    *(char *)(param_1 + 0xc) =
         (char)*(undefined4 *)(&DAT_80327654 + (uint)*(byte *)(param_1 + 0xe) * 4);
    *(char *)(param_1 + 0xd) =
         (char)*(undefined4 *)(&DAT_80327670 + (uint)*(byte *)(param_1 + 0xe) * 4);
    *(char *)(param_1 + 0xe) = *(char *)(param_1 + 0xe) + '\x01';
    *(undefined *)(param_1 + 5) = 0x1e;
    uVar3 = 1;
  }
  return uVar3;
}
