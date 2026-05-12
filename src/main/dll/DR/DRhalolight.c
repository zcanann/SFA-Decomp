#include "ghidra_import.h"
#include "main/dll/DR/DRhalolight.h"

extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_80017814();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_801e9c00();
extern undefined4 FUN_801ecdec();
extern int FUN_80286838();
extern undefined4 FUN_80286884();
extern double FUN_80293900();

extern undefined4* DAT_803dd6e8;
extern f32 lbl_803E6784;
extern f32 lbl_803E6828;
extern f32 lbl_803E682C;
extern f32 lbl_803E6830;
extern f32 lbl_803E6840;
extern f32 lbl_803E6850;

/*
 * --INFO--
 *
 * Function: FUN_801ecf94
 * EN v1.0 Address: 0x801ECF94
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x801ED20C
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_801ecf94(int param_1,undefined4 *param_2)
{
  int iVar1;
  double dVar2;
  double dVar3;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *param_2 = lbl_803E6850;
  dVar2 = FUN_80293900((double)(*(float *)(iVar1 + 0x49c) * *(float *)(iVar1 + 0x49c) +
                               *(float *)(iVar1 + 0x494) * *(float *)(iVar1 + 0x494) +
                               *(float *)(iVar1 + 0x498) * *(float *)(iVar1 + 0x498)));
  dVar3 = (double)(float)(dVar2 * (double)lbl_803E6840);
  if ((double)lbl_803E6784 < (double)(float)(dVar2 * (double)lbl_803E6840)) {
    dVar3 = (double)lbl_803E6784;
  }
  return dVar3;
}

/*
 * --INFO--
 *
 * Function: FUN_801ed014
 * EN v1.0 Address: 0x801ED014
 * EN v1.0 Size: 240b
 * EN v1.1 Address: 0x801ED2CC
 * EN v1.1 Size: 428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ed014(int param_1,int param_2)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(char *)(iVar1 + 0x421) = (char)param_2;
  if (param_2 == 2) {
    GameBit_Set((int)*(short *)(iVar1 + 0x448),1);
    FUN_801ecdec(param_1,iVar1);
    if ((*(byte *)(iVar1 + 0x428) >> 5 & 1) != 0) {
      *(float *)(iVar1 + 0x4b8) = lbl_803E6828;
      *(float *)(iVar1 + 0x4c0) = lbl_803E6784;
      *(float *)(iVar1 + 0x4bc) = lbl_803E682C;
      if (*(char *)(iVar1 + 0x421) == '\x02') {
        (**(code **)(*DAT_803dd6e8 + 0x58))((int)*(float *)(iVar1 + 0x4b8),0x5cd);
        (**(code **)(*DAT_803dd6e8 + 0x68))((double)lbl_803E6830);
      }
    }
    if (*(short *)(param_1 + 0x46) == 0x72) {
      *(undefined *)(*(int *)(param_1 + 0x54) + 0x6a) = 0x14;
      *(undefined *)(*(int *)(param_1 + 0x54) + 0x6b) = 0x14;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ed104
 * EN v1.0 Address: 0x801ED104
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801ED478
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ed104(int param_1)
{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  ObjGroup_RemoveObject(param_1,10);
  iVar2 = 0;
  iVar3 = iVar1;
  do {
    FUN_80017814(*(uint *)(iVar3 + 0x4c8));
    iVar3 = iVar3 + 8;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 9);
  if ((*(byte *)(iVar1 + 0x428) >> 5 & 1) != 0) {
    (**(code **)(*DAT_803dd6e8 + 0x60))();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ed188
 * EN v1.0 Address: 0x801ED188
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x801ED4FC
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ed188(void)
{
  int iVar1;
  char in_r8;
  int iVar2;
  
  iVar1 = FUN_80286838();
  iVar2 = *(int *)(iVar1 + 0xb8);
  FUN_801e9c00();
  if (in_r8 == -1) {
    FUN_8003b818(iVar1);
    ObjPath_GetPointWorldPosition(iVar1,0,(float *)(iVar2 + 1000),(undefined4 *)(iVar2 + 0x3ec),
                 (float *)(iVar2 + 0x3f0),0);
  }
  else {
    FUN_8003b818(iVar1);
    ObjPath_GetPointWorldPosition(iVar1,0,(float *)(iVar2 + 1000),(undefined4 *)(iVar2 + 0x3ec),
                 (float *)(iVar2 + 0x3f0),0);
  }
  FUN_80286884();
  return;
}
