// Function: FUN_801fcfe4
// Entry: 801fcfe4
// Size: 688 bytes

/* WARNING: Removing unreachable block (ram,0x801fd090) */

void FUN_801fcfe4(int param_1)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  float *pfVar4;
  double dVar5;
  
  iVar2 = FUN_8002bac4();
  pfVar4 = *(float **)(param_1 + 0xb8);
  uVar3 = (uint)*(short *)((int)pfVar4 + 6);
  if (uVar3 != 0xffffffff) {
    if (*(char *)((int)pfVar4 + 0xd) != '\0') {
      uVar3 = FUN_80020078(uVar3);
      if (uVar3 != 0) {
        return;
      }
      FUN_800201ac((int)*(short *)((int)pfVar4 + 6),1);
      *(undefined *)((int)pfVar4 + 0xd) = 1;
      return;
    }
    uVar3 = FUN_80020078(uVar3);
    if (uVar3 != 0) {
      *(undefined *)((int)pfVar4 + 0xd) = 1;
      return;
    }
  }
  if (*(char *)((int)pfVar4 + 0xd) == '\0') {
    bVar1 = *(byte *)((int)pfVar4 + 0xe);
    if (bVar1 == 3) {
      dVar5 = (double)FUN_800217c8((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
      if (((dVar5 < (double)*pfVar4) && ((int)*(short *)(pfVar4 + 1) != 0xffffffff)) &&
         (uVar3 = FUN_80020078((int)*(short *)(pfVar4 + 1)), uVar3 == 0)) {
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
        FUN_800201ac((int)*(short *)(pfVar4 + 1),1);
        *(undefined *)((int)pfVar4 + 0xd) = 1;
      }
    }
    else if (bVar1 < 3) {
      if (bVar1 == 1) {
        if (((int)*(short *)(pfVar4 + 1) != 0xffffffff) &&
           (uVar3 = FUN_80020078((int)*(short *)(pfVar4 + 1)), uVar3 != 0)) {
          (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
          *(undefined *)((int)pfVar4 + 0xd) = 1;
        }
      }
      else if (bVar1 == 0) {
        dVar5 = (double)FUN_800217c8((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
        if (dVar5 < (double)*pfVar4) {
          (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
          *(undefined *)((int)pfVar4 + 0xd) = 1;
        }
      }
      else {
        dVar5 = (double)FUN_800217c8((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
        if (((dVar5 < (double)*pfVar4) && ((int)*(short *)(pfVar4 + 1) != 0xffffffff)) &&
           (uVar3 = FUN_80020078((int)*(short *)(pfVar4 + 1)), uVar3 != 0)) {
          (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
          *(undefined *)((int)pfVar4 + 0xd) = 1;
        }
      }
    }
    else if (bVar1 == 5) {
      if (((int)*(short *)(pfVar4 + 1) != 0xffffffff) &&
         (uVar3 = FUN_80020078((int)*(short *)(pfVar4 + 1)), uVar3 != 0)) {
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
      }
    }
    else if (((bVar1 < 5) && ((int)*(short *)(pfVar4 + 1) != 0xffffffff)) &&
            (uVar3 = FUN_80020078((int)*(short *)(pfVar4 + 1)), uVar3 == 0)) {
      (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
      FUN_800201ac((int)*(short *)(pfVar4 + 1),1);
      *(undefined *)((int)pfVar4 + 0xd) = 1;
    }
  }
  return;
}

