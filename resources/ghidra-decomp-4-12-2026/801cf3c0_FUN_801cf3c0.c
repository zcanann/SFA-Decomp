// Function: FUN_801cf3c0
// Entry: 801cf3c0
// Size: 424 bytes

/* WARNING: Removing unreachable block (ram,0x801cf404) */

void FUN_801cf3c0(uint param_1,int param_2)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  
  iVar2 = FUN_801ce62c(param_1,param_2);
  if (iVar2 == 0) {
    bVar1 = *(byte *)(param_2 + 0x408);
    if (bVar1 == 2) {
      *(undefined **)(param_2 + 0x48) = &DAT_803dcbe0;
      iVar2 = FUN_8003809c(param_1,0x576);
      if (iVar2 != 0) {
        FUN_800201ac(0x578,2);
        FUN_8001ffac(0x576);
        (**(code **)(*DAT_803dd6d4 + 0x48))(4,param_1,0xffffffff);
        *(undefined *)(param_2 + 0x408) = 3;
        *(byte *)(param_2 + 0x43c) = *(byte *)(param_2 + 0x43c) | 0x10;
      }
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        *(undefined **)(param_2 + 0x48) = &DAT_803dcbd8;
        uVar3 = FUN_80020078(0xd3);
        if (uVar3 != 0) {
          *(undefined *)(param_2 + 0x408) = 1;
        }
      }
      else {
        *(undefined **)(param_2 + 0x48) = &DAT_803dcbdc;
        uVar3 = FUN_80020078(0x578);
        if (uVar3 == 1) {
          *(undefined *)(param_2 + 0x408) = 2;
        }
        else if (((int)uVar3 < 1) && (-1 < (int)uVar3)) {
          iVar2 = FUN_8003809c(param_1,0x576);
          if (iVar2 != 0) {
            FUN_800201ac(0x578,1);
            FUN_8001ffac(0x576);
            (**(code **)(*DAT_803dd6d4 + 0x48))(2,param_1,0xffffffff);
            *(byte *)(param_2 + 0x43c) = *(byte *)(param_2 + 0x43c) | 0x10;
            *(undefined *)(param_2 + 0x408) = 2;
          }
        }
        else {
          *(undefined *)(param_2 + 0x408) = 3;
        }
      }
    }
    else if (bVar1 < 4) {
      *(undefined **)(param_2 + 0x48) = &DAT_803dcbe4;
    }
  }
  return;
}

