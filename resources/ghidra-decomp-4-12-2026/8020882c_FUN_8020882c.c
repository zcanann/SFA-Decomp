// Function: FUN_8020882c
// Entry: 8020882c
// Size: 436 bytes

void FUN_8020882c(uint param_1)

{
  short sVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  uVar2 = FUN_80020078((int)*(short *)(iVar3 + 2));
  if (((*(char *)(iVar3 + 6) == '\0') && ((short)uVar2 != 0)) &&
     (uVar2 = FUN_80020078(0xedf), uVar2 != 0)) {
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    *(undefined *)(iVar3 + 6) = 1;
  }
  if (((*(char *)(iVar3 + 8) != '\0') && (*(char *)(iVar3 + 6) != '\0')) &&
     (uVar2 = FUN_80020078(0xedf), uVar2 != 0)) {
    FUN_800201ac((int)*(short *)(iVar3 + 2),0);
    (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
    *(undefined *)(iVar3 + 6) = 0;
    *(undefined *)(iVar3 + 8) = 0;
  }
  if ((int)*(short *)(iVar3 + 4) != 0) {
    *(short *)(iVar3 + 4) =
         (short)(int)((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 4) ^ 0x80000000) -
                             DOUBLE_803e7118) - FLOAT_803dc074);
    FUN_8000da78(param_1,0x458);
    if (*(short *)(iVar3 + 4) < 1) {
      *(undefined2 *)(iVar3 + 4) = 0;
      sVar1 = *(short *)(iVar3 + 2);
      if (sVar1 == 0x674) {
        FUN_800201ac(0x670,0);
      }
      else if (sVar1 < 0x674) {
        if (sVar1 == 0x672) {
          FUN_800201ac(0x66e,0);
        }
        else if (0x671 < sVar1) {
          FUN_800201ac(0x66f,0);
        }
      }
      else if (sVar1 < 0x676) {
        FUN_800201ac(0x9f5,0);
      }
    }
  }
  return;
}

