// Function: FUN_802081f4
// Entry: 802081f4
// Size: 436 bytes

void FUN_802081f4(int param_1)

{
  short sVar2;
  int iVar1;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  sVar2 = FUN_8001ffb4((int)*(short *)(iVar3 + 2));
  if (((*(char *)(iVar3 + 6) == '\0') && (sVar2 != 0)) && (iVar1 = FUN_8001ffb4(0xedf), iVar1 != 0))
  {
    (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
    *(undefined *)(iVar3 + 6) = 1;
  }
  if (((*(char *)(iVar3 + 8) != '\0') && (*(char *)(iVar3 + 6) != '\0')) &&
     (iVar1 = FUN_8001ffb4(0xedf), iVar1 != 0)) {
    FUN_800200e8((int)*(short *)(iVar3 + 2),0);
    (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
    *(undefined *)(iVar3 + 6) = 0;
    *(undefined *)(iVar3 + 8) = 0;
  }
  if ((int)*(short *)(iVar3 + 4) != 0) {
    *(short *)(iVar3 + 4) =
         (short)(int)((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 4) ^ 0x80000000) -
                             DOUBLE_803e6480) - FLOAT_803db414);
    FUN_8000da58(param_1,0x458);
    if (*(short *)(iVar3 + 4) < 1) {
      *(undefined2 *)(iVar3 + 4) = 0;
      sVar2 = *(short *)(iVar3 + 2);
      if (sVar2 == 0x674) {
        FUN_800200e8(0x670,0);
      }
      else if (sVar2 < 0x674) {
        if (sVar2 == 0x672) {
          FUN_800200e8(0x66e,0);
        }
        else if (0x671 < sVar2) {
          FUN_800200e8(0x66f,0);
        }
      }
      else if (sVar2 < 0x676) {
        FUN_800200e8(0x9f5,0);
      }
    }
  }
  return;
}

