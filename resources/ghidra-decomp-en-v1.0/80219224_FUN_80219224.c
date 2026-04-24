// Function: FUN_80219224
// Entry: 80219224
// Size: 440 bytes

undefined4 FUN_80219224(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  double dVar6;
  
  iVar1 = FUN_8002b9ec();
  iVar2 = FUN_8002b9ac();
  iVar5 = *(int *)(param_1 + 0xb8);
  iVar3 = FUN_80296ba0(iVar1);
  if (iVar3 == 0x40) {
    uVar4 = 1;
  }
  else {
    if (((*(byte *)(param_1 + 0xaf) & 1) != 0) &&
       (iVar3 = (**(code **)(*DAT_803dca68 + 0x1c))(), iVar3 == 0)) {
      FUN_80014b3c(0,0x100);
      *(undefined *)(*(int *)(param_1 + 0x54) + 0x6e) = 0xb;
      *(undefined *)(*(int *)(param_1 + 0x54) + 0x6f) = 4;
      uVar4 = FUN_800221a0(0,1);
      (**(code **)(*DAT_803dca54 + 0x48))(uVar4,param_1,0xffffffff);
    }
    if ((((iVar2 != 0) &&
         (dVar6 = (double)FUN_80021690(param_1 + 0x18,iVar2 + 0x18), dVar6 < (double)FLOAT_803e6988)
         ) || ((iVar1 != 0 &&
               (dVar6 = (double)FUN_80021690(param_1 + 0x18,iVar1 + 0x18),
               dVar6 < (double)FLOAT_803e6988)))) && (*(short *)(param_1 + 0xa0) != 9)) {
      FUN_80030334((double)FLOAT_803e698c,param_1,9,0);
      *(float *)(iVar5 + 0x6e0) = FLOAT_803e6990;
      if (iVar2 != 0) {
        (**(code **)(**(int **)(iVar2 + 0x68) + 0x34))(iVar2,0,0);
      }
    }
    if (*(short *)(param_1 + 0xa0) == 9) {
      *(undefined *)(*(int *)(param_1 + 0x54) + 0x6e) = 0xb;
      *(undefined *)(*(int *)(param_1 + 0x54) + 0x6f) = 4;
      FUN_80035df4(param_1,0xb,4,7);
      FUN_8003393c(param_1);
    }
    uVar4 = 0;
  }
  return uVar4;
}

