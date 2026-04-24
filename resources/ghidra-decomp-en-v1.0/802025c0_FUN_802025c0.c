// Function: FUN_802025c0
// Entry: 802025c0
// Size: 352 bytes

undefined4 FUN_802025c0(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar3 = *(int *)(iVar2 + 0x40c);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80035f20();
  }
  FUN_80035df4(param_1,10,1,0xffffffff);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    iVar1 = FUN_800221a0(0,1);
    if (iVar1 == 0) {
      if (*(char *)(param_2 + 0x27a) != '\0') {
        FUN_80030334((double)FLOAT_803e62a8,param_1,7,0);
        *(undefined *)(param_2 + 0x346) = 0;
      }
    }
    else if (*(char *)(param_2 + 0x27a) != '\0') {
      FUN_80030334((double)FLOAT_803e62a8,param_1,6,0);
      *(undefined *)(param_2 + 0x346) = 0;
    }
    *(undefined *)(param_2 + 0x34d) = 1;
    *(float *)(param_2 + 0x2a0) =
         FLOAT_803e6344 +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x406)) - DOUBLE_803e62e0) /
         FLOAT_803e6348;
  }
  *(float *)(param_2 + 0x280) = FLOAT_803e62a8;
  if (*(char *)(param_2 + 0x346) != '\0') {
    *(undefined *)(iVar3 + 0x34) = 1;
  }
  *(byte *)(iVar3 + 0x14) = *(byte *)(iVar3 + 0x14) | 2;
  return 0;
}

