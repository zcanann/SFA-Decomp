// Function: FUN_80167764
// Entry: 80167764
// Size: 384 bytes

undefined4 FUN_80167764(int param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar4 = *(int *)(iVar2 + 0x40c);
  if ((*(short *)(param_2 + 0x274) == 2) &&
     (*(float *)(iVar4 + 0x34) = *(float *)(iVar4 + 0x34) - FLOAT_803db414,
     *(float *)(iVar4 + 0x34) <= FLOAT_803e3060)) {
    *(undefined *)(param_2 + 0x346) = 1;
  }
  if ((*(char *)(param_2 + 0x346) != '\0') || (*(char *)(param_2 + 0x27b) != '\0')) {
    iVar2 = (**(code **)(*DAT_803dcab8 + 0x44))
                      ((double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar2 + 0x3fe))
                                      - DOUBLE_803e3068),param_1,param_2,1);
    if (iVar2 != 0) {
      return 5;
    }
    iVar3 = *(int *)(param_1 + 0x4c);
    iVar2 = FUN_800221a0(0,99);
    if (iVar2 < (int)(uint)*(byte *)(iVar3 + 0x2f)) {
      (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,3);
    }
    else {
      uVar1 = FUN_800221a0(300,600);
      *(float *)(iVar4 + 0x34) =
           (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e3070);
      (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,2);
    }
  }
  return 0;
}

