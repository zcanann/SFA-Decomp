// Function: FUN_8018d728
// Entry: 8018d728
// Size: 156 bytes

void FUN_8018d728(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar3 >> 0x20);
  if (((param_6 != '\0') && (*(short *)(iVar1 + 0x46) != 0x1b8)) &&
     (((param_6 != '\0' && (*(short *)(iVar1 + 0x46) != 0x6bf)) ||
      (iVar2 = FUN_8001ffb4((int)*(short *)(*(int *)(iVar1 + 0xb8) + 0x3a)), iVar2 != 0)))) {
    FUN_8003b8f4((double)FLOAT_803e3dd8,iVar1,(int)uVar3,param_3,param_4,param_5);
  }
  FUN_80286128();
  return;
}

