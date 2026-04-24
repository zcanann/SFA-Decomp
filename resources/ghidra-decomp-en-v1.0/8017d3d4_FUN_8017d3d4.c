// Function: FUN_8017d3d4
// Entry: 8017d3d4
// Size: 124 bytes

void FUN_8017d3d4(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  undefined4 uVar1;
  int iVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_802860dc();
  uVar1 = (undefined4)((ulonglong)uVar3 >> 0x20);
  iVar2 = (**(code **)(*DAT_803dcac0 + 0xc))(uVar1,(int)param_6);
  if (iVar2 != 0) {
    FUN_8003b8f4((double)FLOAT_803e37b8,uVar1,(int)uVar3,param_3,param_4,param_5);
  }
  FUN_80286128();
  return;
}

