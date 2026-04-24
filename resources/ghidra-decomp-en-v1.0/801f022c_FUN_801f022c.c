// Function: FUN_801f022c
// Entry: 801f022c
// Size: 192 bytes

void FUN_801f022c(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_802860d8();
  iVar1 = (int)((ulonglong)uVar3 >> 0x20);
  iVar2 = FUN_8001ffb4(0x78);
  if ((((iVar2 == 0) && (param_6 != '\0')) &&
      ((*(short *)(iVar1 + 0x46) != 0x188 || (*(int *)(*(int *)(iVar1 + 0x30) + 0xf4) < 7)))) &&
     (FUN_8003b8f4((double)FLOAT_803e5ce8,iVar1,(int)uVar3,param_3,param_4,param_5),
     DAT_803ddc70 != '\0')) {
    (**(code **)(*DAT_803dca90 + 4))(1);
  }
  FUN_80286124();
  return;
}

