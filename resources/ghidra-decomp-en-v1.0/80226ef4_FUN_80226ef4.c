// Function: FUN_80226ef4
// Entry: 80226ef4
// Size: 360 bytes

void FUN_80226ef4(int param_1)

{
  int iVar1;
  char cVar2;
  undefined4 uVar3;
  undefined auStack24 [16];
  
  uVar3 = *(undefined4 *)(param_1 + 0xb8);
  if (*(int *)(param_1 + 0xf4) == 0) {
    iVar1 = FUN_8001ffb4(0xe05);
    if (iVar1 == 0) {
      FUN_80008b74(param_1,param_1,0x1fb,0);
      FUN_80008b74(param_1,param_1,0x1ff,0);
      FUN_80008b74(param_1,param_1,0x1fc,0);
      FUN_80008b74(param_1,param_1,0x1fd,0);
      FUN_80088e54((double)FLOAT_803e6da8,0);
      FUN_800200e8(0xe05,1);
    }
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  cVar2 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0xac));
  if (cVar2 == '\x02') {
    FUN_802251b4(param_1,uVar3);
  }
  else {
    FUN_8022578c(param_1,uVar3);
  }
  FUN_80226d4c(uVar3);
  iVar1 = (**(code **)(*DAT_803dca58 + 0x24))(auStack24);
  if (iVar1 == 0) {
    FUN_800200e8(0x7f3,0);
    FUN_800200e8(0x7f1,1);
  }
  else {
    FUN_800200e8(0x7f3,1);
    FUN_800200e8(0x7f1,0);
  }
  return;
}

