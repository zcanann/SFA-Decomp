// Function: FUN_802968ac
// Entry: 802968ac
// Size: 208 bytes

void FUN_802968ac(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  iVar1 = FUN_8001ffb4(0x91b);
  if (iVar1 == 0) {
    iVar1 = FUN_8001ffb4(0x91a);
    if (iVar1 == 0) {
      iVar1 = FUN_8001ffb4(0x919);
      if (iVar1 == 0) {
        iVar1 = 10;
      }
      else {
        iVar1 = 0x32;
      }
    }
    else {
      iVar1 = 100;
    }
  }
  else {
    iVar1 = 200;
  }
  iVar2 = (uint)*(byte *)(*(int *)(iVar3 + 0x35c) + 8) + param_2;
  if ((int)(uint)*(byte *)(iVar3 + 1000) < param_2) {
    *(char *)(iVar3 + 1000) = (char)param_2;
  }
  if (iVar2 < 0) {
    iVar2 = 0;
  }
  else if (iVar1 < iVar2) {
    iVar2 = iVar1;
  }
  *(char *)(*(int *)(iVar3 + 0x35c) + 8) = (char)iVar2;
  FUN_800200e8(0x1be);
  return;
}

