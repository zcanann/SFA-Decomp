// Function: FUN_8029700c
// Entry: 8029700c
// Size: 208 bytes

void FUN_8029700c(int param_1,int param_2)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  uVar1 = FUN_80020078(0x91b);
  if (uVar1 == 0) {
    uVar1 = FUN_80020078(0x91a);
    if (uVar1 == 0) {
      uVar1 = FUN_80020078(0x919);
      if (uVar1 == 0) {
        uVar1 = 10;
      }
      else {
        uVar1 = 0x32;
      }
    }
    else {
      uVar1 = 100;
    }
  }
  else {
    uVar1 = 200;
  }
  uVar2 = (uint)*(byte *)(*(int *)(iVar3 + 0x35c) + 8) + param_2;
  if ((int)(uint)*(byte *)(iVar3 + 1000) < param_2) {
    *(char *)(iVar3 + 1000) = (char)param_2;
  }
  if ((int)uVar2 < 0) {
    uVar2 = 0;
  }
  else if ((int)uVar1 < (int)uVar2) {
    uVar2 = uVar1;
  }
  *(char *)(*(int *)(iVar3 + 0x35c) + 8) = (char)uVar2;
  FUN_800201ac(0x1be,uVar2);
  return;
}

