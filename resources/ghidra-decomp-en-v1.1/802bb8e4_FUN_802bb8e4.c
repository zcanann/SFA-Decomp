// Function: FUN_802bb8e4
// Entry: 802bb8e4
// Size: 180 bytes

undefined4 FUN_802bb8e4(int param_1)

{
  byte bVar1;
  undefined4 uVar2;
  int iVar3;
  float local_8 [2];
  
  local_8[0] = FLOAT_803e8ed8;
  bVar1 = *(byte *)(*(int *)(param_1 + 0xb8) + 0xa8c);
  if ((bVar1 == 5) || ((bVar1 < 5 && (bVar1 == 0)))) {
    uVar2 = 0;
  }
  else if (*(short *)(*(int *)(param_1 + 0xb8) + 0x274) == 7) {
    if (*(int *)(param_1 + 0xc0) == 0) {
      iVar3 = FUN_80036f50(0x13,param_1,local_8);
      if ((iVar3 == 0) || ((*(byte *)(iVar3 + 0xaf) & 4) == 0)) {
        uVar2 = 0;
      }
      else {
        FUN_80014b68(0,0x100);
        uVar2 = 1;
      }
    }
    else {
      uVar2 = 0;
    }
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}

