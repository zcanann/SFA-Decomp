// Function: FUN_80283488
// Entry: 80283488
// Size: 160 bytes

uint FUN_80283488(int param_1,uint param_2)

{
  uint uVar1;
  
  uVar1 = FUN_80283418(param_2);
  uVar1 = uVar1 & 0xff;
  if (uVar1 == 0xa1) {
    uVar1 = *(short *)(param_1 + 0x1d0) * 2 + 0x2000;
  }
  else if ((uVar1 < 0xa1) && (0x9f < uVar1)) {
    uVar1 = *(short *)(param_1 + 0x1c4) * 2 + 0x2000;
  }
  else if (*(byte *)(param_1 + 0x121) == 0xff) {
    uVar1 = 0;
  }
  else {
    uVar1 = FUN_80282288(param_2,(uint)*(byte *)(param_1 + 0x121),(uint)*(byte *)(param_1 + 0x122));
    uVar1 = uVar1 & 0xffff;
  }
  return uVar1;
}

