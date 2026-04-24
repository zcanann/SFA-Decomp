// Function: FUN_800089ac
// Entry: 800089ac
// Size: 416 bytes

void FUN_800089ac(uint *param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = *(uint *)(param_2 & 0xfffffff8);
  uVar2 = ((uint *)(param_2 & 0xfffffff8))[1];
  switch(param_2 & 7) {
  case 0:
    param_1[1] = uVar2;
    *param_1 = uVar1;
    return;
  case 1:
    param_1[1] = param_1[1] & 0xff | uVar2 << 8;
    *param_1 = uVar2 >> 0x18 | uVar1 << 8;
    return;
  case 2:
    param_1[1] = param_1[1] & 0xffff | uVar2 << 0x10;
    *param_1 = uVar2 >> 0x10 | uVar1 << 0x10;
    return;
  case 3:
    param_1[1] = param_1[1] & 0xffffff | uVar2 << 0x18;
    *param_1 = uVar2 >> 8 | uVar1 << 0x18;
    return;
  case 4:
    param_1[1] = param_1[1];
    *param_1 = uVar2;
    return;
  case 5:
    param_1[1] = param_1[1];
    *param_1 = *param_1 & 0xff | uVar2 << 8;
    return;
  case 6:
    param_1[1] = param_1[1];
    *param_1 = *param_1 & 0xffff | uVar2 << 0x10;
    return;
  case 7:
    param_1[1] = param_1[1];
    *param_1 = *param_1 & 0xffffff | uVar2 << 0x18;
    return;
  default:
    return;
  }
}

