// Function: FUN_8000881c
// Entry: 8000881c
// Size: 400 bytes

void FUN_8000881c(uint *param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = *(uint *)(param_2 & 0xfffffff8);
  uVar2 = ((uint *)(param_2 & 0xfffffff8))[1];
  switch(param_2 & 7) {
  case 0:
    param_1[1] = param_1[1] & 0xffffff00 | uVar1 >> 0x18;
    *param_1 = *param_1;
    return;
  case 1:
    param_1[1] = param_1[1] & 0xffff0000 | uVar1 >> 0x10;
    *param_1 = *param_1;
    return;
  case 2:
    param_1[1] = param_1[1] & 0xff000000 | uVar1 >> 8;
    *param_1 = *param_1;
    return;
  case 3:
    param_1[1] = uVar1;
    *param_1 = *param_1;
    return;
  case 4:
    param_1[1] = uVar1 << 8 | uVar2 >> 0x18;
    *param_1 = *param_1 & 0xffffff00 | uVar1 >> 0x18;
    return;
  case 5:
    param_1[1] = uVar1 << 0x10 | uVar2 >> 0x10;
    *param_1 = *param_1 & 0xffff0000 | uVar1 >> 0x10;
    return;
  case 6:
    param_1[1] = uVar1 << 0x18 | uVar2 >> 8;
    *param_1 = *param_1 & 0xff000000 | uVar1 >> 8;
    return;
  case 7:
    param_1[1] = uVar2;
    *param_1 = uVar1;
    return;
  default:
    return;
  }
}

