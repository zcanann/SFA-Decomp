// Function: FUN_801d5b68
// Entry: 801d5b68
// Size: 480 bytes

void FUN_801d5b68(undefined4 param_1,int param_2,int param_3)

{
  int iVar1;
  uint uVar2;
  
  *(undefined **)(param_2 + 0x62c) = &DAT_803273d4;
  switch(*(undefined *)(param_2 + 0x626)) {
  case 1:
    *(uint *)(param_2 + 0x62c) = (uint)*(byte *)(param_3 + 0x1a) * 2 + -0x7fcd8c1c;
    break;
  case 2:
    iVar1 = FUN_8001ffb4(0x9e);
    if (iVar1 == 0) {
      *(uint *)(param_2 + 0x62c) = (uint)*(byte *)(param_3 + 0x1a) * 2 + -0x7fcd8c10;
    }
    else {
      *(uint *)(param_2 + 0x62c) = (uint)*(byte *)(param_3 + 0x1a) * 2 + -0x7fcd8c04;
    }
    break;
  case 3:
    iVar1 = FUN_8001ffb4(0x193);
    if (iVar1 == 0) {
      *(uint *)(param_2 + 0x62c) = (uint)*(byte *)(param_3 + 0x1a) * 2 + -0x7fcd8bf8;
    }
    else {
      *(uint *)(param_2 + 0x62c) = (uint)*(byte *)(param_3 + 0x1a) * 2 + -0x7fcd8bec;
    }
    break;
  case 5:
    iVar1 = FUN_8001ffb4(0x23d);
    if (iVar1 == 0) {
      *(uint *)(param_2 + 0x62c) = (uint)*(byte *)(param_3 + 0x1a) * 2 + -0x7fcd8be0;
    }
    break;
  case 6:
    iVar1 = FUN_801d4cd0();
    if (iVar1 != 0) {
      *(undefined *)(param_2 + 0x624) = 0xe;
      return;
    }
    if (*(char *)(param_2 + 0x624) == '\x0e') {
      FUN_8000bb18(0,0x409);
      *(undefined *)(param_2 + 0x624) = 0;
      uVar2 = FUN_800221a0(1000,2000);
      *(float *)(param_2 + 0x630) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5428);
    }
    iVar1 = FUN_8001ffb4(0x13f);
    if (iVar1 == 0) {
      *(undefined **)(param_2 + 0x62c) = &DAT_803dc004;
    }
    break;
  case 8:
    *(uint *)(param_2 + 0x62c) = (uint)*(byte *)(param_3 + 0x1a) * 2 + -0x7fcd8bd4;
  }
  FUN_801d5174(param_1,param_2);
  return;
}

