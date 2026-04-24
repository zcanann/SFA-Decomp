// Function: FUN_802337f8
// Entry: 802337f8
// Size: 240 bytes

void FUN_802337f8(undefined2 *param_1,int param_2,int param_3)

{
  undefined2 uVar1;
  undefined2 *puVar2;
  
  puVar2 = *(undefined2 **)(param_1 + 0x5c);
  uVar1 = FUN_800221a0(100,300);
  *puVar2 = uVar1;
  *(undefined *)((int)puVar2 + 0x15) = *(undefined *)(param_2 + 0x31);
  if (param_3 == 0) {
    uVar1 = FUN_800221a0(0,0xffff);
    param_1[1] = uVar1;
    uVar1 = FUN_800221a0(0,0xffff);
    param_1[2] = uVar1;
    uVar1 = FUN_800221a0(0,0xffff);
    *param_1 = uVar1;
    param_1[3] = param_1[3] | 0x4000;
    *(undefined *)(param_1 + 0x1b) = 0;
  }
  FUN_8008016c(puVar2 + 6);
  FUN_8008016c(puVar2 + 8);
  FUN_80035f00(param_1);
  FUN_80035e8c(param_1);
  return;
}

