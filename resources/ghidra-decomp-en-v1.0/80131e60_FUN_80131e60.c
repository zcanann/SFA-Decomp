// Function: FUN_80131e60
// Entry: 80131e60
// Size: 172 bytes

void FUN_80131e60(undefined4 param_1,undefined4 param_2,short param_3,short param_4,short param_5,
                 undefined2 param_6)

{
  undefined2 uVar2;
  undefined2 *puVar1;
  undefined2 extraout_r4;
  
  uVar2 = FUN_802860d8();
  if (param_5 < param_3) {
    param_5 = param_3;
  }
  if (param_4 < param_5) {
    param_5 = param_4;
  }
  puVar1 = (undefined2 *)FUN_80023cc8(0x10,5,0);
  *(undefined *)((int)puVar1 + 5) = 0;
  puVar1[6] = param_5;
  puVar1[4] = param_3;
  puVar1[5] = param_4;
  *puVar1 = uVar2;
  puVar1[1] = extraout_r4;
  *(undefined *)(puVar1 + 2) = 0;
  *(undefined *)(puVar1 + 3) = 4;
  puVar1[7] = param_6;
  FUN_80286124();
  return;
}

