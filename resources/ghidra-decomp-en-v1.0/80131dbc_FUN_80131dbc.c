// Function: FUN_80131dbc
// Entry: 80131dbc
// Size: 164 bytes

void FUN_80131dbc(undefined4 param_1,undefined4 param_2,short param_3,short param_4,short param_5)

{
  undefined2 uVar2;
  undefined2 *puVar1;
  undefined2 extraout_r4;
  
  uVar2 = FUN_802860dc();
  if (param_5 < param_3) {
    param_5 = param_3;
  }
  if (param_4 < param_5) {
    param_5 = param_4;
  }
  puVar1 = (undefined2 *)FUN_80023cc8(0xe,5,0);
  *(undefined *)((int)puVar1 + 5) = 1;
  puVar1[6] = param_5;
  puVar1[4] = param_3;
  puVar1[5] = param_4;
  *puVar1 = uVar2;
  puVar1[1] = extraout_r4;
  *(undefined *)(puVar1 + 2) = 0;
  *(undefined *)(puVar1 + 3) = 4;
  FUN_80286128();
  return;
}

