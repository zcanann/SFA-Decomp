// Function: FUN_8011fc5c
// Entry: 8011fc5c
// Size: 228 bytes

void FUN_8011fc5c(undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  
  if (DAT_803dd7d0 != (undefined4 *)0x0) {
    if (-1 < *(char *)((int)DAT_803dd7d0 + 0x44)) {
      return;
    }
    FUN_8011f72c();
  }
  puVar1 = (undefined4 *)FUN_80023cc8(0x48,0x19,0);
  FUN_800033a8(puVar1,0,0x48);
  *puVar1 = 0;
  puVar1[1] = param_1;
  puVar1[2] = 0;
  uVar2 = FUN_80054d54(param_2);
  puVar1[0xc] = uVar2;
  *(short *)(puVar1 + 0xb) = (short)param_2;
  uVar2 = FUN_80054d54(0x5d4);
  puVar1[0xd] = uVar2;
  uVar2 = FUN_80054d54(0x5d3);
  puVar1[0xe] = uVar2;
  uVar2 = FUN_80054d54(0x5d2);
  puVar1[0xf] = uVar2;
  DAT_803dd7d0 = puVar1;
  *(undefined *)(puVar1 + 6) = 0;
  puVar1[9] = FLOAT_803e1e68;
  puVar1[0x10] = 1;
  return;
}

