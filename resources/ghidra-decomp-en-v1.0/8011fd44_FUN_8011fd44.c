// Function: FUN_8011fd44
// Entry: 8011fd44
// Size: 200 bytes

void FUN_8011fd44(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  
  if (DAT_803dd7d0 == (undefined4 *)0x0) {
    puVar1 = (undefined4 *)FUN_80023cc8(0x48,0x19,0);
    FUN_800033a8(puVar1,0,0x48);
    *puVar1 = 0;
    puVar1[1] = param_1;
    uVar2 = FUN_80054d54(param_2);
    puVar1[0xb] = uVar2;
    uVar2 = FUN_80054d54(param_3);
    puVar1[0xc] = uVar2;
    puVar1[4] = (uint)*(ushort *)(puVar1[0xb] + 10);
    puVar1[5] = (uint)*(ushort *)(puVar1[0xb] + 0xc);
    DAT_803dd7d0 = puVar1;
    *(undefined *)(puVar1 + 6) = 0;
    puVar1[9] = FLOAT_803e1e68;
    puVar1[0x10] = 0;
  }
  return;
}

