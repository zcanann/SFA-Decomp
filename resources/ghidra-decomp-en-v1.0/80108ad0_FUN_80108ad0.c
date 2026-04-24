// Function: FUN_80108ad0
// Entry: 80108ad0
// Size: 156 bytes

void FUN_80108ad0(undefined2 *param_1)

{
  undefined2 *puVar1;
  
  puVar1 = (undefined2 *)(**(code **)(*DAT_803dca50 + 0xc))();
  if ((puVar1 != (undefined2 *)0x0) && (param_1 != (undefined2 *)0x0)) {
    *puVar1 = *param_1;
    puVar1[1] = param_1[1];
    puVar1[2] = param_1[2];
    *(undefined4 *)(puVar1 + 6) = *(undefined4 *)(param_1 + 4);
    *(undefined4 *)(puVar1 + 8) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(puVar1 + 10) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(puVar1 + 0xc) = *(undefined4 *)(param_1 + 4);
    *(undefined4 *)(puVar1 + 0xe) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(puVar1 + 0x10) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(puVar1 + 0x5a) = *(undefined4 *)(param_1 + 10);
  }
  return;
}

