// Function: FUN_80080548
// Entry: 80080548
// Size: 56 bytes

void FUN_80080548(undefined4 param_1)

{
  undefined2 *puVar1;
  
  puVar1 = (undefined2 *)FUN_800395d8(param_1,0);
  if (puVar1 != (undefined2 *)0x0) {
    puVar1[1] = 0;
    *puVar1 = 0;
  }
  return;
}

