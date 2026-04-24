// Function: FUN_8022f80c
// Entry: 8022f80c
// Size: 144 bytes

void FUN_8022f80c(int param_1,char param_2,char param_3)

{
  undefined *puVar1;
  
  puVar1 = *(undefined **)(param_1 + 0xb8);
  if (param_2 == '\0') {
    *puVar1 = 0;
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
  }
  else {
    FUN_8002b95c(param_1,(uint)(param_3 != '\0'));
    *puVar1 = 1;
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
  }
  return;
}

