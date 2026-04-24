// Function: FUN_80258330
// Entry: 80258330
// Size: 204 bytes

void FUN_80258330(void)

{
  undefined8 uVar1;
  undefined8 uVar2;
  
  *(undefined4 *)(DAT_803de0a8 + 0x18) = 1;
  uVar1 = FUN_80246c50();
  do {
    uVar2 = FUN_80246c50();
  } while ((uint)(0x32 < (uint)uVar2 - (uint)uVar1) +
           ((int)((ulonglong)uVar2 >> 0x20) -
            ((uint)((uint)uVar2 < (uint)uVar1) + (int)((ulonglong)uVar1 >> 0x20)) ^ 0x80000000) <
           0x80000001);
  *(undefined4 *)(DAT_803de0a8 + 0x18) = 0;
  uVar1 = FUN_80246c50();
  do {
    uVar2 = FUN_80246c50();
  } while ((uint)(5 < (uint)uVar2 - (uint)uVar1) +
           ((int)((ulonglong)uVar2 >> 0x20) -
            ((uint)((uint)uVar2 < (uint)uVar1) + (int)((ulonglong)uVar1 >> 0x20)) ^ 0x80000000) <
           0x80000001);
  FUN_80256714();
  return;
}

