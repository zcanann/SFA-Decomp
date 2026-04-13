// Function: FUN_802866d0
// Entry: 802866d0
// Size: 72 bytes

void FUN_802866d0(void)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  
  while (DAT_803df060 != (int *)0x0) {
    puVar1 = DAT_803df060 + 1;
    puVar2 = DAT_803df060 + 2;
    DAT_803df060 = (int *)*DAT_803df060;
    (*(code *)*puVar1)(*puVar2,0xffffffff);
  }
  return;
}

