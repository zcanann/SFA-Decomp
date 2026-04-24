// Function: FUN_800207f4
// Entry: 800207f4
// Size: 356 bytes

void FUN_800207f4(void)

{
  undefined4 uVar1;
  
  if (DAT_803dca39 != '\0') {
    FUN_8004a868();
    FUN_8004a43c(1,0);
    FUN_8004a868();
    FUN_8004a43c(1,0);
    FUN_8004a868();
    FUN_8004a43c(1,0);
    FUN_80023834(0);
    if (DAT_803dcac4 != '\0') {
      FUN_8004a3c0(0,0,0);
      FUN_80056f7c();
      if (DAT_803dca40 != '\0') {
        FUN_800437bc(0,0x80000000);
        DAT_803dca40 = '\0';
      }
    }
    uVar1 = FUN_80023834(0);
    DAT_803dca39 = '\0';
    FUN_8000fc54();
    FUN_801375a0();
    if (-1 < DAT_803db41c) {
      FUN_80014948();
      DAT_803db41c = -1;
    }
    FUN_800234ec(1);
    FUN_800234ec(1);
    if ((DAT_803dca41 != '\0') && (DAT_803dcaf8 != -1)) {
      FUN_80041e30();
      FUN_80042f78(DAT_803dcaf8);
      if (DAT_803dcaf4 != -1) {
        FUN_80042e74();
      }
      FUN_80041e24();
      DAT_803dca41 = '\0';
    }
    FUN_80057410();
    if (DAT_803dca94 != (int *)0x0) {
      (**(code **)(*DAT_803dca94 + 0xc))(1);
    }
    FUN_80023834(uVar1);
    DAT_803dcac4 = '\x01';
  }
  return;
}

