// Function: FUN_802131c8
// Entry: 802131c8
// Size: 544 bytes

undefined4 FUN_802131c8(int param_1,int param_2)

{
  undefined4 uVar1;
  
  if (*(char *)(param_2 + 0x27b) == '\0') {
    *(float *)(DAT_803ddd54 + 4) = *(float *)(DAT_803ddd54 + 4) - FLOAT_803db414;
    if ((*(float *)(DAT_803ddd54 + 4) <= FLOAT_803e67f0) && (*(int *)(param_1 + 0xf8) != 3)) {
      (**(code **)(*DAT_803dca4c + 8))(0x1e,1);
      *(undefined4 *)(param_1 + 0xf8) = 3;
    }
    if (*(float *)(DAT_803ddd54 + 4) <= FLOAT_803e67b8) {
      uVar1 = FUN_8002b9ec();
      FUN_8002ac30(uVar1,0,0,0,0,0);
      FUN_8000a518(0x28,0);
      FUN_8000a518(0x93,0);
      FUN_8000a518(0x94,0);
      *(undefined *)(param_1 + 0xad) = 1;
      FUN_800200e8(0x564,1);
      FUN_800200e8(0x36a,0);
      (**(code **)(*DAT_803dcaac + 0x50))(0xd,0,1);
      (**(code **)(*DAT_803dcaac + 0x50))(0xd,1,1);
      (**(code **)(*DAT_803dcaac + 0x50))(0xd,5,1);
      (**(code **)(*DAT_803dcaac + 0x50))(0xd,10,1);
      (**(code **)(*DAT_803dcaac + 0x50))(0xd,0xb,1);
      FUN_800200e8(0xe05,0);
      FUN_8004350c(0x35,1,0);
      FUN_800200e8(0x83b,1);
      (**(code **)(*DAT_803dcaac + 0x44))(4,2);
    }
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    *(undefined *)(param_2 + 0x349) = 0;
    *(undefined *)(param_2 + 0x25f) = 0;
    *(float *)(DAT_803ddd54 + 4) = FLOAT_803e67ec;
  }
  return 0;
}

