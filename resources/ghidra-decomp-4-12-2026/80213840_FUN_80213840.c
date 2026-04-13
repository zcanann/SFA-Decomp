// Function: FUN_80213840
// Entry: 80213840
// Size: 544 bytes

undefined4 FUN_80213840(int param_1,int param_2)

{
  undefined4 uVar1;
  
  if (*(char *)(param_2 + 0x27b) == '\0') {
    *(float *)(DAT_803de9d4 + 4) = *(float *)(DAT_803de9d4 + 4) - FLOAT_803dc074;
    if ((*(float *)(DAT_803de9d4 + 4) <= FLOAT_803e7488) && (*(int *)(param_1 + 0xf8) != 3)) {
      (**(code **)(*DAT_803dd6cc + 8))(0x1e,1);
      *(undefined4 *)(param_1 + 0xf8) = 3;
    }
    if (*(float *)(DAT_803de9d4 + 4) <= FLOAT_803e7450) {
      uVar1 = FUN_8002bac4();
      FUN_8002ad08(uVar1,0,0,0,0,0);
      FUN_8000a538((int *)0x28,0);
      FUN_8000a538((int *)0x93,0);
      FUN_8000a538((int *)0x94,0);
      *(undefined *)(param_1 + 0xad) = 1;
      FUN_800201ac(0x564,1);
      FUN_800201ac(0x36a,0);
      (**(code **)(*DAT_803dd72c + 0x50))(0xd,0,1);
      (**(code **)(*DAT_803dd72c + 0x50))(0xd,1,1);
      (**(code **)(*DAT_803dd72c + 0x50))(0xd,5,1);
      (**(code **)(*DAT_803dd72c + 0x50))(0xd,10,1);
      (**(code **)(*DAT_803dd72c + 0x50))(0xd,0xb,1);
      FUN_800201ac(0xe05,0);
      FUN_80043604(0x35,1,0);
      FUN_800201ac(0x83b,1);
      (**(code **)(*DAT_803dd72c + 0x44))(4,2);
    }
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    *(undefined *)(param_2 + 0x349) = 0;
    *(undefined *)(param_2 + 0x25f) = 0;
    *(float *)(DAT_803de9d4 + 4) = FLOAT_803e7484;
  }
  return 0;
}

