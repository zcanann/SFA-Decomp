// Function: FUN_8025edc8
// Entry: 8025edc8
// Size: 184 bytes

undefined4 FUN_8025edc8(int param_1,int **param_2)

{
  undefined4 uVar1;
  
  if (((param_1 < 0) || (1 < param_1)) || ((&DAT_803af2ec)[param_1 * 0x44] == 0)) {
    uVar1 = 0xffffff80;
  }
  else {
    FUN_8024377c();
    if ((&DAT_803af1e0)[param_1 * 0x44] == 0) {
      uVar1 = 0xfffffffd;
    }
    else if ((&DAT_803af1e4)[param_1 * 0x44] == -1) {
      uVar1 = 0xffffffff;
    }
    else {
      (&DAT_803af1e4)[param_1 * 0x44] = 0xffffffff;
      uVar1 = 0;
      *(undefined4 *)(&DAT_803af2b0 + param_1 * 0x110) = 0;
      *param_2 = &DAT_803af1e0 + param_1 * 0x44;
    }
    FUN_802437a4();
  }
  return uVar1;
}

