// Function: FUN_80259504
// Entry: 80259504
// Size: 368 bytes

void FUN_80259504(ushort param_1,ushort param_2,uint param_3,uint param_4)

{
  uint uVar1;
  uint uVar2;
  int local_18;
  int iStack_14;
  int local_10 [2];
  
  uVar2 = param_3 & 0xf;
  *(undefined *)(DAT_803dd210 + 0x200) = 0;
  if (param_3 == 0x13) {
    uVar2 = 0xb;
  }
  if ((param_3 == 0x26) || ((((int)param_3 < 0x26 && ((int)param_3 < 4)) && (-1 < (int)param_3)))) {
    *(uint *)(DAT_803dd210 + 0x1fc) = *(uint *)(DAT_803dd210 + 0x1fc) & 0xfffe7fff | 0x18000;
  }
  else {
    *(uint *)(DAT_803dd210 + 0x1fc) = *(uint *)(DAT_803dd210 + 0x1fc) & 0xfffe7fff | 0x10000;
  }
  uVar1 = countLeadingZeros((param_3 & 0x10) - 0x10);
  *(char *)(DAT_803dd210 + 0x200) = (char)(uVar1 >> 5);
  *(uint *)(DAT_803dd210 + 0x1fc) = uVar2 & 8 | *(uint *)(DAT_803dd210 + 0x1fc) & 0xfffffff7;
  FUN_8025a9ac(param_3,param_1,param_2,local_10,&iStack_14,&local_18);
  *(undefined4 *)(DAT_803dd210 + 0x1f8) = 0;
  *(uint *)(DAT_803dd210 + 0x1f8) =
       *(uint *)(DAT_803dd210 + 0x1f8) & 0xfffffc00 | local_10[0] * local_18;
  *(uint *)(DAT_803dd210 + 0x1f8) = *(uint *)(DAT_803dd210 + 0x1f8) & 0xffffff | 0x4d000000;
  *(uint *)(DAT_803dd210 + 0x1fc) =
       *(uint *)(DAT_803dd210 + 0x1fc) & 0xfffffdff | (param_4 & 0xff) << 9;
  *(uint *)(DAT_803dd210 + 0x1fc) = *(uint *)(DAT_803dd210 + 0x1fc) & 0xffffff8f | (uVar2 & 7) << 4;
  return;
}

