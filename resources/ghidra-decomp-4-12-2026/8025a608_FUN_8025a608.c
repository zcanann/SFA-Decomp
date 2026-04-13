// Function: FUN_8025a608
// Entry: 8025a608
// Size: 484 bytes

void FUN_8025a608(int param_1,uint param_2,int param_3,uint param_4,uint param_5,int param_6,
                 int param_7)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  
  if (param_1 == 4) {
    iVar3 = 0;
  }
  else {
    iVar3 = param_1;
    if (param_1 == 5) {
      iVar3 = 1;
    }
  }
  if (param_7 == 0) {
    param_6 = 0;
  }
  iVar1 = -param_7 + 2;
  DAT_cc008000._0_1_ = 0x10;
  DAT_cc008000 = iVar3 + 0x100e;
  uVar2 = (((((param_2 & 0xff) << 1 | param_4) & 0xffffff83 | param_3 << 6) & 0xffff867f |
            (uint)((param_5 & 1) != 0) * 4 | (uint)((param_5 & 2) != 0) * 8 |
            (uint)((param_5 & 4) != 0) * 0x10 | (uint)((param_5 & 8) != 0) * 0x20 |
            (uint)((param_5 & 0x10) != 0) * 0x800 | (uint)((param_5 & 0x20) != 0) * 0x1000 |
            (uint)((param_5 & 0x40) != 0) * 0x2000 | (uint)((param_5 & 0x80) != 0) * 0x4000 |
           param_6 << 7) & 0xfffffdff | (iVar1 - ((uint)(iVar1 == 0) + -param_7 + 1)) * 0x200) &
          0xfffffbff | (uint)(param_7 != 0) * 0x400;
  DAT_cc008000 = uVar2;
  *(undefined2 *)(DAT_803dd210 + 2) = 1;
  if (param_1 == 4) {
    DAT_cc008000._0_1_ = 0x10;
    DAT_cc008000 = 0x1010;
    DAT_cc008000 = uVar2;
  }
  else if (param_1 == 5) {
    DAT_cc008000._0_1_ = 0x10;
    DAT_cc008000 = 0x1011;
    DAT_cc008000 = uVar2;
  }
  return;
}

