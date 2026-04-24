// Function: FUN_80258674
// Entry: 80258674
// Size: 720 bytes

void FUN_80258674(int param_1,int param_2,int param_3,uint param_4,uint param_5,int param_6)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  
  uVar2 = 0;
  iVar3 = 0;
  iVar1 = 5;
  switch(param_3) {
  case 0:
    iVar1 = 0;
    iVar3 = 1;
    break;
  case 1:
    iVar1 = 1;
    iVar3 = 1;
    break;
  case 2:
    iVar1 = 3;
    iVar3 = 1;
    break;
  case 3:
    iVar1 = 4;
    iVar3 = 1;
    break;
  case 4:
    iVar1 = 5;
    break;
  case 5:
    iVar1 = 6;
    break;
  case 6:
    iVar1 = 7;
    break;
  case 7:
    iVar1 = 8;
    break;
  case 8:
    iVar1 = 9;
    break;
  case 9:
    iVar1 = 10;
    break;
  case 10:
    iVar1 = 0xb;
    break;
  case 0xb:
    iVar1 = 0xc;
    break;
  case 0x13:
    iVar1 = 2;
    break;
  case 0x14:
    iVar1 = 2;
  }
  if (param_2 == 1) {
    uVar2 = iVar3 << 2 | iVar1 << 7;
  }
  else if (param_2 < 1) {
    if (-1 < param_2) {
      uVar2 = iVar3 << 2 | 2U | iVar1 << 7;
    }
  }
  else if (param_2 == 10) {
    if (param_3 == 0x13) {
      uVar2 = iVar3 << 2 | 0x20;
    }
    else {
      uVar2 = iVar3 << 2 | 0x30;
    }
    uVar2 = uVar2 | 0x100;
  }
  else if (param_2 < 10) {
    uVar2 = iVar3 << 2 | 0x10U | iVar1 << 7 | (param_3 + -0xc) * 0x1000 & 0xfffc7000U |
            (param_2 + -2) * 0x8000;
  }
  DAT_cc008000._0_1_ = 0x10;
  DAT_cc008000 = param_1 + 0x1040;
  DAT_cc008000 = uVar2;
  DAT_cc008000._0_1_ = 0x10;
  DAT_cc008000 = param_1 + 0x1050;
  DAT_cc008000 = param_6 - 0x40U & 0xfffffeff | (param_5 & 0xff) << 8;
  switch(param_1) {
  case 0:
    *(uint *)(DAT_803dd210 + 0x80) = *(uint *)(DAT_803dd210 + 0x80) & 0xfffff03f | param_4 << 6;
    break;
  case 1:
    *(uint *)(DAT_803dd210 + 0x80) = *(uint *)(DAT_803dd210 + 0x80) & 0xfffc0fff | param_4 << 0xc;
    break;
  case 2:
    *(uint *)(DAT_803dd210 + 0x80) = *(uint *)(DAT_803dd210 + 0x80) & 0xff03ffff | param_4 << 0x12;
    break;
  case 3:
    *(uint *)(DAT_803dd210 + 0x80) = *(uint *)(DAT_803dd210 + 0x80) & 0xc0ffffff | param_4 << 0x18;
    break;
  case 4:
    *(uint *)(DAT_803dd210 + 0x84) = *(uint *)(DAT_803dd210 + 0x84) & 0xffffffc0 | param_4;
    break;
  case 5:
    *(uint *)(DAT_803dd210 + 0x84) = *(uint *)(DAT_803dd210 + 0x84) & 0xfffff03f | param_4 << 6;
    break;
  case 6:
    *(uint *)(DAT_803dd210 + 0x84) = *(uint *)(DAT_803dd210 + 0x84) & 0xfffc0fff | param_4 << 0xc;
    break;
  default:
    *(uint *)(DAT_803dd210 + 0x84) = *(uint *)(DAT_803dd210 + 0x84) & 0xff03ffff | param_4 << 0x12;
  }
  FUN_8025dbf4(param_1 + 1);
  return;
}

