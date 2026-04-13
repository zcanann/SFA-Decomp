// Function: FUN_80257938
// Entry: 80257938
// Size: 436 bytes

void FUN_80257938(undefined4 param_1,uint *param_2)

{
  uint uVar1;
  
  switch(param_1) {
  case 0:
    uVar1 = *(uint *)(DAT_803dd210 + 0x14) & 1;
    break;
  case 1:
    uVar1 = *(uint *)(DAT_803dd210 + 0x14) >> 1 & 1;
    break;
  case 2:
    uVar1 = *(uint *)(DAT_803dd210 + 0x14) >> 2 & 1;
    break;
  case 3:
    uVar1 = *(uint *)(DAT_803dd210 + 0x14) >> 3 & 1;
    break;
  case 4:
    uVar1 = *(uint *)(DAT_803dd210 + 0x14) >> 4 & 1;
    break;
  case 5:
    uVar1 = *(uint *)(DAT_803dd210 + 0x14) >> 5 & 1;
    break;
  case 6:
    uVar1 = *(uint *)(DAT_803dd210 + 0x14) >> 6 & 1;
    break;
  case 7:
    uVar1 = *(uint *)(DAT_803dd210 + 0x14) >> 7 & 1;
    break;
  case 8:
    uVar1 = *(uint *)(DAT_803dd210 + 0x14) >> 8 & 1;
    break;
  case 9:
    uVar1 = *(uint *)(DAT_803dd210 + 0x14) >> 9 & 3;
    break;
  case 10:
    if (*(char *)(DAT_803dd210 + 0x41c) == '\0') {
      uVar1 = 0;
    }
    else {
      uVar1 = *(uint *)(DAT_803dd210 + 0x14) >> 0xb & 3;
    }
    break;
  case 0xb:
    uVar1 = *(uint *)(DAT_803dd210 + 0x14) >> 0xd & 3;
    break;
  case 0xc:
    uVar1 = *(uint *)(DAT_803dd210 + 0x14) >> 0xf & 3;
    break;
  case 0xd:
    uVar1 = *(uint *)(DAT_803dd210 + 0x18) & 3;
    break;
  case 0xe:
    uVar1 = *(uint *)(DAT_803dd210 + 0x18) >> 2 & 3;
    break;
  case 0xf:
    uVar1 = *(uint *)(DAT_803dd210 + 0x18) >> 4 & 3;
    break;
  case 0x10:
    uVar1 = *(uint *)(DAT_803dd210 + 0x18) >> 6 & 3;
    break;
  case 0x11:
    uVar1 = *(uint *)(DAT_803dd210 + 0x18) >> 8 & 3;
    break;
  case 0x12:
    uVar1 = *(uint *)(DAT_803dd210 + 0x18) >> 10 & 3;
    break;
  case 0x13:
    uVar1 = *(uint *)(DAT_803dd210 + 0x18) >> 0xc & 3;
    break;
  case 0x14:
    uVar1 = *(uint *)(DAT_803dd210 + 0x18) >> 0xe & 3;
    break;
  default:
    uVar1 = 0;
    break;
  case 0x19:
    if (*(char *)(DAT_803dd210 + 0x41d) == '\0') {
      uVar1 = 0;
    }
    else {
      uVar1 = *(uint *)(DAT_803dd210 + 0x14) >> 0xb & 3;
    }
  }
  *param_2 = uVar1;
  return;
}

