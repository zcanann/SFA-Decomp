// Function: FUN_8025743c
// Entry: 8025743c
// Size: 900 bytes

void FUN_8025743c(int *param_1)

{
  uint uVar1;
  
  for (; *param_1 != 0xff; param_1 = param_1 + 2) {
    uVar1 = param_1[1];
    switch(*param_1) {
    case 0:
      *(uint *)(DAT_803dd210 + 0x14) = *(uint *)(DAT_803dd210 + 0x14) & 0xfffffffe | uVar1;
      break;
    case 1:
      *(uint *)(DAT_803dd210 + 0x14) = *(uint *)(DAT_803dd210 + 0x14) & 0xfffffffd | uVar1 << 1;
      break;
    case 2:
      *(uint *)(DAT_803dd210 + 0x14) = *(uint *)(DAT_803dd210 + 0x14) & 0xfffffffb | uVar1 << 2;
      break;
    case 3:
      *(uint *)(DAT_803dd210 + 0x14) = *(uint *)(DAT_803dd210 + 0x14) & 0xfffffff7 | uVar1 << 3;
      break;
    case 4:
      *(uint *)(DAT_803dd210 + 0x14) = *(uint *)(DAT_803dd210 + 0x14) & 0xffffffef | uVar1 << 4;
      break;
    case 5:
      *(uint *)(DAT_803dd210 + 0x14) = *(uint *)(DAT_803dd210 + 0x14) & 0xffffffdf | uVar1 << 5;
      break;
    case 6:
      *(uint *)(DAT_803dd210 + 0x14) = *(uint *)(DAT_803dd210 + 0x14) & 0xffffffbf | uVar1 << 6;
      break;
    case 7:
      *(uint *)(DAT_803dd210 + 0x14) = *(uint *)(DAT_803dd210 + 0x14) & 0xffffff7f | uVar1 << 7;
      break;
    case 8:
      *(uint *)(DAT_803dd210 + 0x14) = *(uint *)(DAT_803dd210 + 0x14) & 0xfffffeff | uVar1 << 8;
      break;
    case 9:
      *(uint *)(DAT_803dd210 + 0x14) = *(uint *)(DAT_803dd210 + 0x14) & 0xfffff9ff | uVar1 << 9;
      break;
    case 10:
      if (uVar1 == 0) {
        *(undefined *)(DAT_803dd210 + 0x41c) = 0;
      }
      else {
        *(undefined *)(DAT_803dd210 + 0x41c) = 1;
        *(undefined *)(DAT_803dd210 + 0x41d) = 0;
        *(uint *)(DAT_803dd210 + 0x418) = uVar1;
      }
      break;
    case 0xb:
      *(uint *)(DAT_803dd210 + 0x14) = *(uint *)(DAT_803dd210 + 0x14) & 0xffff9fff | uVar1 << 0xd;
      break;
    case 0xc:
      *(uint *)(DAT_803dd210 + 0x14) = *(uint *)(DAT_803dd210 + 0x14) & 0xfffe7fff | uVar1 << 0xf;
      break;
    case 0xd:
      *(uint *)(DAT_803dd210 + 0x18) = *(uint *)(DAT_803dd210 + 0x18) & 0xfffffffc | uVar1;
      break;
    case 0xe:
      *(uint *)(DAT_803dd210 + 0x18) = *(uint *)(DAT_803dd210 + 0x18) & 0xfffffff3 | uVar1 << 2;
      break;
    case 0xf:
      *(uint *)(DAT_803dd210 + 0x18) = *(uint *)(DAT_803dd210 + 0x18) & 0xffffffcf | uVar1 << 4;
      break;
    case 0x10:
      *(uint *)(DAT_803dd210 + 0x18) = *(uint *)(DAT_803dd210 + 0x18) & 0xffffff3f | uVar1 << 6;
      break;
    case 0x11:
      *(uint *)(DAT_803dd210 + 0x18) = *(uint *)(DAT_803dd210 + 0x18) & 0xfffffcff | uVar1 << 8;
      break;
    case 0x12:
      *(uint *)(DAT_803dd210 + 0x18) = *(uint *)(DAT_803dd210 + 0x18) & 0xfffff3ff | uVar1 << 10;
      break;
    case 0x13:
      *(uint *)(DAT_803dd210 + 0x18) = *(uint *)(DAT_803dd210 + 0x18) & 0xffffcfff | uVar1 << 0xc;
      break;
    case 0x14:
      *(uint *)(DAT_803dd210 + 0x18) = *(uint *)(DAT_803dd210 + 0x18) & 0xffff3fff | uVar1 << 0xe;
      break;
    case 0x19:
      if (uVar1 == 0) {
        *(undefined *)(DAT_803dd210 + 0x41d) = 0;
      }
      else {
        *(undefined *)(DAT_803dd210 + 0x41d) = 1;
        *(undefined *)(DAT_803dd210 + 0x41c) = 0;
        *(uint *)(DAT_803dd210 + 0x418) = uVar1;
      }
    }
  }
  if ((*(char *)(DAT_803dd210 + 0x41c) == '\0') && (*(char *)(DAT_803dd210 + 0x41d) == '\0')) {
    *(uint *)(DAT_803dd210 + 0x14) = *(uint *)(DAT_803dd210 + 0x14) & 0xffffe7ff;
  }
  else {
    *(uint *)(DAT_803dd210 + 0x14) =
         *(uint *)(DAT_803dd210 + 0x14) & 0xffffe7ff | *(int *)(DAT_803dd210 + 0x418) << 0xb;
  }
  *(uint *)(DAT_803dd210 + 0x4f4) = *(uint *)(DAT_803dd210 + 0x4f4) | 8;
  return;
}

