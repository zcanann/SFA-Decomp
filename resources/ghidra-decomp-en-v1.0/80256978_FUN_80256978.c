// Function: FUN_80256978
// Entry: 80256978
// Size: 864 bytes

void FUN_80256978(undefined4 param_1,uint param_2)

{
  switch(param_1) {
  case 0:
    *(uint *)(DAT_803dc5a8 + 0x14) = *(uint *)(DAT_803dc5a8 + 0x14) & 0xfffffffe | param_2;
    break;
  case 1:
    *(uint *)(DAT_803dc5a8 + 0x14) = *(uint *)(DAT_803dc5a8 + 0x14) & 0xfffffffd | param_2 << 1;
    break;
  case 2:
    *(uint *)(DAT_803dc5a8 + 0x14) = *(uint *)(DAT_803dc5a8 + 0x14) & 0xfffffffb | param_2 << 2;
    break;
  case 3:
    *(uint *)(DAT_803dc5a8 + 0x14) = *(uint *)(DAT_803dc5a8 + 0x14) & 0xfffffff7 | param_2 << 3;
    break;
  case 4:
    *(uint *)(DAT_803dc5a8 + 0x14) = *(uint *)(DAT_803dc5a8 + 0x14) & 0xffffffef | param_2 << 4;
    break;
  case 5:
    *(uint *)(DAT_803dc5a8 + 0x14) = *(uint *)(DAT_803dc5a8 + 0x14) & 0xffffffdf | param_2 << 5;
    break;
  case 6:
    *(uint *)(DAT_803dc5a8 + 0x14) = *(uint *)(DAT_803dc5a8 + 0x14) & 0xffffffbf | param_2 << 6;
    break;
  case 7:
    *(uint *)(DAT_803dc5a8 + 0x14) = *(uint *)(DAT_803dc5a8 + 0x14) & 0xffffff7f | param_2 << 7;
    break;
  case 8:
    *(uint *)(DAT_803dc5a8 + 0x14) = *(uint *)(DAT_803dc5a8 + 0x14) & 0xfffffeff | param_2 << 8;
    break;
  case 9:
    *(uint *)(DAT_803dc5a8 + 0x14) = *(uint *)(DAT_803dc5a8 + 0x14) & 0xfffff9ff | param_2 << 9;
    break;
  case 10:
    if (param_2 == 0) {
      *(undefined *)(DAT_803dc5a8 + 0x41c) = 0;
    }
    else {
      *(undefined *)(DAT_803dc5a8 + 0x41c) = 1;
      *(undefined *)(DAT_803dc5a8 + 0x41d) = 0;
      *(uint *)(DAT_803dc5a8 + 0x418) = param_2;
    }
    break;
  case 0xb:
    *(uint *)(DAT_803dc5a8 + 0x14) = *(uint *)(DAT_803dc5a8 + 0x14) & 0xffff9fff | param_2 << 0xd;
    break;
  case 0xc:
    *(uint *)(DAT_803dc5a8 + 0x14) = *(uint *)(DAT_803dc5a8 + 0x14) & 0xfffe7fff | param_2 << 0xf;
    break;
  case 0xd:
    *(uint *)(DAT_803dc5a8 + 0x18) = *(uint *)(DAT_803dc5a8 + 0x18) & 0xfffffffc | param_2;
    break;
  case 0xe:
    *(uint *)(DAT_803dc5a8 + 0x18) = *(uint *)(DAT_803dc5a8 + 0x18) & 0xfffffff3 | param_2 << 2;
    break;
  case 0xf:
    *(uint *)(DAT_803dc5a8 + 0x18) = *(uint *)(DAT_803dc5a8 + 0x18) & 0xffffffcf | param_2 << 4;
    break;
  case 0x10:
    *(uint *)(DAT_803dc5a8 + 0x18) = *(uint *)(DAT_803dc5a8 + 0x18) & 0xffffff3f | param_2 << 6;
    break;
  case 0x11:
    *(uint *)(DAT_803dc5a8 + 0x18) = *(uint *)(DAT_803dc5a8 + 0x18) & 0xfffffcff | param_2 << 8;
    break;
  case 0x12:
    *(uint *)(DAT_803dc5a8 + 0x18) = *(uint *)(DAT_803dc5a8 + 0x18) & 0xfffff3ff | param_2 << 10;
    break;
  case 0x13:
    *(uint *)(DAT_803dc5a8 + 0x18) = *(uint *)(DAT_803dc5a8 + 0x18) & 0xffffcfff | param_2 << 0xc;
    break;
  case 0x14:
    *(uint *)(DAT_803dc5a8 + 0x18) = *(uint *)(DAT_803dc5a8 + 0x18) & 0xffff3fff | param_2 << 0xe;
    break;
  case 0x19:
    if (param_2 == 0) {
      *(undefined *)(DAT_803dc5a8 + 0x41d) = 0;
    }
    else {
      *(undefined *)(DAT_803dc5a8 + 0x41d) = 1;
      *(undefined *)(DAT_803dc5a8 + 0x41c) = 0;
      *(uint *)(DAT_803dc5a8 + 0x418) = param_2;
    }
  }
  if ((*(char *)(DAT_803dc5a8 + 0x41c) == '\0') && (*(char *)(DAT_803dc5a8 + 0x41d) == '\0')) {
    *(uint *)(DAT_803dc5a8 + 0x14) = *(uint *)(DAT_803dc5a8 + 0x14) & 0xffffe7ff;
  }
  else {
    *(uint *)(DAT_803dc5a8 + 0x14) =
         *(uint *)(DAT_803dc5a8 + 0x14) & 0xffffe7ff | *(int *)(DAT_803dc5a8 + 0x418) << 0xb;
  }
  *(uint *)(DAT_803dc5a8 + 0x4f4) = *(uint *)(DAT_803dc5a8 + 0x4f4) | 8;
  return;
}

