// Function: FUN_8025c0c4
// Entry: 8025c0c4
// Size: 476 bytes

void FUN_8025c0c4(uint param_1,int param_2,uint param_3,int param_4)

{
  int iVar1;
  uint *puVar2;
  uint uVar3;
  
  iVar1 = DAT_803dc5a8;
  uVar3 = param_3 & 0xfffffeff;
  *(uint *)(DAT_803dc5a8 + param_1 * 4 + 0x49c) = param_3;
  puVar2 = (uint *)(iVar1 + (((int)param_1 >> 1) + (uint)((int)param_1 < 0 && (param_1 & 1) != 0)) *
                            4 + 0x100);
  if (7 < uVar3) {
    uVar3 = 0;
  }
  if (param_2 < 8) {
    *(uint *)(DAT_803dc5a8 + 0x4e0) = *(uint *)(DAT_803dc5a8 + 0x4e0) | 1 << param_1;
  }
  else {
    param_2 = 0;
    *(uint *)(DAT_803dc5a8 + 0x4e0) = *(uint *)(DAT_803dc5a8 + 0x4e0) & ~(1 << param_1);
  }
  if ((param_1 & 1) == 0) {
    *puVar2 = *puVar2 & 0xfffffff8 | uVar3;
    *puVar2 = *puVar2 & 0xffffffc7 | param_2 << 3;
    if (param_4 == 0xff) {
      iVar1 = 7;
    }
    else {
      iVar1 = *(int *)(&DAT_8032ea88 + param_4 * 4);
    }
    *puVar2 = *puVar2 & 0xfffffc7f | iVar1 << 7;
    iVar1 = 0;
    if ((param_3 != 0xff) && ((param_3 & 0x100) == 0)) {
      iVar1 = 1;
    }
    *puVar2 = *puVar2 & 0xffffffbf | iVar1 << 6;
  }
  else {
    *puVar2 = *puVar2 & 0xffff8fff | uVar3 << 0xc;
    *puVar2 = *puVar2 & 0xfffc7fff | param_2 << 0xf;
    if (param_4 == 0xff) {
      iVar1 = 7;
    }
    else {
      iVar1 = *(int *)(&DAT_8032ea88 + param_4 * 4);
    }
    *puVar2 = *puVar2 & 0xffc7ffff | iVar1 << 0x13;
    iVar1 = 0;
    if ((param_3 != 0xff) && ((param_3 & 0x100) == 0)) {
      iVar1 = 1;
    }
    *puVar2 = *puVar2 & 0xfffbffff | iVar1 << 0x12;
  }
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*puVar2);
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  *(uint *)(DAT_803dc5a8 + 0x4f4) = *(uint *)(DAT_803dc5a8 + 0x4f4) | 1;
  return;
}

