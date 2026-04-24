// Function: FUN_8027595c
// Entry: 8027595c
// Size: 476 bytes

/* WARNING: Removing unreachable block (ram,0x802759c0) */

void FUN_8027595c(int param_1,uint *param_2)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  
  uVar4 = *param_2 >> 8 & 0xffff;
  iVar1 = FUN_80274f20(uVar4,&DAT_803ca2b0);
  if (iVar1 == 0) {
    uVar2 = *param_2 >> 0x18;
    if (uVar2 == 1) {
      DAT_803ca2bc = (param_2[1] * (0x7f - (*(uint *)(param_1 + 0x154) >> 0x10) & 0xff)) / 0x7f;
    }
    else if (uVar2 == 0) {
      DAT_803ca2bc = param_2[1];
    }
    else if (uVar2 < 3) {
      DAT_803ca2bc = (param_2[1] * (*(uint *)(param_1 + 0x154) >> 0x10 & 0xff)) / 0x7f;
    }
    else {
      DAT_803ca2bc = 0;
    }
    if (DAT_803ca2c0 <= DAT_803ca2bc) {
      DAT_803ca2bc = DAT_803ca2c0 - 1;
    }
    uVar3 = countLeadingZeros(*(uint *)(param_1 + 0x114) & 0x800);
    uVar2 = countLeadingZeros(*(uint *)(param_1 + 0x118) & 0x100);
    FUN_80283290(*(uint *)(param_1 + 0xf4) & 0xff,uVar4,&DAT_803ca2b0,uVar2 >> 5,
                 (uint)*(byte *)(param_1 + 0x10c) << 0x18 | *(uint *)(param_1 + 0x110) >> 0xf,
                 *(uint *)(param_1 + 0xf4),uVar3 >> 5,*(undefined *)(param_1 + 0x193));
    *(undefined4 *)(param_1 + 0x124) = DAT_803ca2b0;
    if (*(int *)(param_1 + 0x128) != -1) {
      FUN_80275cb8(param_1);
    }
    *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) | 0x20;
    FUN_80271370(param_1);
  }
  return;
}

