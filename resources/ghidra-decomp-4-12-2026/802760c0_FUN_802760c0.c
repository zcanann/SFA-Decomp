// Function: FUN_802760c0
// Entry: 802760c0
// Size: 476 bytes

/* WARNING: Removing unreachable block (ram,0x80276124) */

void FUN_802760c0(int *param_1,uint *param_2)

{
  undefined2 uVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  
  uVar1 = (undefined2)(*param_2 >> 8);
  iVar2 = FUN_80275684(uVar1,&DAT_803caf10);
  if (iVar2 == 0) {
    uVar3 = *param_2 >> 0x18;
    if (uVar3 == 1) {
      DAT_803caf1c = (param_2[1] * (0x7f - ((uint)param_1[0x55] >> 0x10) & 0xff)) / 0x7f;
    }
    else if (uVar3 == 0) {
      DAT_803caf1c = param_2[1];
    }
    else if (uVar3 < 3) {
      DAT_803caf1c = (param_2[1] * ((uint)param_1[0x55] >> 0x10 & 0xff)) / 0x7f;
    }
    else {
      DAT_803caf1c = 0;
    }
    if (DAT_803caf20 <= DAT_803caf1c) {
      DAT_803caf1c = DAT_803caf20 - 1;
    }
    uVar4 = countLeadingZeros(param_1[0x45] & 0x800);
    uVar3 = countLeadingZeros(param_1[0x46] & 0x100);
    FUN_802839f4(param_1[0x3d] & 0xff,uVar1,&DAT_803caf10,uVar3 >> 5,
                 (uint)*(byte *)(param_1 + 0x43) << 0x18 | (uint)param_1[0x44] >> 0xf,param_1[0x3d],
                 uVar4 >> 5,*(char *)((int)param_1 + 0x193));
    param_1[0x49] = DAT_803caf10;
    if (param_1[0x4a] != -1) {
      FUN_8027641c((int)param_1);
    }
    param_1[0x46] = param_1[0x46] | 0x20;
    FUN_80271ad4(param_1);
  }
  return;
}

