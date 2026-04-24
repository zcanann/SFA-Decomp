// Function: FUN_8011f6e8
// Entry: 8011f6e8
// Size: 720 bytes

void FUN_8011f6e8(void)

{
  short sVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  undefined4 local_58;
  int local_54;
  int local_50;
  int local_4c;
  int local_48;
  undefined4 local_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  
  uVar5 = (uint)*(ushort *)(DAT_803a9790 + 0xc);
  uVar3 = (uint)DAT_803dc6c1;
  uVar2 = (uint)DAT_803dc6c0;
  uVar4 = *(ushort *)(DAT_803a978c + 10) & 0xff;
  if (DAT_803de3ee == 0) {
    sVar1 = -((ushort)DAT_803dc758 * (ushort)DAT_803dc070);
  }
  else {
    sVar1 = (ushort)DAT_803dc758 * (ushort)DAT_803dc070;
  }
  DAT_803de3ec = DAT_803de3ec + sVar1;
  if (DAT_803de3ec < 0) {
    DAT_803de3ec = 0;
  }
  else if (0xff < DAT_803de3ec) {
    DAT_803de3ec = 0xff;
  }
  if (DAT_803de3ec != 0) {
    FUN_8025db38(&local_48,&local_4c,&local_50,&local_54);
    FUN_8025da88(0,0,0x280,0x1e0);
    uStack_3c = (0x140 - (uint)DAT_803dc6c0) - uVar4 ^ 0x80000000;
    local_40 = 0x43300000;
    FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e2af8),
                 (double)FLOAT_803e2b1c,DAT_803a978c,(int)DAT_803de3ec & 0xff,0x100,uVar4,uVar5,1);
    uStack_34 = 0x140 - DAT_803dc6c1 ^ 0x80000000;
    local_38 = 0x43300000;
    FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e2af8),
                 (double)FLOAT_803e2b1c,DAT_803a9790,(int)DAT_803de3ec & 0xff,0x100,
                 (uint)DAT_803dc6c1 << 1,uVar5,0);
    uStack_2c = 0x140 - DAT_803dc6c0 ^ 0x80000000;
    local_30 = 0x43300000;
    FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e2af8),
                 (double)FLOAT_803e2b1c,DAT_803a9794,(int)DAT_803de3ec & 0xff,0x100,uVar2 - uVar3,
                 uVar5,0);
    uStack_24 = DAT_803dc6c1 + 0x140 ^ 0x80000000;
    local_28 = 0x43300000;
    FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e2af8),
                 (double)FLOAT_803e2b1c,DAT_803a9794,(int)DAT_803de3ec & 0xff,0x100,uVar2 - uVar3,
                 uVar5,0);
    uStack_1c = DAT_803dc6c0 + 0x140 ^ 0x80000000;
    local_20 = 0x43300000;
    FUN_80077318((double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e2af8),
                 (double)FLOAT_803e2b1c,DAT_803a978c,(int)DAT_803de3ec & 0xff,0x100);
    local_44 = CONCAT31(0xff0000,(char)DAT_803de3ec);
    local_58 = local_44;
    FUN_80075534((DAT_803dc6c2 + 0x140) - (uint)DAT_803dc757,DAT_803dc756 + 0x32,
                 (uint)DAT_803dc757 + DAT_803dc6c2 + 0x140,(uVar5 + 0x32) - (uint)DAT_803dc756,
                 &local_58);
    FUN_8025da88(local_48,local_4c,local_50,local_54);
  }
  return;
}

