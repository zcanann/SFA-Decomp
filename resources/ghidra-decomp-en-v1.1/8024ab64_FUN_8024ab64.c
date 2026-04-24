// Function: FUN_8024ab64
// Entry: 8024ab64
// Size: 704 bytes

void FUN_8024ab64(int param_1)

{
  undefined4 uVar1;
  uint uVar2;
  
  DAT_803debcc = FUN_8024ab64;
  switch(*(undefined4 *)(param_1 + 8)) {
  case 1:
  case 4:
    uVar1 = DAT_cc006004;
    DAT_cc006004 = uVar1;
    uVar2 = *(int *)(param_1 + 0x14) - *(int *)(param_1 + 0x20);
    if (0x80000 < uVar2) {
      uVar2 = 0x80000;
    }
    *(uint *)(param_1 + 0x1c) = uVar2;
    FUN_80248738(*(int *)(param_1 + 0x18) + *(int *)(param_1 + 0x20),*(uint *)(param_1 + 0x1c),
                 *(int *)(param_1 + 0x10) + *(int *)(param_1 + 0x20),&LAB_8024ae24);
    break;
  case 2:
    uVar1 = DAT_cc006004;
    DAT_cc006004 = uVar1;
    FUN_802489d0(*(uint *)(param_1 + 0x10),&LAB_8024ae24);
    break;
  case 3:
    FUN_80248b34(&LAB_8024ae24);
    break;
  case 5:
    uVar1 = DAT_cc006004;
    DAT_cc006004 = uVar1;
    *(undefined4 *)(param_1 + 0x1c) = 0x20;
    FUN_80248a90(*(undefined4 *)(param_1 + 0x18),&LAB_8024ae24);
    break;
  case 6:
    uVar1 = DAT_cc006004;
    DAT_cc006004 = uVar1;
    if (DAT_803deb9c == 0) {
      *(undefined4 *)(DAT_803deb88 + 0x1c) = 1;
      FUN_80248ce8(0,*(undefined4 *)(param_1 + 0x14),*(uint *)(param_1 + 0x10),&LAB_8024ae24);
    }
    else {
      *(undefined4 *)(DAT_803deb88 + 0x1c) = 0;
      FUN_80248d80(0,&LAB_8024ae24);
    }
    break;
  case 7:
    uVar1 = DAT_cc006004;
    DAT_cc006004 = uVar1;
    FUN_80248ce8(0x10000,0,0,&LAB_8024ae24);
    break;
  case 8:
    uVar1 = DAT_cc006004;
    DAT_cc006004 = uVar1;
    DAT_803deb9c = 1;
    FUN_80248ce8(0,0,0,&LAB_8024ae24);
    break;
  case 9:
    uVar1 = DAT_cc006004;
    DAT_cc006004 = uVar1;
    FUN_80248d80(0,&LAB_8024ae24);
    break;
  case 10:
    uVar1 = DAT_cc006004;
    DAT_cc006004 = uVar1;
    FUN_80248d80(0x10000,&LAB_8024ae24);
    break;
  case 0xb:
    uVar1 = DAT_cc006004;
    DAT_cc006004 = uVar1;
    FUN_80248d80(0x20000,&LAB_8024ae24);
    break;
  case 0xc:
    uVar1 = DAT_cc006004;
    DAT_cc006004 = uVar1;
    FUN_80248d80(0x30000,&LAB_8024ae24);
    break;
  case 0xd:
    uVar1 = DAT_cc006004;
    DAT_cc006004 = uVar1;
    FUN_80248e0c(*(int *)(param_1 + 0x10),*(uint *)(param_1 + 0x14),&LAB_8024ae24);
    break;
  case 0xe:
    uVar1 = DAT_cc006004;
    DAT_cc006004 = uVar1;
    *(undefined4 *)(param_1 + 0x1c) = 0x20;
    FUN_80248c4c(*(undefined4 *)(param_1 + 0x18),&LAB_8024ae24);
    break;
  case 0xf:
    FUN_80248b34(&LAB_8024ae24);
  }
  return;
}

