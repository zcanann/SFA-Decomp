// Function: FUN_8002c528
// Entry: 8002c528
// Size: 444 bytes

void FUN_8002c528(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar5;
  uint uVar6;
  undefined8 extraout_f1;
  undefined8 uVar7;
  undefined8 extraout_f1_00;
  undefined uStack_27;
  
  iVar2 = FUN_80286840();
  if (iVar2 < DAT_803dd838) {
    if (*(char *)(DAT_803dd824 + iVar2) == '\0') {
      iVar1 = iVar2 * 4;
      uVar5 = *(uint *)(DAT_803dd83c + iVar1);
      uVar6 = *(int *)(DAT_803dd83c + iVar1 + 4) - uVar5;
      uVar7 = extraout_f1;
      iVar3 = FUN_80023d8c(uVar6,0xe);
      if (iVar3 != 0) {
        uVar7 = FUN_800490c4(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x3e,
                             iVar3,uVar5,uVar6,in_r7,in_r8,in_r9,in_r10);
        if (*(int *)(iVar3 + 0x20) != 0) {
          *(int *)(iVar3 + 0x20) = iVar3 + *(int *)(iVar3 + 0x20);
        }
        if (*(int *)(iVar3 + 0x24) != 0) {
          *(int *)(iVar3 + 0x24) = iVar3 + *(int *)(iVar3 + 0x24);
        }
        if (*(int *)(iVar3 + 0x28) != 0) {
          *(int *)(iVar3 + 0x28) = iVar3 + *(int *)(iVar3 + 0x28);
        }
        *(int *)(iVar3 + 8) = iVar3 + *(int *)(iVar3 + 8);
        *(int *)(iVar3 + 0xc) = iVar3 + *(int *)(iVar3 + 0xc);
        *(int *)(iVar3 + 0x10) = iVar3 + *(int *)(iVar3 + 0x10);
        if (*(int *)(iVar3 + 0x18) != 0) {
          *(int *)(iVar3 + 0x18) = iVar3 + *(int *)(iVar3 + 0x18);
        }
        if (*(int *)(iVar3 + 0x40) != 0) {
          *(int *)(iVar3 + 0x40) = iVar3 + *(int *)(iVar3 + 0x40);
        }
        if (*(int *)(iVar3 + 0x1c) != 0) {
          *(int *)(iVar3 + 0x1c) = iVar3 + *(int *)(iVar3 + 0x1c);
        }
        *(int *)(iVar3 + 0x2c) = iVar3 + *(int *)(iVar3 + 0x2c);
        *(undefined4 *)(iVar3 + 0x30) = 0;
        *(undefined4 *)(iVar3 + 0x34) = 0;
        if (-1 < *(char *)(iVar3 + 0x5d)) {
          uVar4 = FUN_8002c444(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          *(undefined4 *)(iVar3 + 0x30) = uVar4;
          *(undefined *)(iVar3 + 0x5c) = uStack_27;
          FUN_800648c0(extraout_f1_00,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        }
        *(int *)(DAT_803dd828 + iVar1) = iVar3;
        *(undefined *)(DAT_803dd824 + iVar2) = 1;
      }
    }
    else {
      *(char *)(DAT_803dd824 + iVar2) = *(char *)(DAT_803dd824 + iVar2) + '\x01';
    }
  }
  FUN_8028688c();
  return;
}

