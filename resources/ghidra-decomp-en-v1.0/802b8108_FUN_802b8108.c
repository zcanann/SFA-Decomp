// Function: FUN_802b8108
// Entry: 802b8108
// Size: 372 bytes

/* WARNING: Removing unreachable block (ram,0x802b825c) */

void FUN_802b8108(void)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  undefined4 uVar7;
  undefined8 extraout_f1;
  undefined8 in_f31;
  undefined8 uVar8;
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar8 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar8 >> 0x20);
  iVar3 = (int)uVar8;
  iVar4 = *(int *)(iVar1 + 0xb8);
  uVar8 = extraout_f1;
  if (*(int *)(iVar3 + 0x2d0) != 0) {
    FUN_8003b0d0(iVar1,*(int *)(iVar3 + 0x2d0),iVar4 + 0x3ac,0x19);
  }
  piVar6 = *(int **)(iVar4 + 0x40c);
  iVar5 = *piVar6;
  iVar4 = piVar6[1];
  if ((*(char *)(iVar3 + 0x27a) != '\0') || (*(char *)(iVar3 + 0x346) != '\0')) {
    *(undefined *)(piVar6 + 0xb) = 0;
    *(short *)(piVar6 + 9) = *(short *)(piVar6 + 9) + 1;
    if (*(short *)(iVar5 + (uint)*(ushort *)(piVar6 + 9) * 2) == -1) {
      *(undefined2 *)(piVar6 + 9) = 0;
    }
    if (*(char *)(iVar3 + 0x27a) == '\0') {
      FUN_80030334((double)FLOAT_803e8180,iVar1,
                   (int)*(short *)(iVar5 + (uint)*(ushort *)(piVar6 + 9) * 2),0);
    }
    else {
      uVar2 = FUN_800221a0(0,99);
      *(float *)(iVar1 + 0x98) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e8198) /
           FLOAT_803e817c;
      FUN_80030334((double)*(float *)(iVar1 + 0x98),iVar1,
                   (int)*(short *)(iVar5 + (uint)*(ushort *)(piVar6 + 9) * 2),0);
    }
  }
  *(undefined4 *)(iVar3 + 0x2a0) = *(undefined4 *)(iVar4 + (uint)*(ushort *)(piVar6 + 9) * 4);
  (**(code **)(*DAT_803dca8c + 0x20))(uVar8,iVar1,iVar3,0);
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  FUN_80286128(0);
  return;
}

