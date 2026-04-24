// Function: FUN_802b8868
// Entry: 802b8868
// Size: 372 bytes

/* WARNING: Removing unreachable block (ram,0x802b89bc) */
/* WARNING: Removing unreachable block (ram,0x802b8878) */

void FUN_802b8868(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  short *psVar1;
  uint uVar2;
  int iVar3;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar4;
  int iVar5;
  int *piVar6;
  undefined8 extraout_f1;
  undefined8 uVar7;
  
  uVar7 = FUN_80286840();
  psVar1 = (short *)((ulonglong)uVar7 >> 0x20);
  iVar3 = (int)uVar7;
  iVar4 = *(int *)(psVar1 + 0x5c);
  uVar7 = extraout_f1;
  if (*(int *)(iVar3 + 0x2d0) != 0) {
    in_r6 = 0x19;
    FUN_8003b1c8(psVar1,*(int *)(iVar3 + 0x2d0),iVar4 + 0x3ac,0x19);
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
      FUN_8003042c((double)FLOAT_803e8e18,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar1,(int)*(short *)(iVar5 + (uint)*(ushort *)(piVar6 + 9) * 2),0,in_r6,in_r7,
                   in_r8,in_r9,in_r10);
    }
    else {
      uVar2 = FUN_80022264(0,99);
      *(float *)(psVar1 + 0x4c) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e8e30) /
           FLOAT_803e8e14;
      FUN_8003042c((double)*(float *)(psVar1 + 0x4c),param_2,param_3,param_4,param_5,param_6,param_7
                   ,param_8,psVar1,(int)*(short *)(iVar5 + (uint)*(ushort *)(piVar6 + 9) * 2),0,
                   in_r6,in_r7,in_r8,in_r9,in_r10);
    }
  }
  *(undefined4 *)(iVar3 + 0x2a0) = *(undefined4 *)(iVar4 + (uint)*(ushort *)(piVar6 + 9) * 4);
  (**(code **)(*DAT_803dd70c + 0x20))(uVar7,psVar1,iVar3,0);
  FUN_8028688c();
  return;
}

