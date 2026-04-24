// Function: FUN_80139330
// Entry: 80139330
// Size: 444 bytes

/* WARNING: Removing unreachable block (ram,0x801394cc) */
/* WARNING: Removing unreachable block (ram,0x801394c4) */
/* WARNING: Removing unreachable block (ram,0x80139348) */
/* WARNING: Removing unreachable block (ram,0x80139340) */

void FUN_80139330(void)

{
  short sVar1;
  int *piVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  double extraout_f1;
  double dVar8;
  double in_f30;
  double dVar9;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar10;
  int local_48 [12];
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar10 = FUN_80286834();
  dVar9 = extraout_f1;
  piVar2 = FUN_80037048(3,local_48);
  dVar9 = (double)(float)(dVar9 * dVar9);
  for (iVar7 = 0; iVar7 < local_48[0]; iVar7 = iVar7 + 1) {
    iVar3 = FUN_80111fb0(*piVar2);
    if (iVar3 == 0) {
      dVar8 = FUN_8014ca48(*piVar2);
    }
    else {
      dVar8 = (double)(**(code **)(*DAT_803dd738 + 0x60))(*piVar2);
    }
    iVar3 = *(int *)(*piVar2 + 0x4c);
    if ((int)*(short *)(iVar3 + 0x18) == 0xffffffff) {
      uVar5 = 0;
    }
    else {
      uVar5 = FUN_80020078((int)*(short *)(iVar3 + 0x18));
    }
    if ((int)*(short *)(iVar3 + 0x1a) == 0xffffffff) {
      uVar6 = 1;
    }
    else {
      uVar6 = FUN_80020078((int)*(short *)(iVar3 + 0x1a));
    }
    uVar4 = FUN_80036d04(*piVar2,0x31);
    if ((((((uVar4 == 0) && ((double)FLOAT_803e306c < dVar8)) && (uVar5 == 0)) &&
         ((uVar6 != 0 && (*(short *)(*piVar2 + 0x46) != 0x851)))) &&
        (iVar3 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(iVar3 + 0x14)), iVar3 != 0)) &&
       ((((int)uVar10 != 0 ||
         (((sVar1 = *(short *)(*piVar2 + 0x46), sVar1 != 0x3fe && (sVar1 != 0x4d7)) &&
          ((sVar1 != 0x27c && (sVar1 != 0x251)))))) &&
        (dVar8 = FUN_80021794((float *)((int)((ulonglong)uVar10 >> 0x20) + 0x18),
                              (float *)(*piVar2 + 0x18)), dVar8 < dVar9)))) {
      dVar9 = dVar8;
    }
    piVar2 = piVar2 + 1;
  }
  FUN_80286880();
  return;
}

