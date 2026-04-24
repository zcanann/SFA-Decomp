// Function: FUN_8000d8e4
// Entry: 8000d8e4
// Size: 372 bytes

void FUN_8000d8e4(int param_1,short param_2,ushort param_3)

{
  bool bVar1;
  ushort uVar2;
  short *psVar3;
  int *piVar4;
  int *piVar5;
  short *psVar6;
  short sVar7;
  uint uVar8;
  
  uVar8 = (uint)DAT_803dc878;
  uVar2 = 0;
  psVar6 = &DAT_80336d90;
  piVar5 = &DAT_80336e90;
  psVar3 = psVar6;
  piVar4 = piVar5;
  for (sVar7 = 0; (int)sVar7 < (int)uVar8; sVar7 = sVar7 + 1) {
    if (param_2 == *psVar3) {
      if (param_3 != 0) {
        uVar2 = uVar2 + 1;
      }
      if (*piVar4 == param_1) {
        (&DAT_80336d10)[sVar7] = (&DAT_80336d10)[sVar7] | 3;
        return;
      }
    }
    psVar3 = psVar3 + 1;
    piVar4 = piVar4 + 1;
  }
  if (uVar2 <= param_3) {
    for (sVar7 = 0; (int)sVar7 < (int)uVar8; sVar7 = sVar7 + 1) {
      if ((*piVar5 == param_1) && (param_2 == *psVar6)) {
        bVar1 = true;
        goto LAB_8000d9e0;
      }
      piVar5 = piVar5 + 1;
      psVar6 = psVar6 + 1;
    }
    bVar1 = false;
LAB_8000d9e0:
    if ((!bVar1) && (uVar8 != 0x80)) {
      (&DAT_80336e90)[uVar8] = param_1;
      (&DAT_80336d90)[uVar8] = param_2;
      (&DAT_80336d10)[uVar8] = 0;
      DAT_803dc878 = DAT_803dc878 + 1;
      FUN_8000bb18();
    }
  }
  if (uVar8 != DAT_803dc878) {
    (&DAT_80336d10)[uVar8] = (&DAT_80336d10)[uVar8] | 3;
  }
  return;
}

