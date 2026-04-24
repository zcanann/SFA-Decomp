// Function: FUN_8000d904
// Entry: 8000d904
// Size: 372 bytes

void FUN_8000d904(uint param_1,ushort param_2,ushort param_3)

{
  bool bVar1;
  ushort uVar2;
  ushort *puVar3;
  uint *puVar4;
  uint *puVar5;
  ushort *puVar6;
  short sVar7;
  uint uVar8;
  
  uVar8 = (uint)DAT_803dd4f8;
  uVar2 = 0;
  puVar6 = &DAT_803379f0;
  puVar5 = &DAT_80337af0;
  puVar3 = puVar6;
  puVar4 = puVar5;
  for (sVar7 = 0; (int)sVar7 < (int)uVar8; sVar7 = sVar7 + 1) {
    if (param_2 == *puVar3) {
      if (param_3 != 0) {
        uVar2 = uVar2 + 1;
      }
      if (*puVar4 == param_1) {
        (&DAT_80337970)[sVar7] = (&DAT_80337970)[sVar7] | 3;
        return;
      }
    }
    puVar3 = puVar3 + 1;
    puVar4 = puVar4 + 1;
  }
  if (uVar2 <= param_3) {
    for (sVar7 = 0; (int)sVar7 < (int)uVar8; sVar7 = sVar7 + 1) {
      if ((*puVar5 == param_1) && (param_2 == *puVar6)) {
        bVar1 = true;
        goto LAB_8000da00;
      }
      puVar5 = puVar5 + 1;
      puVar6 = puVar6 + 1;
    }
    bVar1 = false;
LAB_8000da00:
    if ((!bVar1) && (uVar8 != 0x80)) {
      (&DAT_80337af0)[uVar8] = param_1;
      (&DAT_803379f0)[uVar8] = param_2;
      (&DAT_80337970)[uVar8] = 0;
      DAT_803dd4f8 = DAT_803dd4f8 + 1;
      FUN_8000bb38(param_1,param_2);
    }
  }
  if (uVar8 != DAT_803dd4f8) {
    (&DAT_80337970)[uVar8] = (&DAT_80337970)[uVar8] | 3;
  }
  return;
}

