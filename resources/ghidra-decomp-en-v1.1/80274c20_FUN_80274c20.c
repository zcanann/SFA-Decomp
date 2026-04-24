// Function: FUN_80274c20
// Entry: 80274c20
// Size: 364 bytes

undefined4 FUN_80274c20(short *param_1,undefined4 param_2)

{
  int *piVar1;
  short *psVar2;
  undefined4 uVar3;
  uint uVar4;
  uint uVar5;
  short *psVar6;
  ushort uVar7;
  ushort uVar8;
  ushort uVar9;
  
  uVar4 = 0;
  uVar5 = (uint)DAT_803def08;
  for (piVar1 = &DAT_803c08d8; ((int)uVar4 < (int)uVar5 && ((short *)*piVar1 != param_1));
      piVar1 = piVar1 + 3) {
    uVar4 = uVar4 + 1;
  }
  if (uVar4 == uVar5) {
    if (uVar5 < 0x80) {
      uVar9 = 0;
      for (psVar2 = param_1; *psVar2 != -1; psVar2 = psVar2 + 0x10) {
        uVar9 = uVar9 + 1;
      }
      FUN_80285258();
      psVar2 = param_1;
      for (uVar7 = 0; uVar7 < uVar9; uVar7 = uVar7 + 1) {
        uVar5 = 0;
        piVar1 = &DAT_803c08d8;
        for (uVar4 = (uint)DAT_803def08; uVar4 != 0; uVar4 = uVar4 - 1) {
          psVar6 = (short *)*piVar1;
          for (uVar8 = 0; uVar8 < *(ushort *)(piVar1 + 2); uVar8 = uVar8 + 1) {
            if (*psVar2 == *psVar6) goto LAB_80274d10;
            psVar6 = psVar6 + 0x10;
          }
          piVar1 = piVar1 + 3;
          uVar5 = uVar5 + 1;
        }
LAB_80274d10:
        if (uVar5 == DAT_803def08) {
          psVar2[1] = 0;
        }
        else {
          psVar2[1] = -1;
        }
        psVar2 = psVar2 + 0x10;
      }
      uVar4 = (uint)DAT_803def08;
      (&DAT_803c08d8)[uVar4 * 3] = param_1;
      (&DAT_803c08e0)[uVar4 * 6] = uVar9;
      *(undefined4 *)(&DAT_803c08dc + uVar4 * 0xc) = param_2;
      DAT_803def08 = DAT_803def08 + 1;
      FUN_80285220();
      uVar3 = 1;
    }
    else {
      uVar3 = 0;
    }
  }
  else {
    uVar3 = 1;
  }
  return uVar3;
}

