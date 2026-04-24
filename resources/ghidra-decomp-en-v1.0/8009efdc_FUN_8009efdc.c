// Function: FUN_8009efdc
// Entry: 8009efdc
// Size: 464 bytes

void FUN_8009efdc(void)

{
  uint uVar1;
  short *psVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  undefined *puVar7;
  undefined4 *puVar8;
  undefined2 *puVar9;
  undefined *puVar10;
  uint *puVar11;
  int *piVar12;
  
  FUN_802860c0();
  piVar6 = &DAT_8039ab58;
  iVar5 = 0;
  piVar12 = &DAT_8039bd58;
  puVar11 = &DAT_8039bc18;
  puVar10 = &DAT_8039bbc8;
  puVar9 = &DAT_8030f8c8;
  puVar8 = &DAT_8039ba28;
  puVar7 = &DAT_8030f968;
  do {
    iVar3 = *piVar12;
    iVar4 = 0;
    do {
      if ((1 << iVar4 & *puVar11) != 0) {
        if ((&DAT_8039b4e0)[(uint)(*(byte *)(iVar3 + 0x8a) >> 1) * 4] != 0) {
          DAT_803dd258 = 1;
          FUN_80054308((&DAT_8039b4e0)[(uint)(*(byte *)(iVar3 + 0x8a) >> 1) * 4]);
          DAT_803dd258 = 0;
        }
        uVar1 = (uint)(*(byte *)(iVar3 + 0x8a) >> 1);
        psVar2 = &DAT_8039b4e4 + uVar1 * 8;
        if (*psVar2 == 0) {
          FUN_801378a8(s_expgfx_c__mismatch_in_add_remove_8030fbf0);
        }
        else {
          *psVar2 = *psVar2 + -1;
          if (*psVar2 == 0) {
            (&DAT_8039b4e0)[uVar1 * 4] = 0;
            (&DAT_8039b4d8)[uVar1 * 4] = 0;
          }
        }
        *(undefined2 *)(iVar3 + 0x26) = 0xffff;
        *puVar11 = *puVar11 & ~(1 << iVar4);
      }
      iVar3 = iVar3 + 0xa0;
      iVar4 = iVar4 + 1;
    } while (iVar4 < 0x19);
    *puVar10 = 0;
    *puVar9 = 0xffff;
    *puVar8 = 0;
    *puVar7 = 0;
    FUN_802419e8(*piVar12,4000);
    piVar12 = piVar12 + 1;
    puVar11 = puVar11 + 1;
    puVar10 = puVar10 + 1;
    puVar9 = puVar9 + 1;
    puVar8 = puVar8 + 1;
    puVar7 = puVar7 + 1;
    iVar5 = iVar5 + 1;
  } while (iVar5 < 0x50);
  iVar5 = 0;
  do {
    DAT_803dd258 = 1;
    if (*piVar6 != 0) {
      FUN_80054308();
    }
    DAT_803dd258 = 0;
    *piVar6 = 0;
    piVar6[2] = 0;
    piVar6[1] = 0;
    piVar6[3] = 0;
    piVar6 = piVar6 + 4;
    iVar5 = iVar5 + 1;
  } while (iVar5 < 0x20);
  FUN_8028610c();
  return;
}

