// Function: FUN_8009b254
// Entry: 8009b254
// Size: 360 bytes

void FUN_8009b254(void)

{
  uint uVar1;
  short *psVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined2 *puVar6;
  undefined *puVar7;
  uint *puVar8;
  int *piVar9;
  
  FUN_802860cc();
  iVar5 = 0;
  piVar9 = &DAT_8039bd58;
  puVar8 = &DAT_8039bc18;
  puVar7 = &DAT_8039bbc8;
  puVar6 = &DAT_8030f8c8;
  do {
    iVar3 = *piVar9;
    iVar4 = 0;
    do {
      if ((1 << iVar4 & *puVar8) != 0) {
        if (((&DAT_8039b4e0)[(uint)(*(byte *)(iVar3 + 0x8a) >> 1) * 4] != 0) &&
           ((&DAT_8039b4e0)[(uint)(*(byte *)(iVar3 + 0x8a) >> 1) * 4] != 0)) {
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
        *puVar8 = *puVar8 & ~(1 << iVar4);
      }
      iVar3 = iVar3 + 0xa0;
      iVar4 = iVar4 + 1;
    } while (iVar4 < 0x19);
    *puVar7 = 0;
    *puVar6 = 0xffff;
    FUN_802419e8(*piVar9,4000);
    piVar9 = piVar9 + 1;
    puVar8 = puVar8 + 1;
    puVar7 = puVar7 + 1;
    puVar6 = puVar6 + 1;
    iVar5 = iVar5 + 1;
  } while (iVar5 < 0x50);
  FUN_80286118();
  return;
}

