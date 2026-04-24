// Function: FUN_800387b4
// Entry: 800387b4
// Size: 716 bytes

/* WARNING: Removing unreachable block (ram,0x80038a60) */
/* WARNING: Removing unreachable block (ram,0x80038a58) */
/* WARNING: Removing unreachable block (ram,0x80038a50) */
/* WARNING: Removing unreachable block (ram,0x80038a48) */
/* WARNING: Removing unreachable block (ram,0x80038a40) */
/* WARNING: Removing unreachable block (ram,0x80038a38) */
/* WARNING: Removing unreachable block (ram,0x800387ec) */
/* WARNING: Removing unreachable block (ram,0x800387e4) */
/* WARNING: Removing unreachable block (ram,0x800387dc) */
/* WARNING: Removing unreachable block (ram,0x800387d4) */
/* WARNING: Removing unreachable block (ram,0x800387cc) */
/* WARNING: Removing unreachable block (ram,0x800387c4) */

void FUN_800387b4(void)

{
  byte *pbVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  short *psVar5;
  int iVar6;
  
  FUN_8028683c();
  piVar2 = FUN_8005b11c();
  iVar4 = 0;
  do {
    iVar6 = *piVar2;
    if (iVar6 != 0) {
      psVar5 = *(short **)(iVar6 + 0x20);
      for (iVar3 = 0; iVar3 < (int)(uint)*(ushort *)(iVar6 + 8); iVar3 = iVar3 + (uint)*pbVar1 * 4)
      {
        if (*psVar5 == 0x130) {
          FUN_802945e0();
          FUN_80294964();
          FUN_802945e0();
          FUN_80294964();
        }
        pbVar1 = (byte *)(psVar5 + 1);
        psVar5 = psVar5 + (uint)*pbVar1 * 2;
      }
    }
    piVar2 = piVar2 + 1;
    iVar4 = iVar4 + 1;
  } while (iVar4 < 0x50);
  FUN_80286888();
  return;
}

