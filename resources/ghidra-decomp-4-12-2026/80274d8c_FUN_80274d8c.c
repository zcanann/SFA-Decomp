// Function: FUN_80274d8c
// Entry: 80274d8c
// Size: 216 bytes

undefined4 FUN_80274d8c(short param_1)

{
  uint uVar1;
  undefined4 *puVar2;
  int iVar3;
  short *psVar4;
  short *local_c [2];
  
  puVar2 = &DAT_803c08d8;
  iVar3 = 0;
  for (uVar1 = (uint)DAT_803def08; psVar4 = (short *)0x0, uVar1 != 0; uVar1 = uVar1 - 1) {
    for (psVar4 = (short *)*puVar2; *psVar4 != -1; psVar4 = psVar4 + 0x10) {
      if ((*psVar4 == param_1) && (psVar4[1] != -1)) goto LAB_80274e00;
    }
    puVar2 = puVar2 + 3;
    iVar3 = iVar3 + 1;
  }
LAB_80274e00:
  if (psVar4[1] == 0) {
    local_c[0] = psVar4 + 6;
    *(int *)(psVar4 + 4) = *(int *)(psVar4 + 2) + *(int *)(&DAT_803c08dc + iVar3 * 0xc);
    FUN_80284560((int *)local_c,(uint *)(psVar4 + 4));
  }
  psVar4[1] = psVar4[1] + 1;
  return 1;
}

