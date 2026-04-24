// Function: FUN_80274628
// Entry: 80274628
// Size: 216 bytes

undefined4 FUN_80274628(short param_1)

{
  uint uVar1;
  short **ppsVar2;
  int iVar3;
  short *psVar4;
  short *local_c [2];
  
  ppsVar2 = (short **)&DAT_803bfc78;
  iVar3 = 0;
  for (uVar1 = (uint)DAT_803de288; psVar4 = (short *)0x0, uVar1 != 0; uVar1 = uVar1 - 1) {
    for (psVar4 = *ppsVar2; *psVar4 != -1; psVar4 = psVar4 + 0x10) {
      if ((*psVar4 == param_1) && (psVar4[1] != -1)) goto LAB_8027469c;
    }
    ppsVar2 = ppsVar2 + 3;
    iVar3 = iVar3 + 1;
  }
LAB_8027469c:
  if (psVar4[1] == 0) {
    local_c[0] = psVar4 + 6;
    *(int *)(psVar4 + 4) = *(int *)(psVar4 + 2) + *(int *)(&DAT_803bfc7c + iVar3 * 0xc);
    FUN_80283dfc(local_c,psVar4 + 4);
  }
  psVar4[1] = psVar4[1] + 1;
  return 1;
}

