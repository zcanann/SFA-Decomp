// Function: FUN_80222e94
// Entry: 80222e94
// Size: 388 bytes

/* WARNING: Removing unreachable block (ram,0x80222ff8) */
/* WARNING: Removing unreachable block (ram,0x80222ea4) */

void FUN_80222e94(void)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  double in_f31;
  double in_ps31_1;
  float fStack_4c;
  undefined4 uStack_48;
  float afStack_44 [15];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  iVar2 = FUN_8028682c();
  piVar4 = *(int **)(iVar2 + 0xb8);
  FUN_8003b9ec(iVar2);
  FUN_80038524(iVar2,0,(float *)(piVar4 + 5),piVar4 + 6,(float *)(piVar4 + 7),0);
  iVar3 = 0;
  do {
    FUN_80038524(iVar2,iVar3 + 1,&fStack_4c,&uStack_48,afStack_44,0);
    FUN_80247eb8(&fStack_4c,(float *)(iVar2 + 0xc),&fStack_4c);
    FUN_80098608((double)FLOAT_803e7940,(double)FLOAT_803e7944);
    iVar3 = iVar3 + 1;
  } while (iVar3 < 4);
  iVar3 = piVar4[2];
  if (iVar3 != 0) {
    iVar2 = FUN_80036f50(0x19,iVar2,(float *)0x0);
    bVar1 = false;
    if ((iVar2 != 0) && (iVar3 == iVar2)) {
      bVar1 = true;
    }
    if ((bVar1) && (*piVar4 != 4)) {
      *(int *)(piVar4[2] + 0xc) = piVar4[5];
      *(int *)(piVar4[2] + 0x10) = piVar4[6];
      *(int *)(piVar4[2] + 0x14) = piVar4[7];
      FUN_8003b9ec(piVar4[2]);
    }
  }
  FUN_80286878();
  return;
}

