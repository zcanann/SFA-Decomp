// Function: FUN_8022a488
// Entry: 8022a488
// Size: 704 bytes

/* WARNING: Removing unreachable block (ram,0x8022a728) */
/* WARNING: Removing unreachable block (ram,0x8022a720) */
/* WARNING: Removing unreachable block (ram,0x8022a4a0) */
/* WARNING: Removing unreachable block (ram,0x8022a498) */

void FUN_8022a488(void)

{
  int iVar1;
  int *piVar2;
  undefined2 *puVar3;
  short *psVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  
  iVar1 = FUN_80286830();
  iVar5 = *(int *)(iVar1 + 0x4c);
  FUN_8002bac4();
  iVar6 = *(int *)(iVar1 + 0xb8);
  FUN_8022a060(iVar1,iVar6);
  piVar2 = (int *)FUN_8002b660(iVar1);
  iVar8 = *piVar2;
  for (iVar7 = 0; iVar7 < (int)(uint)*(ushort *)(iVar8 + 0xe4); iVar7 = iVar7 + 1) {
    puVar3 = (undefined2 *)FUN_80028568((int)piVar2,iVar7);
    psVar4 = (short *)FUN_800284d8(iVar8,iVar7);
    if (*psVar4 < 1) {
      dVar9 = (double)FUN_802945e0();
      local_60 = (double)CONCAT44(0x43300000,(int)*psVar4 ^ 0x80000000);
      *puVar3 = (short)(int)-(float)((double)FLOAT_803e7b0c * dVar9 -
                                    (double)(float)(local_60 - DOUBLE_803e7b18));
    }
    else {
      dVar9 = (double)FUN_802945e0();
      local_68 = (double)CONCAT44(0x43300000,(int)*psVar4 ^ 0x80000000);
      *puVar3 = (short)(int)((double)FLOAT_803e7b0c * dVar9 +
                            (double)(float)(local_68 - DOUBLE_803e7b18));
    }
  }
  if (*(char *)(iVar6 + 0x5f) == '\0') {
    FUN_800201ac(0xedb,0);
    FUN_80035ff8(iVar1);
  }
  else {
    if ((*(byte *)(iVar6 + 0x66) & 1) == 0) {
      FUN_800201ac(0xedb,1);
      *(byte *)(iVar6 + 0x66) = *(byte *)(iVar6 + 0x66) | 1;
      FUN_800201ac((int)*(short *)(iVar5 + 0x1e),1);
    }
    local_58 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar1 + 0x36));
    iVar5 = (int)((float)(local_58 - DOUBLE_803e7b20) + FLOAT_803dc074);
    if (iVar5 < 0) {
      iVar5 = 0;
    }
    else if (0xff < iVar5) {
      iVar5 = 0xff;
    }
    *(char *)(iVar1 + 0x36) = (char)iVar5;
    FUN_80036018(iVar1);
  }
  iVar5 = FUN_8002bac4();
  if (iVar5 != 0) {
    iVar5 = FUN_8002bac4();
    dVar9 = FUN_802480e8((float *)(iVar1 + 0x18),(float *)(iVar5 + 0x18));
    if ((double)FLOAT_803e7b2c < dVar9) {
      FUN_800201ac(0xedb,0);
    }
  }
  FUN_8028687c();
  return;
}

