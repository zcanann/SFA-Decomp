// Function: FUN_8022a170
// Entry: 8022a170
// Size: 660 bytes

/* WARNING: Removing unreachable block (ram,0x8022a3e4) */
/* WARNING: Removing unreachable block (ram,0x8022a3dc) */
/* WARNING: Removing unreachable block (ram,0x8022a188) */
/* WARNING: Removing unreachable block (ram,0x8022a180) */

void FUN_8022a170(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int *piVar2;
  undefined2 *puVar3;
  short *psVar4;
  int iVar5;
  int iVar6;
  double dVar7;
  undefined8 local_58;
  undefined8 local_50;
  
  iVar1 = FUN_80286838();
  iVar5 = *(int *)(iVar1 + 0x4c);
  iVar6 = *(int *)(iVar1 + 0xb8);
  *(undefined *)(param_3 + 0x56) = 0;
  *(ushort *)(param_3 + 0x70) = *(ushort *)(param_3 + 0x70) & 0xffdf;
  *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xffdf;
  FUN_8022a060(iVar1,iVar6);
  if (*(char *)(param_3 + 0x80) == '\x01') {
    *(undefined *)(iVar6 + 0x5f) = 1;
  }
  if (*(char *)(iVar6 + 0x5f) != '\0') {
    if ((*(byte *)(iVar6 + 0x66) & 1) == 0) {
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
  }
  piVar2 = (int *)FUN_8002b660(iVar1);
  iVar5 = *piVar2;
  for (iVar1 = 0; iVar1 < (int)(uint)*(ushort *)(iVar5 + 0xe4); iVar1 = iVar1 + 1) {
    puVar3 = (undefined2 *)FUN_80028568((int)piVar2,iVar1);
    psVar4 = (short *)FUN_800284d8(iVar5,iVar1);
    if (*psVar4 < 1) {
      dVar7 = (double)FUN_802945e0();
      local_50 = (double)CONCAT44(0x43300000,(int)*psVar4 ^ 0x80000000);
      *puVar3 = (short)(int)-(float)((double)FLOAT_803e7b0c * dVar7 -
                                    (double)(float)(local_50 - DOUBLE_803e7b18));
    }
    else {
      dVar7 = (double)FUN_802945e0();
      local_58 = (double)CONCAT44(0x43300000,(int)*psVar4 ^ 0x80000000);
      *puVar3 = (short)(int)((double)FLOAT_803e7b0c * dVar7 +
                            (double)(float)(local_58 - DOUBLE_803e7b18));
    }
  }
  FUN_80286884();
  return;
}

