// Function: FUN_8013b568
// Entry: 8013b568
// Size: 392 bytes

/* WARNING: Removing unreachable block (ram,0x8013b6d0) */
/* WARNING: Removing unreachable block (ram,0x8013b6c8) */
/* WARNING: Removing unreachable block (ram,0x8013b580) */
/* WARNING: Removing unreachable block (ram,0x8013b578) */

void FUN_8013b568(undefined4 param_1,undefined4 param_2,float *param_3)

{
  undefined4 uVar1;
  int *piVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  double in_f30;
  double dVar6;
  double in_f31;
  double dVar7;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar8;
  int local_58;
  int local_54;
  int local_50 [2];
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar8 = FUN_8028683c();
  uVar1 = (undefined4)((ulonglong)uVar8 >> 0x20);
  piVar2 = FUN_80037048(0x40,local_50);
  dVar6 = (double)FLOAT_803e3114;
  dVar7 = DOUBLE_803e3090;
  for (iVar5 = 0; iVar5 < local_50[0]; iVar5 = iVar5 + 1) {
    iVar3 = *(int *)(*piVar2 + 0x4c);
    uStack_44 = (uint)*(ushort *)(iVar3 + 0x18);
    local_48 = 0x43300000;
    uStack_3c = (uint)*(ushort *)(iVar3 + 0x1a);
    local_40 = 0x43300000;
    FUN_8013b368((double)(float)(dVar6 * (double)(float)((double)CONCAT44(0x43300000,uStack_44) -
                                                        dVar7)),
                 (double)(float)(dVar6 * (double)(float)((double)CONCAT44(0x43300000,uStack_3c) -
                                                        dVar7)),uVar1,(int)uVar8,param_3,
                 (float *)(*piVar2 + 0x18));
    piVar2 = piVar2 + 1;
  }
  iVar5 = FUN_8002e1f4(&local_54,&local_58);
  piVar2 = (int *)(iVar5 + local_54 * 4);
  for (; local_54 < local_58; local_54 = local_54 + 1) {
    iVar5 = *piVar2;
    uVar4 = (uint)*(ushort *)(*(int *)(iVar5 + 0x50) + 0x84);
    if (((uVar4 != 0) && (*(int *)(iVar5 + 0x54) != 0)) &&
       ((*(ushort *)(*(int *)(iVar5 + 0x54) + 0x60) & 1) != 0)) {
      local_40 = 0x43300000;
      uStack_44 = (uint)*(ushort *)(*(int *)(iVar5 + 0x50) + 0x86);
      local_48 = 0x43300000;
      uStack_3c = uVar4;
      FUN_8013b368((double)(FLOAT_803e3114 *
                           (float)((double)CONCAT44(0x43300000,uVar4) - DOUBLE_803e3090)),
                   (double)(FLOAT_803e3114 *
                           (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e3090)),uVar1,
                   (int)uVar8,param_3,(float *)(iVar5 + 0x18));
    }
    piVar2 = piVar2 + 1;
  }
  FUN_80286888();
  return;
}

