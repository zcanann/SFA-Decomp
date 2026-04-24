// Function: FUN_8001e568
// Entry: 8001e568
// Size: 356 bytes

void FUN_8001e568(undefined4 param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  float *pfVar4;
  int iVar5;
  undefined8 uVar6;
  undefined4 local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  
  uVar6 = FUN_80286840();
  uVar1 = DAT_803dd6b4;
  iVar3 = (int)((ulonglong)uVar6 >> 0x20);
  iVar5 = (int)uVar6;
  if (((&DAT_8033cac8)[iVar3 * 4] == 0) || ((&DAT_8033cac8)[iVar3 * 4] == 2)) {
    FUN_8001e23c(iVar5,param_3,DAT_803dd6b4);
  }
  else {
    pfVar4 = (float *)FUN_8000f56c();
    iVar2 = *(int *)(iVar5 + 0x50);
    if (iVar2 != 3) {
      if (iVar2 < 3) {
        if (1 < iVar2) {
          FUN_80247eb8((float *)(param_3 + 0xc),(float *)(iVar5 + 0x10),&local_34);
          FUN_80247ef8(&local_34,&local_34);
          if (*(int *)(iVar5 + 0x60) == 0) {
            FUN_80247cd8(pfVar4,&local_34,&local_28);
          }
          else {
            local_28 = local_34;
            local_24 = local_30;
            local_20 = local_2c;
          }
          FUN_8025a0a8((double)local_28,(double)local_24,(double)local_20,iVar5 + 0xc0);
        }
      }
      else if (iVar2 < 5) {
        FUN_8025a0a8((double)*(float *)(iVar5 + 0x40),(double)*(float *)(iVar5 + 0x44),
                     (double)*(float *)(iVar5 + 0x48),iVar5 + 0xc0);
      }
    }
    local_38 = *(undefined4 *)(iVar5 + 0x100);
    FUN_8025a17c(iVar5 + 0xc0,(byte *)&local_38);
    FUN_8025a1a4(iVar5 + 0xc0,uVar1);
  }
  (&DAT_8033cac4)[iVar3 * 4] = (&DAT_8033cac4)[iVar3 * 4] | DAT_803dd6b4;
  DAT_803dd6b4 = DAT_803dd6b4 << 1;
  FUN_8028688c();
  return;
}

