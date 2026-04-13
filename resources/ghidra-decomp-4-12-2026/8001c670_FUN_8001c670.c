// Function: FUN_8001c670
// Entry: 8001c670
// Size: 488 bytes

void FUN_8001c670(undefined4 param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  FUN_80286838();
  uVar1 = (uint)*(byte *)(param_3 + 0x1e);
  iVar5 = (int)*(short *)(param_3 + 0x14);
  iVar4 = (int)*(short *)(param_3 + 0x16);
  iVar3 = (int)(uint)*(ushort *)(param_3 + 8) >> 1;
  iVar2 = (int)(uint)*(ushort *)(param_3 + 10) >> 1;
  FUN_8005d294(0,(char)DAT_803dc054,(char)DAT_803dc058,(char)DAT_803dc05c,(char)DAT_803dc060);
  FUN_80079b3c();
  FUN_80079764();
  FUN_80079980();
  FUN_80076998((double)(float)((double)CONCAT44(0x43300000,iVar5 - DAT_803dc050 ^ 0x80000000) -
                              DOUBLE_803df3c8),
               (double)(float)((double)CONCAT44(0x43300000,iVar4 - DAT_803dc050 ^ 0x80000000) -
                              DOUBLE_803df3c8),DAT_803dd6a0,uVar1,0x100,iVar3 + DAT_803dc050,
               iVar2 + DAT_803dc050,0);
  FUN_80076998((double)(float)((double)CONCAT44(0x43300000,iVar5 + iVar3 ^ 0x80000000) -
                              DOUBLE_803df3c8),
               (double)(float)((double)CONCAT44(0x43300000,iVar4 - DAT_803dc050 ^ 0x80000000) -
                              DOUBLE_803df3c8),DAT_803dd6a0,uVar1,0x100,iVar3 + DAT_803dc050,
               iVar2 + DAT_803dc050,1);
  FUN_80076998((double)(float)((double)CONCAT44(0x43300000,iVar5 - DAT_803dc050 ^ 0x80000000) -
                              DOUBLE_803df3c8),
               (double)(float)((double)CONCAT44(0x43300000,iVar4 + iVar2 ^ 0x80000000) -
                              DOUBLE_803df3c8),DAT_803dd6a0,uVar1,0x100,iVar3 + DAT_803dc050,
               iVar2 + DAT_803dc050,2);
  FUN_80076998((double)(float)((double)CONCAT44(0x43300000,iVar5 + iVar3 ^ 0x80000000) -
                              DOUBLE_803df3c8),
               (double)(float)((double)CONCAT44(0x43300000,iVar4 + iVar2 ^ 0x80000000) -
                              DOUBLE_803df3c8),DAT_803dd6a0,uVar1,0x100,iVar3 + DAT_803dc050,
               iVar2 + DAT_803dc050,3);
  FUN_80286884();
  return;
}

