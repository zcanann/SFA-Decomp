// Function: FUN_8001c5ac
// Entry: 8001c5ac
// Size: 488 bytes

void FUN_8001c5ac(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  FUN_802860d4();
  uVar1 = *(undefined *)(param_3 + 0x1e);
  iVar5 = (int)*(short *)(param_3 + 0x14);
  iVar4 = (int)*(short *)(param_3 + 0x16);
  iVar3 = (int)(uint)*(ushort *)(param_3 + 8) >> 1;
  iVar2 = (int)(uint)*(ushort *)(param_3 + 10) >> 1;
  FUN_8005d118(0,DAT_803db3f4 & 0xff,DAT_803db3f8 & 0xff,DAT_803db3fc & 0xff,DAT_803db400 & 0xff);
  FUN_800799c0();
  FUN_800795e8();
  FUN_80079804();
  FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,iVar5 - DAT_803db3f0 ^ 0x80000000) -
                              DOUBLE_803de748),
               (double)(float)((double)CONCAT44(0x43300000,iVar4 - DAT_803db3f0 ^ 0x80000000) -
                              DOUBLE_803de748),DAT_803dca20,uVar1,0x100,iVar3 + DAT_803db3f0,
               iVar2 + DAT_803db3f0,0);
  FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,iVar5 + iVar3 ^ 0x80000000) -
                              DOUBLE_803de748),
               (double)(float)((double)CONCAT44(0x43300000,iVar4 - DAT_803db3f0 ^ 0x80000000) -
                              DOUBLE_803de748),DAT_803dca20,uVar1,0x100,iVar3 + DAT_803db3f0,
               iVar2 + DAT_803db3f0,1);
  FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,iVar5 - DAT_803db3f0 ^ 0x80000000) -
                              DOUBLE_803de748),
               (double)(float)((double)CONCAT44(0x43300000,iVar4 + iVar2 ^ 0x80000000) -
                              DOUBLE_803de748),DAT_803dca20,uVar1,0x100,iVar3 + DAT_803db3f0,
               iVar2 + DAT_803db3f0,2);
  FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,iVar5 + iVar3 ^ 0x80000000) -
                              DOUBLE_803de748),
               (double)(float)((double)CONCAT44(0x43300000,iVar4 + iVar2 ^ 0x80000000) -
                              DOUBLE_803de748),DAT_803dca20,uVar1,0x100,iVar3 + DAT_803db3f0,
               iVar2 + DAT_803db3f0,3);
  FUN_80286120();
  return;
}

