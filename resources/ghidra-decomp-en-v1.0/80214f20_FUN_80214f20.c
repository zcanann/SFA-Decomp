// Function: FUN_80214f20
// Entry: 80214f20
// Size: 716 bytes

void FUN_80214f20(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  undefined8 uVar8;
  undefined auStack104 [48];
  undefined4 local_38;
  uint uStack52;
  double local_30;
  undefined4 local_28;
  uint uStack36;
  
  uVar8 = FUN_802860d4();
  iVar1 = (int)((ulonglong)uVar8 >> 0x20);
  DAT_803ddd58 = *(int *)(iVar1 + 0xb8);
  if ((param_6 != '\0') && (*(int *)(iVar1 + 0xf4) == 0)) {
    if (*(int *)(DAT_803ddd54 + 0x178) != 0) {
      FUN_800604b4();
    }
    iVar6 = 0;
    iVar7 = 0;
    do {
      if (*(int *)(DAT_803ddd54 + iVar7 + 0x17c) != 0) {
        FUN_8008f904();
        iVar2 = *(int *)(DAT_803ddd54 + iVar7 + 0x17c);
        uStack52 = (uint)*(ushort *)(iVar2 + 0x20);
        local_38 = 0x43300000;
        iVar3 = (int)((float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e67e0) +
                     FLOAT_803db414);
        local_30 = (double)(longlong)iVar3;
        *(short *)(iVar2 + 0x20) = (short)iVar3;
        iVar3 = *(int *)(DAT_803ddd54 + iVar7 + 0x17c);
        if (*(ushort *)(iVar3 + 0x22) <= *(ushort *)(iVar3 + 0x20)) {
          FUN_80023800();
          *(undefined4 *)(DAT_803ddd54 + iVar7 + 0x17c) = 0;
        }
      }
      iVar7 = iVar7 + 4;
      iVar6 = iVar6 + 1;
    } while (iVar6 < 5);
    if (*(float *)(DAT_803ddd58 + 1000) != FLOAT_803e67b8) {
      iVar6 = (int)*(float *)(DAT_803ddd58 + 1000);
      local_30 = (double)(longlong)iVar6;
      FUN_8003b5e0(200,0,0,iVar6);
    }
    FUN_8003b8f4((double)FLOAT_803e6818,iVar1,(int)uVar8,param_3,param_4,param_5);
    FUN_8003842c(iVar1,1,DAT_803ddd54 + 0x130,DAT_803ddd54 + 0x134,DAT_803ddd54 + 0x138,0);
    FUN_8003842c(iVar1,2,DAT_803ddd54 + 0x148,DAT_803ddd54 + 0x14c,DAT_803ddd54 + 0x150,0);
    FUN_8003842c(iVar1,3,DAT_803ddd54 + 0x160,DAT_803ddd54 + 0x164,DAT_803ddd54 + 0x168,0);
    FUN_8003842c(iVar1,0,DAT_803ddd54 + 0x118,DAT_803ddd54 + 0x11c,DAT_803ddd54 + 0x120,0);
    uVar4 = FUN_800383a0(iVar1,4);
    FUN_80003494(auStack104,uVar4,0x30);
    uVar5 = FUN_800221a0(0xffffffce,0x32);
    local_30 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
    *(float *)(DAT_803ddd54 + 0x16c) = FLOAT_803e67b4 * (float)(local_30 - DOUBLE_803e6800);
    uStack52 = FUN_800221a0(0x3c,0x78);
    uStack52 = uStack52 ^ 0x80000000;
    local_38 = 0x43300000;
    *(float *)(DAT_803ddd54 + 0x170) =
         FLOAT_803e67b4 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e6800);
    uStack36 = FUN_800221a0(100,0x96);
    uStack36 = uStack36 ^ 0x80000000;
    local_28 = 0x43300000;
    *(float *)(DAT_803ddd54 + 0x174) =
         FLOAT_803e6848 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e6800);
    FUN_80247574(auStack104,DAT_803ddd54 + 0x16c,DAT_803ddd54 + 0x16c);
    *(uint *)(DAT_803ddd54 + 0x104) = *(uint *)(DAT_803ddd54 + 0x104) | 0x100000;
  }
  FUN_80286120();
  return;
}

