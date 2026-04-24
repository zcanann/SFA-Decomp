// Function: FUN_80295674
// Entry: 80295674
// Size: 320 bytes

void FUN_80295674(void)

{
  undefined4 uVar1;
  undefined4 uVar2;
  int iVar3;
  undefined8 uVar4;
  undefined auStack120 [12];
  undefined auStack108 [12];
  float local_60;
  float local_5c;
  float local_58;
  undefined auStack84 [12];
  float local_48;
  float local_38;
  float local_28;
  undefined4 local_20;
  uint uStack28;
  
  uVar4 = FUN_802860dc();
  uVar1 = (undefined4)((ulonglong)uVar4 >> 0x20);
  iVar3 = (int)uVar4;
  if (*(byte *)(iVar3 + 0x8b1) != 0) {
    if ((*(byte *)(iVar3 + 0x8b1) & 1) != 0) {
      uVar2 = FUN_800383a0(uVar1,5);
      FUN_80003494(auStack84,uVar2,0x30);
      local_48 = FLOAT_803e7ea4;
      local_38 = FLOAT_803e7ea4;
      local_28 = FLOAT_803e7ea4;
      local_60 = FLOAT_803e7ea4;
      local_5c = FLOAT_803e7ea4;
      uStack28 = FUN_800221a0(*(byte *)(iVar3 + 0x8b1) + 4,*(byte *)(iVar3 + 0x8b1) + 8);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_58 = FLOAT_803e7ec8 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e7ec0);
      FUN_80247494(auStack84,&local_60,auStack120);
      local_60 = FLOAT_803e7ea4;
      local_5c = FLOAT_803e7ecc;
      local_58 = FLOAT_803e7ed0;
      FUN_8003842c(uVar1,10,&local_60,&local_5c,&local_58,1);
      (**(code **)(*DAT_803dca88 + 8))(uVar1,0x7e5,auStack108,0x200001,0xffffffff,auStack120);
    }
    *(char *)(iVar3 + 0x8b1) = *(char *)(iVar3 + 0x8b1) + -1;
  }
  FUN_80286128();
  return;
}

