// Function: FUN_80295dd4
// Entry: 80295dd4
// Size: 320 bytes

void FUN_80295dd4(void)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined8 uVar4;
  float afStack_78 [3];
  undefined auStack_6c [12];
  float local_60;
  float local_5c;
  float local_58;
  float afStack_54 [3];
  float local_48;
  float local_38;
  float local_28;
  undefined4 local_20;
  uint uStack_1c;
  
  uVar4 = FUN_80286840();
  iVar1 = (int)((ulonglong)uVar4 >> 0x20);
  iVar3 = (int)uVar4;
  if (*(byte *)(iVar3 + 0x8b1) != 0) {
    if ((*(byte *)(iVar3 + 0x8b1) & 1) != 0) {
      uVar2 = FUN_80038498(iVar1,5);
      FUN_80003494((uint)afStack_54,uVar2,0x30);
      local_48 = FLOAT_803e8b3c;
      local_38 = FLOAT_803e8b3c;
      local_28 = FLOAT_803e8b3c;
      local_60 = FLOAT_803e8b3c;
      local_5c = FLOAT_803e8b3c;
      uStack_1c = FUN_80022264(*(byte *)(iVar3 + 0x8b1) + 4,*(byte *)(iVar3 + 0x8b1) + 8);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_58 = FLOAT_803e8b60 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e8b58);
      FUN_80247bf8(afStack_54,&local_60,afStack_78);
      local_60 = FLOAT_803e8b3c;
      local_5c = FLOAT_803e8b64;
      local_58 = FLOAT_803e8b68;
      FUN_80038524(iVar1,10,&local_60,&local_5c,&local_58,1);
      (**(code **)(*DAT_803dd708 + 8))(iVar1,0x7e5,auStack_6c,0x200001,0xffffffff,afStack_78);
    }
    *(char *)(iVar3 + 0x8b1) = *(char *)(iVar3 + 0x8b1) + -1;
  }
  FUN_8028688c();
  return;
}

