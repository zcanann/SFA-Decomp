// Function: FUN_8014d5f8
// Entry: 8014d5f8
// Size: 312 bytes

void FUN_8014d5f8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  byte bVar1;
  short sVar2;
  int iVar3;
  uint uVar4;
  uint *puVar5;
  int iVar6;
  int iVar7;
  undefined8 uVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_80286840();
  iVar3 = (int)((ulonglong)uVar9 >> 0x20);
  puVar5 = *(uint **)(iVar3 + 0xb8);
  if ((uint *)puVar5[0xdb] != (uint *)0x0) {
    FUN_80026d4c((uint *)puVar5[0xdb]);
  }
  if (puVar5[0xda] != 0) {
    FUN_8001f448(puVar5[0xda]);
    puVar5[0xda] = 0;
  }
  if (*puVar5 != 0) {
    FUN_800238c4(*puVar5);
    *puVar5 = 0;
  }
  sVar2 = *(short *)(iVar3 + 0x46);
  if (sVar2 == 0x851) {
    uVar4 = FUN_80036d04(iVar3,0x50);
    if (uVar4 != 0) {
      FUN_8003709c(iVar3,0x50);
    }
  }
  else if ((sVar2 < 0x851) && (sVar2 == 0x7c8)) {
    FUN_80159d64(iVar3);
  }
  bVar1 = *(byte *)(iVar3 + 0xeb);
  for (iVar6 = 0; iVar6 < (int)(uint)bVar1; iVar6 = iVar6 + 1) {
    iVar7 = *(int *)(iVar3 + 200);
    if ((iVar7 != 0) &&
       ((uVar8 = FUN_80037da8(iVar3,iVar7), (int)uVar9 == 0 ||
        ((*(ushort *)(iVar7 + 0xb0) & 0x10) == 0)))) {
      FUN_8002cc9c(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar7);
    }
  }
  (**(code **)(*DAT_803dd6f8 + 0x14))(iVar3);
  FUN_8003709c(iVar3,3);
  FUN_8028688c();
  return;
}

