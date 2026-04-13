// Function: FUN_802b91c8
// Entry: 802b91c8
// Size: 160 bytes

void FUN_802b91c8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_8028683c();
  iVar2 = (int)((ulonglong)uVar7 >> 0x20);
  uVar4 = *(undefined4 *)(iVar2 + 0xb8);
  FUN_8003709c(iVar2,3);
  bVar1 = *(byte *)(iVar2 + 0xeb);
  for (iVar3 = 0; iVar3 < (int)(uint)bVar1; iVar3 = iVar3 + 1) {
    iVar5 = *(int *)(iVar2 + 200);
    if ((iVar5 != 0) && (uVar6 = FUN_80037da8(iVar2,iVar5), (int)uVar7 == 0)) {
      FUN_8002cc9c(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar5);
    }
  }
  (**(code **)(*DAT_803dd738 + 0x40))(iVar2,uVar4,0x20);
  FUN_80286888();
  return;
}

