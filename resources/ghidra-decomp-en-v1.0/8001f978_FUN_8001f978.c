// Function: FUN_8001f978
// Entry: 8001f978
// Size: 212 bytes

void FUN_8001f978(undefined4 param_1,undefined4 param_2,uint *param_3,uint *param_4,uint param_5)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  undefined4 uVar5;
  int iVar6;
  uint uVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_802860dc();
  uVar3 = (uint)((ulonglong)uVar8 >> 0x20);
  iVar4 = FUN_80022a48();
  uVar1 = uVar3 & 0x1f;
  uVar7 = (int)uVar8 + uVar1 + 0x1f;
  uVar2 = *param_3 + (uVar7 & 0xffffffe0);
  if (param_5 < uVar2) {
    *param_4 = *param_3;
    *param_3 = uVar3;
    uVar5 = 0;
  }
  else {
    iVar6 = uVar3 - uVar1;
    *param_4 = uVar2;
    iVar4 = iVar4 + *param_3;
    *param_3 = iVar4 + uVar1;
    for (uVar7 = uVar7 >> 5; 0x7f < uVar7; uVar7 = uVar7 - 0x80) {
      FUN_800229f8(iVar4,iVar6,0);
      iVar4 = iVar4 + 0x1000;
      iVar6 = iVar6 + 0x1000;
    }
    if (uVar7 != 0) {
      FUN_800229f8(iVar4,iVar6,uVar7);
    }
    uVar5 = 1;
  }
  FUN_80286128(uVar5);
  return;
}

