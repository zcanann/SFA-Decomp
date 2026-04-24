// Function: FUN_8001fa3c
// Entry: 8001fa3c
// Size: 212 bytes

void FUN_8001fa3c(undefined4 param_1,undefined4 param_2,uint *param_3,uint *param_4,uint param_5)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_80286840();
  uVar4 = (uint)((ulonglong)uVar6 >> 0x20);
  iVar3 = FUN_80022b0c();
  uVar1 = uVar4 & 0x1f;
  uVar5 = (int)uVar6 + uVar1 + 0x1f;
  uVar2 = *param_3 + (uVar5 & 0xffffffe0);
  if (param_5 < uVar2) {
    *param_4 = *param_3;
    *param_3 = uVar4;
  }
  else {
    uVar4 = uVar4 - uVar1;
    *param_4 = uVar2;
    uVar2 = iVar3 + *param_3;
    *param_3 = uVar2 + uVar1;
    for (uVar5 = uVar5 >> 5; 0x7f < uVar5; uVar5 = uVar5 - 0x80) {
      FUN_80022abc(uVar2,uVar4,0);
      uVar2 = uVar2 + 0x1000;
      uVar4 = uVar4 + 0x1000;
    }
    if (uVar5 != 0) {
      FUN_80022abc(uVar2,uVar4,uVar5);
    }
  }
  FUN_8028688c();
  return;
}

