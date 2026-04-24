// Function: FUN_8028eddc
// Entry: 8028eddc
// Size: 272 bytes

void FUN_8028eddc(undefined *param_1,undefined4 param_2,int param_3,int param_4)

{
  byte bVar1;
  undefined uVar2;
  undefined *puVar3;
  undefined *puVar4;
  uint uVar5;
  undefined8 uVar6;
  longlong lVar7;
  
  lVar7 = CONCAT44(param_3,param_4);
  *param_1 = 0;
  if (param_4 == 0 && param_3 == 0) {
    *(undefined2 *)(param_1 + 2) = 0;
    param_1[4] = 1;
    param_1[5] = 0;
  }
  else {
    param_1[4] = 0;
    while( true ) {
      uVar5 = (uint)((ulonglong)lVar7 >> 0x20);
      if (lVar7 == 0) break;
      uVar6 = FUN_80286ac8(uVar5,(uint)lVar7,0,10);
      bVar1 = param_1[4];
      param_1[4] = bVar1 + 1;
      param_1[bVar1 + 5] = (char)uVar6;
      lVar7 = FUN_802868a4(uVar5,(uint)lVar7,0,10);
    }
    puVar3 = param_1 + (byte)param_1[4] + 5;
    for (puVar4 = param_1 + 5; puVar3 = puVar3 + -1, puVar4 < puVar3; puVar4 = puVar4 + 1) {
      uVar2 = *puVar4;
      *puVar4 = *puVar3;
      *puVar3 = uVar2;
    }
    *(ushort *)(param_1 + 2) = (byte)param_1[4] - 1;
  }
  return;
}

