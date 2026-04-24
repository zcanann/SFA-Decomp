// Function: FUN_8028e67c
// Entry: 8028e67c
// Size: 272 bytes

void FUN_8028e67c(undefined *param_1,undefined4 param_2,uint param_3,uint param_4)

{
  byte bVar1;
  undefined uVar2;
  undefined *puVar3;
  undefined extraout_r4;
  undefined *puVar4;
  undefined4 uVar5;
  longlong lVar6;
  
  lVar6 = CONCAT44(param_3,param_4);
  *param_1 = 0;
  if ((param_4 | param_3) == 0) {
    *(undefined2 *)(param_1 + 2) = 0;
    param_1[4] = 1;
    param_1[5] = 0;
  }
  else {
    param_1[4] = 0;
    while( true ) {
      uVar5 = (undefined4)((ulonglong)lVar6 >> 0x20);
      if (lVar6 == 0) break;
      FUN_80286364(uVar5,(int)lVar6,0,10);
      bVar1 = param_1[4];
      param_1[4] = bVar1 + 1;
      param_1[bVar1 + 5] = extraout_r4;
      lVar6 = FUN_80286140(uVar5,(int)lVar6,0,10);
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

