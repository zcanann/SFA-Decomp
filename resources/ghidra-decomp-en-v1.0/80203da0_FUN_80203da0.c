// Function: FUN_80203da0
// Entry: 80203da0
// Size: 380 bytes

void FUN_80203da0(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  char cVar6;
  int iVar3;
  undefined4 *puVar4;
  undefined4 uVar5;
  int iVar7;
  int iVar8;
  int local_28 [10];
  
  iVar1 = FUN_802860d8();
  iVar8 = *(int *)(iVar1 + 0x4c);
  for (iVar7 = 0; iVar7 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar7 = iVar7 + 1) {
    if ((((*(char *)(param_3 + iVar7 + 0x81) == '\x01') &&
         (iVar2 = FUN_8001ffb4(*(char *)(iVar8 + 0x19) + 0xa29), iVar2 == 0)) &&
        (cVar6 = FUN_8002e04c(), cVar6 != '\0')) &&
       (iVar2 = FUN_8005b490(0x4658a,0,0,0,0), iVar2 != 0)) {
      iVar3 = FUN_8002bdf4(0x38,0x539);
      FUN_80003494(iVar3,iVar2,0x38);
      *(undefined4 *)(iVar3 + 8) = *(undefined4 *)(iVar1 + 0xc);
      *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(iVar1 + 0x10);
      *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(iVar1 + 0x14);
      *(undefined4 *)(iVar3 + 0x14) = 0xffffffff;
      *(undefined2 *)(iVar3 + 0x1a) = 0x95;
      FUN_8002b5a0(iVar1,iVar3);
    }
  }
  iVar7 = FUN_8001ffb4((int)*(short *)(iVar8 + 0x1e));
  if ((iVar7 == 0) && (DAT_803ddce0 == 0)) {
    uVar5 = 0;
  }
  else {
    puVar4 = (undefined4 *)FUN_80036f50(0x24,local_28);
    FUN_800376d8(0,3,iVar1,0x11,0);
    while (local_28[0] != 0) {
      uVar5 = *puVar4;
      puVar4 = puVar4 + 1;
      local_28[0] = local_28[0] + -1;
      FUN_80036fa4(uVar5,0x24);
    }
    uVar5 = 4;
    local_28[0] = local_28[0] + -1;
  }
  FUN_80286124(uVar5);
  return;
}

