// Function: FUN_80241044
// Entry: 80241044
// Size: 284 bytes

void FUN_80241044(int *param_1)

{
  undefined4 uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  undefined8 uVar5;
  
  uVar1 = FUN_8024377c();
  if (*param_1 == 0) {
    FUN_802437a4(uVar1);
  }
  else {
    iVar4 = param_1[5];
    if (iVar4 == 0) {
      iRam803dde0c = param_1[4];
    }
    else {
      *(int *)(iVar4 + 0x10) = param_1[4];
    }
    if (param_1[4] == 0) {
      DAT_803dde08 = iVar4;
      if (iVar4 != 0) {
        uVar5 = FUN_80246c70();
        uVar3 = *(uint *)(iVar4 + 0xc) - (uint)uVar5;
        uVar2 = *(int *)(iVar4 + 8) -
                ((uint)(*(uint *)(iVar4 + 0xc) < (uint)uVar5) + (int)((ulonglong)uVar5 >> 0x20)) ^
                0x80000000;
        if (uVar2 < 0x80000000) {
          FUN_80294640(0);
        }
        else if (uVar2 < (uVar3 < 0x80000000) + 0x80000000) {
          FUN_80294640(uVar3);
        }
        else {
          FUN_80294640(0x7fffffff);
        }
      }
    }
    else {
      *(int *)(param_1[4] + 0x14) = iVar4;
    }
    *param_1 = 0;
    FUN_802437a4(uVar1);
  }
  return;
}

