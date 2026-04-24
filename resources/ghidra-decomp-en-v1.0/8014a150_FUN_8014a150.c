// Function: FUN_8014a150
// Entry: 8014a150
// Size: 436 bytes

void FUN_8014a150(undefined4 param_1,undefined4 param_2,undefined4 *param_3,undefined4 *param_4)

{
  short sVar1;
  bool bVar2;
  char cVar4;
  int iVar3;
  int iVar5;
  double dVar6;
  undefined8 uVar7;
  char local_a0 [4];
  undefined auStack156 [8];
  undefined auStack148 [8];
  undefined auStack140 [12];
  undefined4 local_80;
  float local_7c;
  undefined4 local_78;
  undefined auStack116 [116];
  
  uVar7 = FUN_802860d8();
  iVar3 = (int)((ulonglong)uVar7 >> 0x20);
  iVar5 = (int)uVar7;
  local_a0[0] = '\0';
  cVar4 = '\0';
  if (*(int *)(iVar5 + 0x29c) != 0) {
    local_80 = *param_3;
    local_7c = (float)param_3[1];
    local_78 = param_3[2];
    bVar2 = true;
    sVar1 = *(short *)(iVar3 + 0x46);
    if (((((sVar1 != 0x613) && (sVar1 != 0x642)) && (sVar1 != 0x3fe)) &&
        ((sVar1 != 0x7c6 && (sVar1 != 0x7c8)))) && ((sVar1 != 0x251 && (sVar1 != 0x851)))) {
      local_7c = local_7c + FLOAT_803e25a0;
      bVar2 = false;
    }
    FUN_80012d00(&local_80,auStack156);
    local_80 = *param_4;
    local_7c = FLOAT_803e25a0 + (float)param_4[1];
    local_78 = param_4[2];
    FUN_80012d00(&local_80,auStack148);
    FUN_80247754(param_3,&local_80,auStack140);
    dVar6 = (double)FUN_802477f0(auStack140);
    if (dVar6 < (double)FLOAT_803e25b0) {
      if (*(int *)(iVar3 + 0x30) == 0) {
        cVar4 = FUN_800128dc(auStack148,auStack156,0,local_a0,0);
      }
      if ((!bVar2) && (local_a0[0] == '\x01')) {
        cVar4 = '\x01';
      }
    }
  }
  if ((cVar4 != '\0') && ((*(uint *)(iVar5 + 0x2e4) & 8) != 0)) {
    iVar3 = FUN_800640cc((double)FLOAT_803e256c,param_3,&local_80,0,auStack116,iVar3,
                         *(undefined *)(iVar5 + 0x261),0xffffffff,0,0);
    if (iVar3 != 0) {
      cVar4 = '\0';
    }
  }
  FUN_80286124(cVar4);
  return;
}

