// Function: FUN_8014a5b0
// Entry: 8014a5b0
// Size: 436 bytes

void FUN_8014a5b0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,float *param_11,float *param_12)

{
  short sVar1;
  bool bVar2;
  int *piVar3;
  char cVar4;
  int iVar5;
  double dVar6;
  undefined8 uVar7;
  char local_a0 [4];
  short asStack_9c [4];
  short asStack_94 [4];
  float afStack_8c [3];
  float local_80;
  float local_7c;
  float local_78;
  int aiStack_74 [29];
  
  uVar7 = FUN_8028683c();
  piVar3 = (int *)((ulonglong)uVar7 >> 0x20);
  iVar5 = (int)uVar7;
  local_a0[0] = '\0';
  cVar4 = '\0';
  if (*(int *)(iVar5 + 0x29c) != 0) {
    local_80 = *param_11;
    local_7c = param_11[1];
    local_78 = param_11[2];
    bVar2 = true;
    sVar1 = *(short *)((int)piVar3 + 0x46);
    if (((((sVar1 != 0x613) && (sVar1 != 0x642)) && (sVar1 != 0x3fe)) &&
        ((sVar1 != 0x7c6 && (sVar1 != 0x7c8)))) && ((sVar1 != 0x251 && (sVar1 != 0x851)))) {
      local_7c = local_7c + FLOAT_803e3234;
      bVar2 = false;
    }
    FUN_80012d20(&local_80,asStack_9c);
    local_80 = *param_12;
    local_7c = FLOAT_803e3234 + param_12[1];
    local_78 = param_12[2];
    FUN_80012d20(&local_80,asStack_94);
    FUN_80247eb8(param_11,&local_80,afStack_8c);
    dVar6 = FUN_80247f54(afStack_8c);
    if (dVar6 < (double)FLOAT_803e3244) {
      if (piVar3[0xc] == 0) {
        cVar4 = FUN_800128fc(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             asStack_94,asStack_9c,(undefined4 *)0x0,local_a0,0);
      }
      if ((!bVar2) && (local_a0[0] == '\x01')) {
        cVar4 = '\x01';
      }
    }
  }
  if ((cVar4 != '\0') && ((*(uint *)(iVar5 + 0x2e4) & 8) != 0)) {
    FUN_80064248(param_11,&local_80,(float *)0x0,aiStack_74,piVar3,(uint)*(byte *)(iVar5 + 0x261),
                 0xffffffff,0,0);
  }
  FUN_80286888();
  return;
}

