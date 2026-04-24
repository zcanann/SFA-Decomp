// Function: FUN_80240430
// Entry: 80240430
// Size: 680 bytes

void FUN_80240430(undefined2 *param_1)

{
  bool bVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  uint uStack_28;
  int iStack_24;
  undefined4 auStack_20 [5];
  
  piVar5 = *(int **)(param_1 + 0x5c);
  if (*piVar5 == 0) {
    iVar3 = FUN_8002e1ac(0x47b77);
    *piVar5 = iVar3;
  }
  if (piVar5[1] == 0) {
    iVar3 = FUN_8002e1ac(0x4c611);
    piVar5[1] = iVar3;
  }
  FUN_80035eec((int)param_1,5,2,-1);
  FUN_80036018((int)param_1);
  if (*piVar5 != 0) {
    *(undefined4 *)(param_1 + 6) = *(undefined4 *)(*piVar5 + 0xc);
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(*piVar5 + 0x10);
    *(undefined4 *)(param_1 + 10) = *(undefined4 *)(*piVar5 + 0x14);
  }
  bVar1 = *(char *)(piVar5 + 7) != *(char *)((int)piVar5 + 0x1d);
  *(char *)((int)piVar5 + 0x1d) = *(char *)(piVar5 + 7);
  cVar2 = *(char *)(piVar5 + 7);
  if (cVar2 == '\x01') {
    if (bVar1) {
      *(undefined *)((int)piVar5 + 0x1f) = 0x3c;
      (**(code **)(*DAT_803dd6e8 + 0x58))(0x50,0x643);
    }
    (**(code **)(*DAT_803dd6e8 + 0x5c))(*(undefined *)((int)piVar5 + 0x1e));
    iVar4 = FUN_80036974((int)param_1,auStack_20,&iStack_24,&uStack_28);
    iVar3 = (uint)*(byte *)((int)piVar5 + 0x1f) - (uint)DAT_803dc070;
    if (iVar3 < 0) {
      iVar3 = 0;
    }
    *(char *)((int)piVar5 + 0x1f) = (char)iVar3;
    if ((iVar4 != 0) && (*(char *)((int)piVar5 + 0x1f) == '\0')) {
      FUN_8002ad08(param_1,0x19,200,0,0,1);
      *(undefined *)((int)piVar5 + 0x1f) = 6;
      *(char *)((int)piVar5 + 0x1e) = *(char *)((int)piVar5 + 0x1e) + -1;
      if (*(char *)((int)piVar5 + 0x1e) == '\0') {
        *(undefined *)(piVar5 + 7) = 2;
        FUN_8023ad80(*piVar5,1);
        FUN_8000bb38((uint)param_1,0x485);
      }
      else {
        FUN_8000bb38((uint)param_1,0x484);
      }
    }
    param_1[3] = param_1[3] & 0xbfff;
  }
  else if (cVar2 < '\x01') {
    if (-1 < cVar2) {
      if (bVar1) {
        (**(code **)(*DAT_803dd6e8 + 100))();
      }
      *param_1 = *(undefined2 *)*piVar5;
      param_1[3] = param_1[3] | 0x4000;
    }
  }
  else if (cVar2 < '\x03') {
    if (bVar1) {
      FUN_80240910(piVar5[1],2,'\0');
      (**(code **)(*DAT_803dd6e8 + 100))();
    }
    param_1[3] = param_1[3] | 0x4000;
    FUN_8023ad80(*piVar5,8);
  }
  return;
}

