// Function: FUN_8028de08
// Entry: 8028de08
// Size: 508 bytes

void FUN_8028de08(undefined4 *param_1,int *param_2,uint param_3)

{
  bool bVar1;
  uint *puVar2;
  int *piVar3;
  int *piVar4;
  int iVar5;
  
  iVar5 = 0;
  for (puVar2 = &DAT_802c3180; *puVar2 < param_3; puVar2 = puVar2 + 1) {
    iVar5 = iVar5 + 1;
  }
  piVar3 = (int *)param_2[-1];
  piVar4 = param_1 + iVar5 * 2 + 1;
  if (piVar3[3] == 0) {
    if ((int *)piVar4[1] != piVar3) {
      if ((int *)*piVar4 == piVar3) {
        piVar4[1] = *(int *)piVar4[1];
        *piVar4 = *(int *)*piVar4;
      }
      else {
        *(int *)(*piVar3 + 4) = piVar3[1];
        *(int *)piVar3[1] = *piVar3;
        piVar3[1] = piVar4[1];
        *piVar3 = *(int *)piVar3[1];
        *(int **)(*piVar3 + 4) = piVar3;
        *(int **)piVar3[1] = piVar3;
        piVar4[1] = (int)piVar3;
      }
    }
  }
  *param_2 = piVar3[3];
  piVar3[3] = (int)(param_2 + -1);
  iVar5 = piVar3[4];
  piVar3[4] = iVar5 + -1;
  if (iVar5 + -1 == 0) {
    if ((int *)piVar4[1] == piVar3) {
      piVar4[1] = piVar3[1];
    }
    if ((int *)*piVar4 == piVar3) {
      *piVar4 = *piVar3;
    }
    *(int *)(*piVar3 + 4) = piVar3[1];
    *(int *)piVar3[1] = *piVar3;
    if ((int *)piVar4[1] == piVar3) {
      piVar4[1] = 0;
    }
    if ((int *)*piVar4 == piVar3) {
      *piVar4 = 0;
    }
    piVar4 = (int *)(piVar3[-1] & 0xfffffffe);
    FUN_8028e0c0((int)piVar4,(uint *)(piVar3 + -2));
    bVar1 = false;
    if (((piVar4[4] & 2U) == 0) && ((piVar4[4] & 0xfffffff8U) == (piVar4[3] & 0xfffffff8U) - 0x18))
    {
      bVar1 = true;
    }
    if (bVar1) {
      piVar3 = (int *)piVar4[1];
      if (piVar3 == piVar4) {
        piVar3 = (int *)0x0;
      }
      if ((int *)*param_1 == piVar4) {
        *param_1 = piVar3;
      }
      if (piVar3 != (int *)0x0) {
        *piVar3 = *piVar4;
        *(int **)(*piVar3 + 4) = piVar3;
      }
      piVar4[1] = 0;
      *piVar4 = 0;
      FUN_80286f20((int)piVar4);
    }
  }
  return;
}

