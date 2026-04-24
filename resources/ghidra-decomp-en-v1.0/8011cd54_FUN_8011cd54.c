// Function: FUN_8011cd54
// Entry: 8011cd54
// Size: 548 bytes

void FUN_8011cd54(undefined4 param_1)

{
  uint uVar1;
  char cVar3;
  int iVar2;
  int iVar4;
  int *piVar5;
  int iVar6;
  double dVar7;
  double dVar8;
  double local_18;
  
  iVar6 = DAT_803dba28 * 0x10;
  cVar3 = FUN_80134bbc();
  if (cVar3 == '\0') {
    dVar8 = (double)(**(code **)(*DAT_803dca4c + 0x18))();
    dVar7 = (double)FLOAT_803e1dd4;
    FUN_8001b444(FUN_80135a90);
    uVar1 = (int)(dVar7 - dVar8) & 0xff;
    if (uVar1 < 0x80) {
      local_18 = (double)CONCAT44(0x43300000,uVar1 * 0x86 ^ 0x80000000);
      FUN_80135820((double)FLOAT_803e1dd8,
                   -(double)((float)(local_18 - DOUBLE_803e1de8) * FLOAT_803e1de0 - FLOAT_803e1ddc))
      ;
      iVar4 = 0;
    }
    else {
      FUN_80135820((double)FLOAT_803e1dd8,(double)FLOAT_803e1de4);
      iVar4 = ((int)(dVar7 - dVar8) & 0x7fU) << 1;
    }
    FUN_80134d40(iVar4,0,0);
    if (*(short *)(&DAT_8031acc2 + iVar6) != -1) {
      FUN_80019908(0xff,0xff,0xff,0xff);
      iVar2 = FUN_80019570(*(undefined2 *)(&DAT_8031acc2 + iVar6));
      iVar2 = FUN_800173c8(*(undefined *)(iVar2 + 4));
      *(char *)(iVar2 + 0x1e) = (char)iVar4;
      FUN_80016870(*(undefined2 *)(&DAT_8031acc2 + iVar6));
    }
    if (*(short *)(&DAT_8031acc4 + iVar6) != -1) {
      FUN_80019908(0xff,0xff,0xff,iVar4);
      FUN_80016870(*(undefined2 *)(&DAT_8031acc4 + iVar6));
    }
    iVar6 = 0;
    piVar5 = &DAT_803a87d0;
    do {
      if (*piVar5 != 0) {
        (**(code **)(*DAT_803dcaa4 + 0x18))(*piVar5,param_1,iVar4);
      }
      piVar5 = piVar5 + 1;
      iVar6 = iVar6 + 1;
    } while (iVar6 < 8);
    (**(code **)(*DAT_803dcaa0 + 0x30))(iVar4);
    (**(code **)(*DAT_803dcaa0 + 0x10))(param_1);
    FUN_8001b444(0);
    FUN_80134c28(0);
    DAT_803dd706 = DAT_803dd706 + -1;
    if (DAT_803dd706 < '\0') {
      DAT_803dd706 = '\0';
    }
  }
  else {
    FUN_801349c8();
  }
  return;
}

