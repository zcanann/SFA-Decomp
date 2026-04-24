// Function: FUN_8013a7f4
// Entry: 8013a7f4
// Size: 468 bytes

void FUN_8013a7f4(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4)

{
  undefined8 uVar1;
  int iVar2;
  char cVar5;
  char cVar6;
  int *piVar3;
  int iVar4;
  int iVar7;
  char cVar8;
  char cVar9;
  char *pcVar10;
  int *piVar11;
  undefined8 uVar12;
  char local_28 [40];
  
  uVar12 = FUN_802860d0();
  iVar2 = (int)((ulonglong)uVar12 >> 0x20);
  piVar3 = (int *)uVar12;
  cVar6 = '\0';
  uVar1 = uVar12;
  while( true ) {
    iVar4 = (int)((ulonglong)uVar1 >> 0x20);
    if ('\a' < cVar6) break;
    iVar7 = *(int *)uVar1;
    if (iVar7 != 0) {
      FUN_8004b31c(iVar4 + 0x538,iVar7,*(undefined4 *)(iVar2 + 0x28),param_4,
                   *(undefined *)(param_3 + cVar6));
    }
    uVar1 = CONCAT44(iVar4 + 0x30,(int *)uVar1 + 1);
    cVar6 = cVar6 + '\x01';
  }
  for (cVar6 = '\0'; cVar6 < 'd'; cVar6 = cVar6 + '\x01') {
    cVar8 = '\0';
    cVar9 = '\0';
    pcVar10 = local_28;
    uVar1 = uVar12;
    while( true ) {
      iVar4 = (int)((ulonglong)uVar1 >> 0x20);
      piVar11 = (int *)uVar1;
      if ('\a' < cVar9) break;
      if (*piVar11 == 0) {
        *pcVar10 = -1;
      }
      else {
        cVar5 = FUN_8004b218(iVar4 + 0x538,1);
        *pcVar10 = cVar5;
      }
      cVar5 = *pcVar10;
      if (cVar5 != '\0') {
        if (cVar5 < '\0') {
          if (-2 < cVar5) {
            *piVar11 = 0;
            cVar8 = cVar8 + '\x01';
          }
        }
        else if (cVar5 < '\x02') {
          iVar4 = (int)cVar9;
          goto LAB_8013a9b0;
        }
      }
      uVar1 = CONCAT44(iVar4 + 0x30,piVar11 + 1);
      pcVar10 = pcVar10 + 1;
      cVar9 = cVar9 + '\x01';
    }
    if (cVar8 == '\b') goto LAB_8013a994;
    if ((cVar8 < '\b') && ('\x06' < cVar8)) {
      cVar6 = '\0';
      goto LAB_8013a988;
    }
  }
  iVar4 = -1;
LAB_8013a9b0:
  FUN_8028611c(iVar4);
  return;
LAB_8013a988:
  if ('\a' < cVar6) goto LAB_8013a994;
  if (*piVar3 != 0) {
    iVar4 = (int)cVar6;
    cVar6 = FUN_8004b218(iVar2 + iVar4 * 0x30 + 0x538,500);
    local_28[iVar4] = cVar6;
    if (local_28[iVar4] != '\x01') {
      iVar4 = -1;
    }
    goto LAB_8013a9b0;
  }
  piVar3 = piVar3 + 1;
  cVar6 = cVar6 + '\x01';
  goto LAB_8013a988;
LAB_8013a994:
  iVar4 = -1;
  goto LAB_8013a9b0;
}

