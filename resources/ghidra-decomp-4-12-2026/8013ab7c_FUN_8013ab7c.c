// Function: FUN_8013ab7c
// Entry: 8013ab7c
// Size: 468 bytes

void FUN_8013ab7c(undefined4 param_1,undefined4 param_2,int param_3,int param_4)

{
  ulonglong uVar1;
  char cVar3;
  char cVar4;
  int *piVar2;
  int iVar5;
  char cVar6;
  char cVar7;
  char *pcVar8;
  int iVar9;
  int *piVar10;
  undefined8 uVar11;
  char local_28 [40];
  
  uVar11 = FUN_80286834();
  uVar1 = (ulonglong)uVar11 >> 0x20;
  piVar2 = (int *)uVar11;
  cVar7 = '\0';
  while( true ) {
    iVar9 = (int)((ulonglong)uVar11 >> 0x20);
    if ('\a' < cVar7) break;
    iVar5 = *(int *)uVar11;
    if (iVar5 != 0) {
      FUN_8004b498((int *)(iVar9 + 0x538),iVar5,*(int *)((int)uVar1 + 0x28),param_4,
                   *(byte *)(param_3 + cVar7));
    }
    uVar11 = CONCAT44(iVar9 + 0x30,(int *)uVar11 + 1);
    cVar7 = cVar7 + '\x01';
  }
  for (cVar7 = '\0'; cVar7 < 'd'; cVar7 = cVar7 + '\x01') {
    cVar4 = '\0';
    pcVar8 = local_28;
    piVar10 = piVar2;
    for (cVar6 = '\0'; cVar6 < '\b'; cVar6 = cVar6 + '\x01') {
      if (*piVar10 == 0) {
        *pcVar8 = -1;
      }
      else {
        cVar3 = FUN_8004b394();
        *pcVar8 = cVar3;
      }
      cVar3 = *pcVar8;
      if (cVar3 != '\0') {
        if (cVar3 < '\0') {
          if (-2 < cVar3) {
            *piVar10 = 0;
            cVar4 = cVar4 + '\x01';
          }
        }
        else if (cVar3 < '\x02') goto LAB_8013ad38;
      }
      piVar10 = piVar10 + 1;
      pcVar8 = pcVar8 + 1;
    }
    if (cVar4 == '\b') break;
    if ((cVar4 < '\b') && ('\x06' < cVar4)) {
      cVar7 = '\0';
      goto LAB_8013ad10;
    }
  }
LAB_8013ad38:
  FUN_80286880();
  return;
LAB_8013ad10:
  if ('\a' < cVar7) goto LAB_8013ad38;
  if (*piVar2 != 0) {
    cVar4 = FUN_8004b394();
    local_28[cVar7] = cVar4;
    goto LAB_8013ad38;
  }
  piVar2 = piVar2 + 1;
  cVar7 = cVar7 + '\x01';
  goto LAB_8013ad10;
}

