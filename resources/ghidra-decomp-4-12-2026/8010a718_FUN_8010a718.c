// Function: FUN_8010a718
// Entry: 8010a718
// Size: 276 bytes

void FUN_8010a718(undefined4 param_1,undefined4 param_2,uint param_3)

{
  bool bVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_80286840();
  iVar4 = (int)((ulonglong)uVar6 >> 0x20);
  piVar3 = (int *)uVar6;
  bVar1 = false;
  *piVar3 = 0;
  while (!bVar1) {
    bVar1 = true;
    if ((*(char *)(iVar4 + 0x19) != '\x1b') && (*(char *)(iVar4 + 0x19) != '\x1a')) {
      for (iVar5 = 0; iVar5 < 5; iVar5 = iVar5 + 1) {
        if ((((-1 < *(int *)(iVar4 + iVar5 * 4 + 0x1c)) &&
             (((int)*(char *)(iVar4 + 0x1b) & 1 << iVar5) != 0)) &&
            (iVar2 = (**(code **)(*DAT_803dd71c + 0x1c))(), iVar2 != 0)) &&
           (((*(byte *)(iVar2 + 0x31) == param_3 || (*(byte *)(iVar2 + 0x32) == param_3)) ||
            (*(byte *)(iVar2 + 0x33) == param_3)))) {
          bVar1 = false;
          iVar5 = 5;
          iVar4 = iVar2;
        }
      }
    }
    if (!bVar1) {
      *piVar3 = *piVar3 + 1;
    }
  }
  FUN_8028688c();
  return;
}

