// Function: FUN_8014d164
// Entry: 8014d164
// Size: 312 bytes

void FUN_8014d164(void)

{
  byte bVar1;
  short sVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_802860dc();
  iVar3 = (int)((ulonglong)uVar7 >> 0x20);
  piVar4 = *(int **)(iVar3 + 0xb8);
  if (piVar4[0xdb] != 0) {
    FUN_80026c88();
  }
  if (piVar4[0xda] != 0) {
    FUN_8001f384();
    piVar4[0xda] = 0;
  }
  if (*piVar4 != 0) {
    FUN_80023800();
    *piVar4 = 0;
  }
  sVar2 = *(short *)(iVar3 + 0x46);
  if (sVar2 == 0x851) {
    iVar5 = FUN_80036c0c(iVar3,0x50);
    if (iVar5 != 0) {
      FUN_80036fa4(iVar3,0x50);
    }
  }
  else if ((sVar2 < 0x851) && (sVar2 == 0x7c8)) {
    FUN_801598b8(iVar3,piVar4);
  }
  bVar1 = *(byte *)(iVar3 + 0xeb);
  for (iVar5 = 0; iVar5 < (int)(uint)bVar1; iVar5 = iVar5 + 1) {
    iVar6 = *(int *)(iVar3 + 200);
    if ((iVar6 != 0) &&
       ((FUN_80037cb0(iVar3,iVar6), (int)uVar7 == 0 || ((*(ushort *)(iVar6 + 0xb0) & 0x10) == 0))))
    {
      FUN_8002cbc4(iVar6);
    }
  }
  (**(code **)(*DAT_803dca78 + 0x14))(iVar3);
  FUN_80036fa4(iVar3,3);
  FUN_80286128();
  return;
}

