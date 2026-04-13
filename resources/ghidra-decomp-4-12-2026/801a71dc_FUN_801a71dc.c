// Function: FUN_801a71dc
// Entry: 801a71dc
// Size: 308 bytes

void FUN_801a71dc(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  char *pcVar7;
  
  iVar2 = FUN_8028683c();
  pcVar7 = *(char **)(iVar2 + 0xb8);
  iVar6 = *(int *)(iVar2 + 0x4c);
  if ((*pcVar7 == '\0') && (uVar3 = FUN_80020078((int)*(short *)(iVar6 + 0x18)), uVar3 != 0)) {
    *pcVar7 = '\x02';
  }
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar5 = iVar5 + 1) {
    bVar1 = *(byte *)(param_3 + iVar5 + 0x81);
    if (bVar1 == 2) {
      (**(code **)(*DAT_803dd708 + 8))(iVar2,0x70b,0,2,0xffffffff,0);
      iVar4 = 0;
      do {
        (**(code **)(*DAT_803dd708 + 8))(iVar2,0x70c,0,2,0xffffffff,0);
        iVar4 = iVar4 + 1;
      } while (iVar4 < 0x28);
    }
    else if ((bVar1 < 2) && (bVar1 != 0)) {
      *pcVar7 = '\x01';
      uVar3 = (uint)*(short *)(iVar6 + 0x1a);
      if (uVar3 != 0xffffffff) {
        FUN_800201ac(uVar3,1);
      }
    }
  }
  FUN_80286888();
  return;
}

