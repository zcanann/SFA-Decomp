// Function: FUN_80228478
// Entry: 80228478
// Size: 348 bytes

undefined4 FUN_80228478(int param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  local_28 = DAT_802c25d8;
  local_24 = DAT_802c25dc;
  local_20 = DAT_802c25e0;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar4 = iVar4 + 1) {
    bVar1 = *(byte *)(param_3 + iVar4 + 0x81);
    if (bVar1 == 2) {
      if (*(short *)(iVar5 + 0x24) != 0) {
        (**(code **)(*DAT_803dca54 + 0x58))(param_3);
      }
    }
    else if ((bVar1 < 2) || (3 < bVar1)) {
      if ((*(byte *)(iVar5 + 0x1b) & 4) != 0) {
        FUN_800200e8((int)*(short *)(iVar5 + 0x1c),1);
        puVar2 = (undefined4 *)FUN_800394ac(param_1,0,0);
        if (puVar2 != (undefined4 *)0x0) {
          *puVar2 = 0x100;
        }
      }
    }
    else if (*(char *)(param_1 + 0xad) == '\x01') {
      uVar3 = FUN_800571e4();
      (**(code **)(*DAT_803dcaac + 0x24))(&local_28,0xffffc000,uVar3,0);
    }
  }
  return 0;
}

