// Function: FUN_80228b20
// Entry: 80228b20
// Size: 348 bytes

undefined4 FUN_80228b20(int param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  undefined4 *puVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  local_28 = DAT_802c2d58;
  local_24 = DAT_802c2d5c;
  local_20 = DAT_802c2d60;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar4 = iVar4 + 1) {
    bVar1 = *(byte *)(param_3 + iVar4 + 0x81);
    if (bVar1 == 2) {
      if (*(short *)(iVar5 + 0x24) != 0) {
        (**(code **)(*DAT_803dd6d4 + 0x58))(param_3);
      }
    }
    else if ((bVar1 < 2) || (3 < bVar1)) {
      if ((*(byte *)(iVar5 + 0x1b) & 4) != 0) {
        FUN_800201ac((int)*(short *)(iVar5 + 0x1c),1);
        puVar2 = (undefined4 *)FUN_800395a4(param_1,0);
        if (puVar2 != (undefined4 *)0x0) {
          *puVar2 = 0x100;
        }
      }
    }
    else if (*(char *)(param_1 + 0xad) == '\x01') {
      iVar3 = FUN_80057360();
      (**(code **)(*DAT_803dd72c + 0x24))(&local_28,0xffffc000,iVar3,0);
    }
  }
  return 0;
}

