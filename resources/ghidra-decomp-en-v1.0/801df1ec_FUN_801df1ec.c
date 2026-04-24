// Function: FUN_801df1ec
// Entry: 801df1ec
// Size: 280 bytes

void FUN_801df1ec(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  undefined *puVar5;
  
  iVar2 = FUN_802860d4();
  puVar5 = *(undefined **)(iVar2 + 0xb8);
  iVar4 = *(int *)(iVar2 + 0x4c);
  uVar3 = FUN_8002b9ec();
  *(code **)(param_3 + 0xec) = FUN_801df110;
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
    bVar1 = *(byte *)(param_3 + iVar2 + 0x81);
    if (bVar1 == 2) {
      FUN_800200e8((int)*(short *)(iVar4 + 0x1e),1);
      FUN_802968ac(uVar3,-(int)*(short *)(iVar4 + 0x1a));
      *puVar5 = 2;
    }
    else if ((bVar1 < 2) && (bVar1 != 0)) {
      puVar5[2] = 1;
    }
  }
  FUN_80019908(0xff,0xff,0xff,0xff);
  if (puVar5[2] == '\x01') {
    FUN_80016870(*(undefined4 *)(&DAT_80327af0 + (uint)(byte)puVar5[1] * 8));
  }
  else if (puVar5[2] == '\x02') {
    FUN_80016870(*(undefined4 *)(&DAT_80327af4 + (uint)(byte)puVar5[1] * 8));
  }
  FUN_80286120(0);
  return;
}

