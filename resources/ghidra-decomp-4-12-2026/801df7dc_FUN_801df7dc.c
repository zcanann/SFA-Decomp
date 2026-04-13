// Function: FUN_801df7dc
// Entry: 801df7dc
// Size: 280 bytes

void FUN_801df7dc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined *puVar5;
  undefined8 uVar6;
  
  iVar2 = FUN_80286838();
  puVar5 = *(undefined **)(iVar2 + 0xb8);
  iVar4 = *(int *)(iVar2 + 0x4c);
  iVar2 = FUN_8002bac4();
  *(code **)(param_11 + 0xec) = FUN_801df700;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar3 = iVar3 + 1) {
    bVar1 = *(byte *)(param_11 + iVar3 + 0x81);
    if (bVar1 == 2) {
      FUN_800201ac((int)*(short *)(iVar4 + 0x1e),1);
      FUN_8029700c(iVar2,-(int)*(short *)(iVar4 + 0x1a));
      *puVar5 = 2;
    }
    else if ((bVar1 < 2) && (bVar1 != 0)) {
      puVar5[2] = 1;
    }
  }
  uVar6 = FUN_80019940(0xff,0xff,0xff,0xff);
  if (puVar5[2] == '\x01') {
    FUN_800168a8(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(undefined4 *)(&DAT_80328730 + (uint)(byte)puVar5[1] * 8));
  }
  else if (puVar5[2] == '\x02') {
    FUN_800168a8(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(undefined4 *)(&DAT_80328734 + (uint)(byte)puVar5[1] * 8));
  }
  FUN_80286884();
  return;
}

