// Function: FUN_8020816c
// Entry: 8020816c
// Size: 240 bytes

undefined4
FUN_8020816c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,
            undefined4 param_10,int param_11)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  
  iVar2 = *(int *)(param_9 + 0x5c);
  *(byte *)(iVar2 + 8) = *(byte *)(iVar2 + 8) & 0x7f | 0x80;
  FUN_800146a8();
  for (iVar1 = 0; iVar1 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar1 = iVar1 + 1) {
    if (*(char *)(param_11 + iVar1 + 0x81) == '\x01') {
      *(byte *)(iVar2 + 8) = *(byte *)(iVar2 + 8) & 0xef | 0x10;
      *(undefined *)(iVar2 + 7) = 0;
      FUN_800201ac((int)*(short *)(iVar2 + 2),0);
      uVar3 = FUN_800201ac(0xedf,1);
      iVar1 = 0;
      do {
        uVar3 = FUN_80207f80(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        iVar1 = iVar1 + 1;
      } while (iVar1 < 4);
      *(byte *)(iVar2 + 8) = *(byte *)(iVar2 + 8) & 0xbf | 0x40;
    }
  }
  FUN_80207cc4(param_9);
  return 0;
}

