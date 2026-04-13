// Function: FUN_801a4ad8
// Entry: 801a4ad8
// Size: 160 bytes

undefined4
FUN_801a4ad8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            undefined4 param_9,undefined4 param_10,int param_11)

{
  undefined4 uVar1;
  int iVar2;
  undefined8 uVar3;
  
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar2 = iVar2 + 1) {
    if (*(char *)(param_11 + iVar2 + 0x81) == '\x01') {
      FUN_800201ac(0xdcb,1);
      uVar3 = FUN_800201ac(0x4a3,0);
      FUN_80043070(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x2b);
      FUN_80043604(0,0,1);
      uVar1 = FUN_8004832c(0x2b);
      FUN_80043658(uVar1,0);
    }
  }
  return 0;
}

