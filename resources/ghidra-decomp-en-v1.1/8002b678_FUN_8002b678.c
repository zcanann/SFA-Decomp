// Function: FUN_8002b678
// Entry: 8002b678
// Size: 192 bytes

int FUN_8002b678(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                int param_9,undefined4 param_10)

{
  undefined uVar1;
  uint uVar2;
  undefined4 in_r9;
  undefined4 in_r10;
  uint *puVar3;
  int iVar4;
  undefined8 extraout_f1;
  
  puVar3 = *(uint **)(param_9 + 0x30);
  uVar1 = *(undefined *)(param_9 + 0xac);
  uVar2 = FUN_800431a4();
  if ((uVar2 & 0x100000) == 0) {
    iVar4 = FUN_8002d654(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_10,5,
                         uVar1,0xffffffff,puVar3,0,in_r9,in_r10);
    if (iVar4 != 0) {
      FUN_8002d404(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,5);
      FUN_8007d858();
    }
  }
  else {
    FUN_8007d858();
    iVar4 = 0;
  }
  return iVar4;
}

