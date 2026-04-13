// Function: FUN_80054f2c
// Entry: 80054f2c
// Size: 420 bytes

/* WARNING: Removing unreachable block (ram,0x80054f74) */
/* WARNING: Removing unreachable block (ram,0x80054fc0) */

void FUN_80054f2c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int *piVar1;
  undefined4 uVar2;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  undefined8 uVar4;
  
  uVar2 = 0;
  DAT_803dda44 = FUN_80023d8c(0x2bc0,6);
  iVar3 = 0;
  DAT_803dda3c = 0;
  DAT_8037ed14 = (int *)FUN_80043860(0x24);
  for (piVar1 = DAT_8037ed14; *piVar1 != -1; piVar1 = piVar1 + 1) {
    iVar3 = iVar3 + 1;
  }
  DAT_8037ed08 = iVar3 + -1;
  iVar3 = 0;
  DAT_8037ed18 = (int *)FUN_80043860(0x21);
  for (piVar1 = DAT_8037ed18; *piVar1 != -1; piVar1 = piVar1 + 1) {
    iVar3 = iVar3 + 1;
  }
  DAT_8037ed0c = iVar3 + -1;
  iVar3 = 0;
  DAT_8037ed1c = (int *)FUN_80043860(0x50);
  for (piVar1 = DAT_8037ed1c; *piVar1 != -1; piVar1 = piVar1 + 1) {
    iVar3 = iVar3 + 1;
  }
  DAT_8037ed10 = iVar3 + -1;
  uVar4 = FUN_8001f82c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,&DAT_803dda40
                       ,0x22,uVar2,in_r6,in_r7,in_r8,in_r9,in_r10);
  iVar3 = 0;
  for (piVar1 = DAT_8037ed14; *piVar1 != -1; piVar1 = piVar1 + 1) {
    iVar3 = iVar3 + 1;
  }
  DAT_8037ed08 = iVar3 + -1;
  iVar3 = 0;
  for (piVar1 = DAT_8037ed18; *piVar1 != -1; piVar1 = piVar1 + 1) {
    iVar3 = iVar3 + 1;
  }
  DAT_8037ed0c = iVar3 + -1;
  DAT_803dda38 = FUN_80023d8c(0x120,6);
  FUN_80054620(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  return;
}

