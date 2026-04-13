// Function: FUN_801bd814
// Entry: 801bd814
// Size: 260 bytes

void FUN_801bd814(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  uint uVar1;
  int iVar2;
  undefined8 uVar3;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  FUN_800201ac(0xefd,0);
  FUN_800201ac(0xc1e,1);
  FUN_800201ac(0xc1f,0);
  FUN_800201ac(0xc20,0);
  FUN_800201ac(0xd8f,0);
  FUN_800201ac(0x3e2,0);
  *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0x7f;
  FUN_8000faec();
  uVar3 = FUN_8003709c(param_9,3);
  if (*(int *)(param_9 + 200) != 0) {
    FUN_8002cc9c(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(int *)(param_9 + 200));
    *(undefined4 *)(param_9 + 200) = 0;
  }
  (**(code **)(*DAT_803dd738 + 0x40))(param_9,iVar2,0x20);
  if (DAT_803de808 != (undefined *)0x0) {
    FUN_80013e4c(DAT_803de808);
  }
  DAT_803de808 = (undefined *)0x0;
  uVar1 = **(uint **)(iVar2 + 0x40c);
  if (uVar1 != 0) {
    FUN_8001f448(uVar1);
  }
  FUN_8005517c();
  return;
}

