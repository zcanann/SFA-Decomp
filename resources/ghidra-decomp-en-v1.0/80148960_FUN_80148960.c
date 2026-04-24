// Function: FUN_80148960
// Entry: 80148960
// Size: 536 bytes

void FUN_80148960(int param_1)

{
  int iVar1;
  int *piVar2;
  int *piVar3;
  undefined2 local_18 [6];
  
  piVar3 = *(int **)(param_1 + 0xb8);
  local_18[0] = DAT_803e23c0;
  FUN_800200e8(0x4e3,0xff);
  iVar1 = FUN_8001ffb4(0x25);
  if (iVar1 != 0) {
    FUN_800200e8(0x3f8,1);
  }
  *(code **)(param_1 + 0xbc) = FUN_80145304;
  FUN_80037200(param_1,1);
  FUN_8004b5d4(piVar3 + 0x14e);
  FUN_8004b5d4(piVar3 + 0x15a);
  FUN_8004b5d4(piVar3 + 0x166);
  FUN_8004b5d4(piVar3 + 0x172);
  FUN_8004b5d4(piVar3 + 0x17e);
  FUN_8004b5d4(piVar3 + 0x18a);
  FUN_8004b5d4(piVar3 + 0x196);
  FUN_8004b5d4(piVar3 + 0x1a2);
  FUN_8004b5d4(piVar3 + 0x1ae);
  iVar1 = (**(code **)(*DAT_803dcaac + 0x94))();
  *piVar3 = iVar1;
  iVar1 = FUN_8002b9ec();
  piVar3[1] = iVar1;
  *(undefined *)(piVar3 + 2) = 0;
  *(undefined *)((int)piVar3 + 0xb) = 0;
  piVar3[0x1bc] = 0;
  *(undefined2 *)(piVar3 + 0x34) = 0;
  piVar3[0x38] = *(int *)(param_1 + 0x18);
  piVar3[0x39] = *(int *)(param_1 + 0x1c);
  piVar3[0x3a] = *(int *)(param_1 + 0x20);
  *(byte *)(piVar3 + 0x20b) = *(byte *)(*piVar3 + 2) / 10;
  iVar1 = FUN_8002b588(param_1);
  *(undefined *)(*(int *)(iVar1 + 0x34) + 8) = *(undefined *)(piVar3 + 0x20b);
  piVar2 = piVar3 + 0x3e;
  (**(code **)(*DAT_803dcaa8 + 4))(piVar2,1,0xa7,1);
  (**(code **)(*DAT_803dcaa8 + 8))(piVar2,1,&DAT_8031d300,&DAT_803dbc48,2);
  (**(code **)(*DAT_803dcaa8 + 0xc))(piVar2,2,&DAT_8031d2e8,&DAT_803dbc40,local_18);
  (**(code **)(*DAT_803dcaa8 + 0x20))(param_1,piVar2);
  FUN_800dd644();
  FUN_800dc398();
  *(undefined *)(piVar3 + 0xdd) = 2;
  *(byte *)((int)piVar3 + 0x82e) = *(byte *)((int)piVar3 + 0x82e) & 0x7f | 0x80;
  *(undefined *)((int)piVar3 + 0xd) = 0xff;
  return;
}

