// Function: FUN_80148d88
// Entry: 80148d88
// Size: 536 bytes

void FUN_80148d88(int param_1)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  int *piVar4;
  undefined2 local_18 [6];
  
  piVar4 = *(int **)(param_1 + 0xb8);
  local_18[0] = DAT_803e3050;
  FUN_800201ac(0x4e3,0xff);
  uVar1 = FUN_80020078(0x25);
  if (uVar1 != 0) {
    FUN_800201ac(0x3f8,1);
  }
  *(code **)(param_1 + 0xbc) = FUN_8014568c;
  FUN_800372f8(param_1,1);
  FUN_8004b750(piVar4 + 0x14e);
  FUN_8004b750(piVar4 + 0x15a);
  FUN_8004b750(piVar4 + 0x166);
  FUN_8004b750(piVar4 + 0x172);
  FUN_8004b750(piVar4 + 0x17e);
  FUN_8004b750(piVar4 + 0x18a);
  FUN_8004b750(piVar4 + 0x196);
  FUN_8004b750(piVar4 + 0x1a2);
  FUN_8004b750(piVar4 + 0x1ae);
  iVar2 = (**(code **)(*DAT_803dd72c + 0x94))();
  *piVar4 = iVar2;
  iVar2 = FUN_8002bac4();
  piVar4[1] = iVar2;
  *(undefined *)(piVar4 + 2) = 0;
  *(undefined *)((int)piVar4 + 0xb) = 0;
  piVar4[0x1bc] = 0;
  *(undefined2 *)(piVar4 + 0x34) = 0;
  piVar4[0x38] = *(int *)(param_1 + 0x18);
  piVar4[0x39] = *(int *)(param_1 + 0x1c);
  piVar4[0x3a] = *(int *)(param_1 + 0x20);
  *(byte *)(piVar4 + 0x20b) = *(byte *)(*piVar4 + 2) / 10;
  iVar2 = FUN_8002b660(param_1);
  *(undefined *)(*(int *)(iVar2 + 0x34) + 8) = *(undefined *)(piVar4 + 0x20b);
  piVar3 = piVar4 + 0x3e;
  (**(code **)(*DAT_803dd728 + 4))(piVar3,1,0xa7,1);
  (**(code **)(*DAT_803dd728 + 8))(piVar3,1,&DAT_8031df50,&DAT_803dc8b0,2);
  (**(code **)(*DAT_803dd728 + 0xc))(piVar3,2,&DAT_8031df38,&DAT_803dc8a8,local_18);
  (**(code **)(*DAT_803dd728 + 0x20))(param_1,piVar3);
  FUN_800dd8c8();
  FUN_800dc624();
  *(undefined *)(piVar4 + 0xdd) = 2;
  *(byte *)((int)piVar4 + 0x82e) = *(byte *)((int)piVar4 + 0x82e) & 0x7f | 0x80;
  *(undefined *)((int)piVar4 + 0xd) = 0xff;
  return;
}

