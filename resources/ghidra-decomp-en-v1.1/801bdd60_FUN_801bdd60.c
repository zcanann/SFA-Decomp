// Function: FUN_801bdd60
// Entry: 801bdd60
// Size: 804 bytes

void FUN_801bdd60(int param_1,undefined4 param_2,int param_3)

{
  float fVar1;
  uint uVar2;
  char cVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 *puVar6;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined2 local_1c;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  local_28 = DAT_802c2ab8;
  local_24 = DAT_802c2abc;
  local_20 = DAT_802c2ac0;
  local_1c = DAT_802c2ac4;
  FUN_8005d06c(0);
  *(undefined *)(param_1 + 0xe4) = 2;
  uVar4 = 6;
  if (param_3 != 0) {
    uVar4 = 7;
  }
  (**(code **)(*DAT_803dd738 + 0x58))
            ((double)FLOAT_803e58c0,param_1,param_2,iVar5,0xc,6,0x102,uVar4);
  *(code **)(param_1 + 0xbc) = FUN_801bd0e8;
  *(undefined2 *)(iVar5 + 0x402) = 0;
  (**(code **)(*DAT_803dd70c + 0x14))(param_1,iVar5,0);
  *(undefined2 *)(iVar5 + 0x270) = 0;
  *(undefined *)(iVar5 + 0x354) = 3;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x88;
  uVar2 = FUN_80020078(0x210);
  if (uVar2 != 0) {
    *(undefined2 *)(iVar5 + 0x402) = 4;
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  uVar2 = FUN_80020078(0x20e);
  if (uVar2 != 0) {
    *(undefined2 *)(iVar5 + 0x402) = 3;
  }
  fVar1 = FLOAT_803e5870;
  puVar6 = *(undefined4 **)(iVar5 + 0x40c);
  puVar6[0x2a] = FLOAT_803e5870;
  puVar6[0x29] = fVar1;
  *(undefined2 *)(param_1 + 0xa2) = 0xffff;
  *puVar6 = 0;
  DAT_803de804 = 0;
  DAT_803de800 = 0;
  FUN_800201ac(0x4e4,1);
  FUN_80115200(param_1,(undefined4 *)&DAT_803ad63c,0xd8e4,0x1c71,6);
  FUN_80114238(-0x7fc529c4,(wchar_t *)&local_28,(wchar_t *)&local_28);
  DAT_803adc4d = DAT_803adc4d & 0xfe | 8;
  *(byte *)((int)puVar6 + 0xb6) = *(byte *)((int)puVar6 + 0xb6) & 0x7f | 0x80;
  DAT_803de808 = FUN_80013ee8(0x5a);
  uVar2 = FUN_80020078(0x1df);
  if (uVar2 == 0) {
    *(undefined *)(puVar6 + 0x2d) = 2;
    puVar6[0x2b] = FLOAT_803e5910;
    (**(code **)(*DAT_803dd72c + 0x50))(0x1c,5,1);
  }
  else {
    (**(code **)(*DAT_803dd72c + 0x50))(0x1c,5,0);
  }
  puVar6[0x2c] = 0;
  cVar3 = (**(code **)(*DAT_803dd72c + 0x40))(7);
  if (cVar3 == '\x02') {
    (**(code **)(*DAT_803dd72c + 0x44))(7,3);
  }
  FUN_800201ac(0xefd,1);
  FUN_80043604(0,0,1);
  uVar4 = FUN_8004832c(0x1c);
  FUN_80043658(uVar4,1);
  uVar4 = FUN_8004832c(0x1b);
  FUN_80043658(uVar4,0);
  FUN_800201ac(0xcbb,0);
  FUN_8000a538((int *)0x36,1);
  FUN_800201ac(0xda5,0);
  FUN_8000a538((int *)0xd7,0);
  FUN_8000a538((int *)0xe0,0);
  return;
}

