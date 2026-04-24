// Function: FUN_801fa270
// Entry: 801fa270
// Size: 304 bytes

void FUN_801fa270(int param_1,int param_2)

{
  short sVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  FUN_800372f8(param_1,9);
  *(undefined2 *)(iVar3 + 2) = 0;
  *(undefined2 *)(iVar3 + 4) = 0;
  *(undefined2 *)(iVar3 + 6) = 0;
  *(undefined2 *)(iVar3 + 8) = 0;
  *(undefined2 *)(iVar3 + 10) = 0;
  *(undefined2 *)(iVar3 + 0xc) = 0;
  *(undefined2 *)(iVar3 + 0xe) = 1;
  sVar1 = *(short *)(param_2 + 0x1a);
  if ((sVar1 != 0) && (sVar1 < 3)) {
    *(short *)(iVar3 + 0xe) = sVar1;
  }
  DAT_803dcdb0 = 0x82;
  (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0xac));
  *(undefined2 *)(iVar3 + 10) = 0;
  *(undefined2 *)(iVar3 + 0xc) = 0;
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  FUN_800551b4();
  FUN_800201ac(0xdcf,1);
  FUN_80043604(0,0,1);
  uVar2 = FUN_80020078(0xe1b);
  if (uVar2 == 0) {
    FUN_800201ac(0xe1a,0);
    FUN_800201ac(0xe19,0);
    FUN_800201ac(0xe17,0);
    FUN_800201ac(0xe18,0);
  }
  else {
    *(undefined *)(iVar3 + 0x18) = 4;
  }
  return;
}

