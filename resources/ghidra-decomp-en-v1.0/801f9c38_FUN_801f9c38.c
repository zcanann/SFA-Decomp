// Function: FUN_801f9c38
// Entry: 801f9c38
// Size: 304 bytes

void FUN_801f9c38(int param_1,int param_2)

{
  short sVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  FUN_80037200(param_1,9);
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
  DAT_803dc148 = 0x82;
  (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0xac));
  *(undefined2 *)(iVar3 + 10) = 0;
  *(undefined2 *)(iVar3 + 0xc) = 0;
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  FUN_80055038();
  FUN_800200e8(0xdcf,1);
  FUN_8004350c(0,0,1);
  iVar2 = FUN_8001ffb4(0xe1b);
  if (iVar2 == 0) {
    FUN_800200e8(0xe1a,0);
    FUN_800200e8(0xe19,0);
    FUN_800200e8(0xe17,0);
    FUN_800200e8(0xe18,0);
  }
  else {
    *(undefined *)(iVar3 + 0x18) = 4;
  }
  return;
}

