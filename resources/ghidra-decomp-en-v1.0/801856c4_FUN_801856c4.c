// Function: FUN_801856c4
// Entry: 801856c4
// Size: 420 bytes

void FUN_801856c4(int param_1,int param_2)

{
  short sVar1;
  undefined2 uVar4;
  int iVar2;
  int iVar3;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  *(undefined *)(iVar5 + 0x24) = 0;
  *(undefined2 *)(iVar5 + 0x14) = *(undefined2 *)(param_2 + 0x1a);
  uVar4 = FUN_800221a0(1000,4000);
  *(undefined2 *)(iVar5 + 0x16) = uVar4;
  uVar4 = FUN_800221a0(0x32,100);
  *(undefined2 *)(iVar5 + 0x1c) = uVar4;
  *(undefined4 *)(iVar5 + 0xc) = *(undefined4 *)(param_2 + 0xc);
  iVar2 = FUN_8002b588(param_1);
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x3d5) {
    iVar3 = FUN_800221a0(0,3);
    *(undefined *)(*(int *)(iVar2 + 0x34) + 8) = (&DAT_803dbdb8)[iVar3];
    *(undefined2 *)(iVar5 + 0x1e) = 0x43;
    *(undefined2 *)(iVar5 + 0x20) = 2;
    *(undefined2 *)(iVar5 + 0x22) = 4;
    *(undefined *)(iVar5 + 0x27) = 2;
    goto LAB_80185840;
  }
  if (sVar1 < 0x3d5) {
    if (sVar1 == 0x3d3) {
      iVar3 = FUN_800221a0(0,2);
      *(undefined *)(*(int *)(iVar2 + 0x34) + 8) = (&DAT_803dbdb0)[iVar3];
      *(undefined2 *)(iVar5 + 0x1e) = 0x41;
      *(undefined2 *)(iVar5 + 0x20) = 4;
      *(undefined2 *)(iVar5 + 0x22) = 2;
      *(undefined *)(iVar5 + 0x27) = 0;
      goto LAB_80185840;
    }
    if (0x3d2 < sVar1) {
      iVar3 = FUN_800221a0(0,1);
      *(undefined *)(*(int *)(iVar2 + 0x34) + 8) = (&DAT_803dbdb4)[iVar3];
      *(undefined2 *)(iVar5 + 0x1e) = 0x42;
      *(undefined2 *)(iVar5 + 0x20) = 1;
      *(undefined2 *)(iVar5 + 0x22) = 5;
      *(undefined *)(iVar5 + 0x27) = 1;
      goto LAB_80185840;
    }
  }
  *(undefined *)(*(int *)(iVar2 + 0x34) + 8) = 5;
  *(undefined2 *)(iVar5 + 0x1e) = 0x44;
  *(undefined2 *)(iVar5 + 0x20) = 6;
  *(undefined2 *)(iVar5 + 0x22) = 1;
  *(undefined *)(iVar5 + 0x27) = 3;
LAB_80185840:
  FUN_80037964(param_1,2);
  return;
}

