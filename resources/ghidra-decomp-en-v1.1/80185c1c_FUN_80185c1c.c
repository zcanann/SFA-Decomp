// Function: FUN_80185c1c
// Entry: 80185c1c
// Size: 420 bytes

void FUN_80185c1c(int param_1,int param_2)

{
  short sVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  *(undefined *)(iVar4 + 0x24) = 0;
  *(undefined2 *)(iVar4 + 0x14) = *(undefined2 *)(param_2 + 0x1a);
  uVar2 = FUN_80022264(1000,4000);
  *(short *)(iVar4 + 0x16) = (short)uVar2;
  uVar2 = FUN_80022264(0x32,100);
  *(short *)(iVar4 + 0x1c) = (short)uVar2;
  *(undefined4 *)(iVar4 + 0xc) = *(undefined4 *)(param_2 + 0xc);
  iVar3 = FUN_8002b660(param_1);
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x3d5) {
    uVar2 = FUN_80022264(0,3);
    *(undefined *)(*(int *)(iVar3 + 0x34) + 8) = (&DAT_803dca20)[uVar2];
    *(undefined2 *)(iVar4 + 0x1e) = 0x43;
    *(undefined2 *)(iVar4 + 0x20) = 2;
    *(undefined2 *)(iVar4 + 0x22) = 4;
    *(undefined *)(iVar4 + 0x27) = 2;
    goto LAB_80185d98;
  }
  if (sVar1 < 0x3d5) {
    if (sVar1 == 0x3d3) {
      uVar2 = FUN_80022264(0,2);
      *(undefined *)(*(int *)(iVar3 + 0x34) + 8) = (&DAT_803dca18)[uVar2];
      *(undefined2 *)(iVar4 + 0x1e) = 0x41;
      *(undefined2 *)(iVar4 + 0x20) = 4;
      *(undefined2 *)(iVar4 + 0x22) = 2;
      *(undefined *)(iVar4 + 0x27) = 0;
      goto LAB_80185d98;
    }
    if (0x3d2 < sVar1) {
      uVar2 = FUN_80022264(0,1);
      *(undefined *)(*(int *)(iVar3 + 0x34) + 8) = (&DAT_803dca1c)[uVar2];
      *(undefined2 *)(iVar4 + 0x1e) = 0x42;
      *(undefined2 *)(iVar4 + 0x20) = 1;
      *(undefined2 *)(iVar4 + 0x22) = 5;
      *(undefined *)(iVar4 + 0x27) = 1;
      goto LAB_80185d98;
    }
  }
  *(undefined *)(*(int *)(iVar3 + 0x34) + 8) = 5;
  *(undefined2 *)(iVar4 + 0x1e) = 0x44;
  *(undefined2 *)(iVar4 + 0x20) = 6;
  *(undefined2 *)(iVar4 + 0x22) = 1;
  *(undefined *)(iVar4 + 0x27) = 3;
LAB_80185d98:
  FUN_80037a5c(param_1,2);
  return;
}

