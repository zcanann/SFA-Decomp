// Function: FUN_80203aa8
// Entry: 80203aa8
// Size: 428 bytes

void FUN_80203aa8(int param_1,int param_2,int param_3)

{
  uint uVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  uVar2 = 6;
  if (param_3 != 0) {
    uVar2 = 7;
  }
  (**(code **)(*DAT_803dcab8 + 0x58))
            ((double)FLOAT_803e62fc,param_1,param_2,iVar4,0x10,7,0x10a,uVar2);
  FUN_80037200(param_1,3);
  *(undefined4 *)(param_1 + 0xbc) = 0;
  puVar3 = *(undefined4 **)(iVar4 + 0x40c);
  FUN_800033a8(puVar3,0,0x50);
  puVar3[2] = FLOAT_803e62fc;
  *puVar3 = &PTR_DAT_80329514 + *(short *)(param_2 + 0x24) * 2;
  uVar1 = FUN_800221a0(10,300);
  puVar3[3] = (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e6368);
  *(byte *)(puVar3 + 0x11) =
       (byte)((*(byte *)(param_2 + 0x2b) & 1) << 5) | *(byte *)(puVar3 + 0x11) & 0xdf;
  *(byte *)(puVar3 + 0x11) = *(byte *)(puVar3 + 0x11) & 0xef | 0x10;
  puVar3[6] = 0;
  FUN_80030334((double)FLOAT_803e62a8,param_1,8,0);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  (**(code **)(*DAT_803dca8c + 0x14))(param_1,iVar4,3);
  *(undefined2 *)(iVar4 + 0x270) = 0;
  *(undefined *)(iVar4 + 0x25f) = 1;
  FUN_80035f20(param_1);
  FUN_80037964(param_1,4);
  iVar4 = *(int *)(param_1 + 100);
  if (iVar4 != 0) {
    *(uint *)(iVar4 + 0x30) = *(uint *)(iVar4 + 0x30) | 0x4008;
  }
  return;
}

