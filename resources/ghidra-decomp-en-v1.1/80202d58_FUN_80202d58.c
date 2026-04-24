// Function: FUN_80202d58
// Entry: 80202d58
// Size: 416 bytes

void FUN_80202d58(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  int iVar2;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_80286840();
  uVar1 = (uint)((ulonglong)uVar6 >> 0x20);
  iVar2 = (int)uVar6;
  iVar5 = *(int *)(uVar1 + 0xb8);
  iVar3 = *(int *)(uVar1 + 0x4c);
  iVar4 = *(int *)(iVar5 + 0x40c);
  if (*(char *)(iVar2 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 uVar1,0xe,0,in_r6,in_r7,in_r8,in_r9,in_r10);
    *(undefined *)(iVar2 + 0x346) = 0;
  }
  *(byte *)(uVar1 + 0xaf) = *(byte *)(uVar1 + 0xaf) | 8;
  if (FLOAT_803e6fe4 < *(float *)(uVar1 + 0x98)) {
    *(byte *)(iVar4 + 0x14) = *(byte *)(iVar4 + 0x14) | 2;
    FUN_80035ff8(uVar1);
  }
  if (*(char *)(iVar2 + 0x27a) != '\0') {
    *(float *)(iVar2 + 0x2a0) = FLOAT_803e6f8c;
    *(float *)(iVar2 + 0x280) = FLOAT_803e6f40;
  }
  if (*(char *)(iVar2 + 0x346) != '\0') {
    FUN_8000bb38(uVar1,0x1ea);
    *(float *)(iVar4 + 4) = FLOAT_803e6f60;
    uVar6 = FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,uVar1,8,0,in_r6,in_r7,in_r8,in_r9,in_r10);
    *(undefined4 *)(iVar2 + 0x2d0) = 0;
    *(undefined *)(iVar2 + 0x25f) = 0;
    *(undefined *)(iVar2 + 0x349) = 0;
    *(undefined2 *)(iVar5 + 0x402) = 0;
    *(byte *)(iVar5 + 0x404) = *(byte *)(iVar5 + 0x404) | *(byte *)(iVar3 + 0x2b);
    if (*(int *)(iVar4 + 0x18) != 0) {
      FUN_800379bc(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   *(int *)(iVar4 + 0x18),0x11,uVar1,0x13,in_r7,in_r8,in_r9,in_r10);
      *(undefined4 *)(iVar4 + 0x18) = 0;
      *(undefined2 *)(iVar4 + 0x1c) = 0xffff;
    }
    if ((*(byte *)(iVar4 + 0x15) & 2) == 0) {
      *(byte *)(uVar1 + 0xaf) = *(byte *)(uVar1 + 0xaf) | 8;
    }
    *(undefined *)(iVar4 + 0x34) = 1;
  }
  (**(code **)(*DAT_803dd70c + 0x34))(uVar1,iVar2,7,0,&DAT_8032a280);
  FUN_8028688c();
  return;
}

