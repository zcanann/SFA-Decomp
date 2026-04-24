// Function: FUN_8018bc64
// Entry: 8018bc64
// Size: 200 bytes

void FUN_8018bc64(short *param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x5c);
  param_1[0x58] = param_1[0x58] | 0x6000;
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x1c));
  if (uVar1 != 0) {
    *(float *)(iVar3 + 4) = FLOAT_803e48e4;
  }
  *param_1 = (ushort)*(byte *)(param_2 + 0x23) << 8;
  iVar2 = FUN_8002b660((int)param_1);
  iVar2 = FUN_8002867c(iVar2,0);
  if (0 < *(short *)(param_2 + 0x24)) {
    uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x24));
    if (uVar1 == 0) {
      *(undefined *)(iVar2 + 8) = 0x16;
    }
    else {
      *(byte *)(iVar3 + 1) = *(byte *)(iVar3 + 1) | 0xc;
      *(undefined *)(iVar2 + 8) = 0x17;
    }
  }
  return;
}

