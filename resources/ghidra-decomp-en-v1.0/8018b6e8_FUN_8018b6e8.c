// Function: FUN_8018b6e8
// Entry: 8018b6e8
// Size: 200 bytes

void FUN_8018b6e8(short *param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x5c);
  param_1[0x58] = param_1[0x58] | 0x6000;
  iVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1c));
  if (iVar1 != 0) {
    *(float *)(iVar4 + 4) = FLOAT_803e3c4c;
  }
  *param_1 = (ushort)*(byte *)(param_2 + 0x23) << 8;
  uVar2 = FUN_8002b588(param_1);
  iVar1 = FUN_800285b8(uVar2,0);
  if (0 < *(short *)(param_2 + 0x24)) {
    iVar3 = FUN_8001ffb4();
    if (iVar3 == 0) {
      *(undefined *)(iVar1 + 8) = 0x16;
    }
    else {
      *(byte *)(iVar4 + 1) = *(byte *)(iVar4 + 1) | 0xc;
      *(undefined *)(iVar1 + 8) = 0x17;
    }
  }
  return;
}

