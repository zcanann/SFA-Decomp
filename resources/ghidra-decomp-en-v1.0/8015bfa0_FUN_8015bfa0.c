// Function: FUN_8015bfa0
// Entry: 8015bfa0
// Size: 276 bytes

undefined4 FUN_8015bfa0(int param_1,int param_2)

{
  bool bVar1;
  float fVar2;
  int iVar3;
  
  iVar3 = *(int *)(*(int *)(param_1 + 0xb8) + 0x40c);
  *(byte *)(iVar3 + 0x44) = *(byte *)(iVar3 + 0x44) | 0xc;
  bVar1 = *(char *)(param_2 + 0x27a) != '\0';
  if (bVar1) {
    if (bVar1) {
      FUN_80030334((double)FLOAT_803e2d14,param_1,0xf,0);
      *(undefined *)(param_2 + 0x346) = 0;
    }
    *(undefined *)(param_2 + 0x34d) = 1;
  }
  *(float *)(param_2 + 0x2a0) = *(float *)(param_2 + 0x2c0) / FLOAT_803e2d3c;
  if (*(float *)(param_2 + 0x2a0) <= FLOAT_803e2d40) {
    if (*(float *)(param_2 + 0x2a0) < FLOAT_803e2d38) {
      *(float *)(param_2 + 0x2a0) = FLOAT_803e2d38;
    }
  }
  else {
    *(float *)(param_2 + 0x2a0) = FLOAT_803e2d40;
  }
  fVar2 = *(float *)(param_1 + 0x98);
  if (FLOAT_803e2d24 <= fVar2) {
    *(float *)(param_2 + 0x280) = FLOAT_803e2d44 * (FLOAT_803e2d48 - fVar2);
  }
  else {
    *(float *)(param_2 + 0x280) = FLOAT_803e2d44 * fVar2;
  }
  (**(code **)(*DAT_803dca8c + 0x30))((double)FLOAT_803db414,param_1,param_2,4);
  return 0;
}

