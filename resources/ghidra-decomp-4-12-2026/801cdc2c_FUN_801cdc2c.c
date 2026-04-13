// Function: FUN_801cdc2c
// Entry: 801cdc2c
// Size: 348 bytes

/* WARNING: Removing unreachable block (ram,0x801cdce4) */

void FUN_801cdc2c(undefined2 *param_1,int param_2)

{
  int *piVar1;
  int *piVar2;
  undefined auStack_38 [16];
  float local_28;
  undefined4 local_20;
  uint uStack_1c;
  
  piVar2 = *(int **)(param_1 + 0x5c);
  *param_1 = (short)(((int)*(char *)(param_2 + 0x18) & 0x3fU) << 10);
  if (*(short *)(param_2 + 0x1a) < 1) {
    *(float *)(param_1 + 4) = FLOAT_803e5e80;
  }
  else {
    uStack_1c = (int)*(short *)(param_2 + 0x1a) ^ 0x80000000;
    local_20 = 0x43300000;
    *(float *)(param_1 + 4) =
         (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e5e88) / FLOAT_803e5e7c;
  }
  *(undefined *)((int)piVar2 + 0xb) = *(undefined *)(param_2 + 0x19);
  *(undefined *)(piVar2 + 3) = 0;
  *(undefined *)((int)piVar2 + 0xf) = 0;
  *piVar2 = (int)*(short *)(param_2 + 0x1e);
  local_28 = FLOAT_803e5e78;
  if (*(char *)((int)piVar2 + 0xb) == '\x01') {
    *(char *)((int)piVar2 + 0xf) = (char)*(undefined2 *)(param_2 + 0x1c);
    *(undefined *)((int)piVar2 + 0xd) = 0;
    *(ushort *)(piVar2 + 2) = (ushort)*(byte *)((int)piVar2 + 0xf) * 0x28 + 0x398;
    *(undefined *)((int)piVar2 + 0xe) = 0;
  }
  else if (*(char *)((int)piVar2 + 0xb) == '\0') {
    *(undefined *)(piVar2 + 3) = 1;
    piVar1 = (int *)FUN_80013ee8(0x69);
    if (*(short *)(param_2 + 0x1c) == 0) {
      (**(code **)(*piVar1 + 4))(param_1,0,auStack_38,0x10004,0xffffffff,0);
    }
  }
  *(undefined2 *)(piVar2 + 1) = 0;
  return;
}

