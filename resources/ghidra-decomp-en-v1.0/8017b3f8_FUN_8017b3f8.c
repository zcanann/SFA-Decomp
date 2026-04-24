// Function: FUN_8017b3f8
// Entry: 8017b3f8
// Size: 464 bytes

void FUN_8017b3f8(short *param_1,int param_2)

{
  short sVar1;
  float fVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined *puVar5;
  
  puVar5 = *(undefined **)(param_1 + 0x5c);
  *param_1 = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[0x58] = param_1[0x58] | 0x6000;
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x19);
  if (*(char *)(*(int *)(param_1 + 0x28) + 0x55) <= *(char *)((int)param_1 + 0xad)) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  fVar2 = FLOAT_803e3778;
  *(float *)(puVar5 + 0x80) = FLOAT_803e3778;
  if (param_1[0x23] == 0x77b) {
    puVar5[0x84] = puVar5[0x84] & 0x7f | 0x80;
    puVar5[0x84] = puVar5[0x84] & 0xbf | 0x40;
    puVar5[0x84] = puVar5[0x84] & 0xdf | 0x20;
    *(float *)(puVar5 + 0x80) = fVar2;
  }
  *(undefined4 *)(puVar5 + 0x7c) = *(undefined4 *)(param_2 + 0xc);
  iVar3 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1a));
  if (iVar3 != 0) {
    *(float *)(param_1 + 8) =
         *(float *)(puVar5 + 0x7c) -
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1c)) - DOUBLE_803e3770);
    *puVar5 = 0x1e;
    puVar5[0x84] = puVar5[0x84] & 0xdf;
    sVar1 = param_1[0x23];
    if ((((sVar1 != 0x19f) && (sVar1 != 0x26c)) && (sVar1 != 0x274)) && (sVar1 != 0x545)) {
      puVar5[0x84] = puVar5[0x84] & 0xef | 0x10;
    }
    if (((char)puVar5[0x84] < '\0') &&
       (puVar4 = (undefined4 *)FUN_800394ac(param_1,0,0), puVar4 != (undefined4 *)0x0)) {
      *puVar4 = 0x100;
    }
  }
  FUN_80037200(param_1,0x53);
  *(undefined4 *)(puVar5 + 4) = 0;
  *(undefined4 *)(puVar5 + 8) = 0;
  *(undefined4 *)(puVar5 + 0xc) = 0;
  *(undefined4 *)(puVar5 + 0x10) = 0;
  *(undefined4 *)(puVar5 + 0x14) = 0;
  *(undefined4 *)(puVar5 + 0x18) = 0;
  *(undefined4 *)(puVar5 + 0x1c) = 0;
  *(undefined4 *)(puVar5 + 0x20) = 0;
  *(undefined4 *)(puVar5 + 0x24) = 0;
  *(undefined4 *)(puVar5 + 0x28) = 0;
  *(code **)(param_1 + 0x5e) = FUN_8017ac2c;
  return;
}

