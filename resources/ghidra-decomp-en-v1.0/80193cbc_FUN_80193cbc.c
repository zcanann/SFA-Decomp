// Function: FUN_80193cbc
// Entry: 80193cbc
// Size: 256 bytes

void FUN_80193cbc(int param_1,int param_2)

{
  double dVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  *(char *)(iVar3 + 0x2b) = (char)*(undefined2 *)(param_2 + 0x1e);
  dVar1 = DOUBLE_803e3fa0;
  *(float *)(iVar3 + 0x18) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x27)) - DOUBLE_803e3fa0);
  *(float *)(iVar3 + 0x10) = FLOAT_803e3fb8;
  *(float *)(iVar3 + 0x14) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x26)) - dVar1);
  if (*(char *)(param_2 + 0x25) != '\0') {
    iVar2 = FUN_8001ffb4((int)*(short *)(param_2 + 0x18));
    if (iVar2 != 0) {
      *(float *)(iVar3 + 0xc) =
           FLOAT_803e3f98 *
           (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x20)) - DOUBLE_803e3fa0);
      *(byte *)(iVar3 + 0x2d) = *(byte *)(iVar3 + 0x2d) | 2;
    }
    FUN_80037200(param_1,0x31);
    if (1 < *(byte *)(param_2 + 0x21)) {
      *(undefined *)(param_2 + 0x21) = 0;
    }
  }
  return;
}

