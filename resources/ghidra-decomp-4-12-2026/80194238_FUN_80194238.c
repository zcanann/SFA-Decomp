// Function: FUN_80194238
// Entry: 80194238
// Size: 256 bytes

void FUN_80194238(int param_1,int param_2)

{
  double dVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  *(char *)(iVar3 + 0x2b) = (char)*(undefined2 *)(param_2 + 0x1e);
  dVar1 = DOUBLE_803e4c38;
  *(float *)(iVar3 + 0x18) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x27)) - DOUBLE_803e4c38);
  *(float *)(iVar3 + 0x10) = FLOAT_803e4c50;
  *(float *)(iVar3 + 0x14) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x26)) - dVar1);
  if (*(char *)(param_2 + 0x25) != '\0') {
    uVar2 = FUN_80020078((int)*(short *)(param_2 + 0x18));
    if (uVar2 != 0) {
      *(float *)(iVar3 + 0xc) =
           FLOAT_803e4c30 *
           (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x20)) - DOUBLE_803e4c38);
      *(byte *)(iVar3 + 0x2d) = *(byte *)(iVar3 + 0x2d) | 2;
    }
    FUN_800372f8(param_1,0x31);
    if (1 < *(byte *)(param_2 + 0x21)) {
      *(undefined *)(param_2 + 0x21) = 0;
    }
  }
  return;
}

