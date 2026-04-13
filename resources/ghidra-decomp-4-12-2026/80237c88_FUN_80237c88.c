// Function: FUN_80237c88
// Entry: 80237c88
// Size: 504 bytes

void FUN_80237c88(int param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  if (((int)*(short *)(iVar4 + 0x24) == 0xffffffff) ||
     (uVar1 = FUN_80020078((int)*(short *)(iVar4 + 0x24)), uVar1 != 0)) {
    if (*(short *)(param_1 + 0x46) == 0x807) {
      if ((*(byte *)(iVar4 + 0x1b) != 0) && (*(byte *)(iVar4 + 0x1c) != 0)) {
        FUN_8009742c((double)*(float *)(iVar4 + 0x20),param_1,*(byte *)(iVar4 + 0x1b),
                     (uint)*(byte *)(iVar4 + 0x1c),(uint)*(byte *)(iVar4 + 0x1d),0);
      }
    }
    else if (*(short *)(param_1 + 0x46) == 0x80e) {
      if ((*(byte *)(iVar4 + 0x1b) != 0) && (*(byte *)(iVar4 + 0x1c) != 0)) {
        FUN_800972fc(param_1,(uint)*(byte *)(iVar4 + 0x1b),(uint)*(byte *)(iVar4 + 0x1c),
                     (uint)*(byte *)(iVar4 + 0x1d),0);
      }
    }
    else {
      uVar1 = (uint)*(byte *)(iVar4 + 0x1b);
      if (((uVar1 != 0) && (uVar2 = (uint)*(byte *)(iVar4 + 0x1c), uVar2 != 0)) &&
         (uVar3 = (uint)*(byte *)(iVar4 + 0x1d), uVar3 != 0)) {
        if (*(char *)(iVar4 + 0x2a) == '\0') {
          FUN_80097dbc((double)*(float *)(iVar4 + 0x20),
                       (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar4 + 0x26)) -
                                      DOUBLE_803e8060),
                       (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar4 + 0x27)) -
                                      DOUBLE_803e8060),
                       (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar4 + 0x28)) -
                                      DOUBLE_803e8060),param_1,uVar1,uVar2,uVar3,
                       (uint)*(byte *)(iVar4 + 0x29),0,0);
        }
        else if (*(char *)(iVar4 + 0x2a) == '\x01') {
          FUN_800979c0((double)*(float *)(iVar4 + 0x20),
                       (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar4 + 0x26)) -
                                      DOUBLE_803e8060),
                       (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar4 + 0x27)) -
                                      DOUBLE_803e8060),
                       (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar4 + 0x28)) -
                                      DOUBLE_803e8060),param_1,uVar1,uVar2,uVar3,
                       (uint)*(byte *)(iVar4 + 0x29),0,0);
        }
        else {
          FUN_80097568((double)*(float *)(iVar4 + 0x20),
                       (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar4 + 0x26)) -
                                      DOUBLE_803e8060),param_1,uVar1,uVar2,uVar3,
                       (uint)*(byte *)(iVar4 + 0x29),0,0);
        }
      }
    }
  }
  return;
}

