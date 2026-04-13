// Function: FUN_8027629c
// Entry: 8027629c
// Size: 384 bytes

void FUN_8027629c(int param_1,uint *param_2)

{
  char cVar1;
  char cVar2;
  uint local_10 [2];
  
  if ((*param_2 >> 0x18 & 3) == 0) {
    *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) & 0xffffbfff;
    *(undefined4 *)(param_1 + 0x114) = *(undefined4 *)(param_1 + 0x114);
  }
  else {
    *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) | 0x4000;
  }
  local_10[0] = param_2[1] >> 0x10;
  if ((param_2[1] >> 8 & 1) == 0) {
    FUN_802836f4(local_10,param_1);
  }
  else {
    FUN_802836e4((int *)local_10);
  }
  if (local_10[0] == 0) {
    *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) & 0xffffdfff;
    *(undefined4 *)(param_1 + 0x114) = *(undefined4 *)(param_1 + 0x114);
  }
  else {
    *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) | 0x2000;
    *(uint *)(param_1 + 0x144) = local_10[0];
    cVar2 = (char)(*param_2 >> 8);
    cVar1 = (char)(*param_2 >> 0x10);
    if (cVar2 < '\0') {
      if (cVar1 < '\0') {
        *(char *)(param_1 + 0x141) = -cVar1;
      }
      else {
        *(char *)(param_1 + 0x141) = cVar1;
      }
      *(char *)(param_1 + 0x140) = -cVar2;
      *(uint *)(param_1 + 0x148) = *(uint *)(param_1 + 0x144) >> 1;
    }
    else {
      if (cVar1 < '\0') {
        if (cVar2 == '\0') {
          *(char *)(param_1 + 0x141) = -cVar1;
          *(uint *)(param_1 + 0x148) = *(uint *)(param_1 + 0x144) >> 1;
        }
        else {
          *(char *)(param_1 + 0x141) = 'd' - cVar1;
          cVar2 = cVar2 + -1;
          *(undefined4 *)(param_1 + 0x148) = 0;
        }
      }
      else {
        *(char *)(param_1 + 0x141) = cVar1;
        *(undefined4 *)(param_1 + 0x148) = 0;
      }
      *(char *)(param_1 + 0x140) = cVar2;
    }
  }
  return;
}

