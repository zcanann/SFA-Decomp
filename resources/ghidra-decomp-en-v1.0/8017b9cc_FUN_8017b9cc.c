// Function: FUN_8017b9cc
// Entry: 8017b9cc
// Size: 436 bytes

void FUN_8017b9cc(short *param_1,int param_2)

{
  char cVar1;
  short sVar2;
  undefined uVar4;
  int iVar3;
  undefined2 *puVar5;
  
  puVar5 = *(undefined2 **)(param_1 + 0x5c);
  *(undefined *)((int)puVar5 + 5) = 1;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1f) << 8;
  *(code **)(param_1 + 0x5e) = FUN_8017b5c8;
  param_1[0x58] = param_1[0x58] | 0x2000;
  *(float *)(param_1 + 4) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x21)) - DOUBLE_803e3790) *
       FLOAT_803e3784;
  if (*(float *)(param_1 + 4) == FLOAT_803e3788) {
    *(float *)(param_1 + 4) = FLOAT_803e3780;
  }
  *(float *)(param_1 + 4) = *(float *)(param_1 + 4) * *(float *)(*(int *)(param_1 + 0x28) + 4);
  if (*(short *)(param_2 + 0x1a) == -1) {
    *(undefined *)(puVar5 + 2) = 0;
  }
  else {
    uVar4 = FUN_8001ffb4();
    *(undefined *)(puVar5 + 2) = uVar4;
  }
  *(undefined *)(puVar5 + 3) = 0;
  iVar3 = FUN_8001ffb4((int)*(short *)(param_2 + 0x18));
  if (iVar3 != 0) {
    *(byte *)(puVar5 + 3) = *(byte *)(puVar5 + 3) | 1;
  }
  iVar3 = FUN_8001ffb4((int)*(short *)(param_2 + 0x22));
  if (iVar3 != 0) {
    *(byte *)(puVar5 + 3) = *(byte *)(puVar5 + 3) | 2;
  }
  sVar2 = param_1[0x23];
  if (sVar2 != 0x44d) {
    if (0x44c < sVar2) {
      return;
    }
    if (sVar2 != 0x166) {
      return;
    }
    *puVar5 = 0x113;
    puVar5[1] = 0x1f8;
    return;
  }
  cVar1 = *(char *)(param_1 + 0x56);
  if (cVar1 < '(') {
    if ((cVar1 < '#') && ('\x1e' < cVar1)) {
LAB_8017bb2c:
      *puVar5 = 0x340;
      puVar5[1] = 0x341;
      return;
    }
  }
  else if (cVar1 < '+') goto LAB_8017bb2c;
  *puVar5 = 0x482;
  puVar5[1] = 0x483;
  return;
}

