// Function: FUN_8017bf24
// Entry: 8017bf24
// Size: 436 bytes

void FUN_8017bf24(short *param_1,int param_2)

{
  char cVar1;
  short sVar2;
  uint uVar3;
  undefined2 *puVar4;
  
  puVar4 = *(undefined2 **)(param_1 + 0x5c);
  *(undefined *)((int)puVar4 + 5) = 1;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1f) << 8;
  *(code **)(param_1 + 0x5e) = FUN_8017bb20;
  param_1[0x58] = param_1[0x58] | 0x2000;
  *(float *)(param_1 + 4) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x21)) - DOUBLE_803e4428) *
       FLOAT_803e441c;
  if (*(float *)(param_1 + 4) == FLOAT_803e4420) {
    *(float *)(param_1 + 4) = FLOAT_803e4418;
  }
  *(float *)(param_1 + 4) = *(float *)(param_1 + 4) * *(float *)(*(int *)(param_1 + 0x28) + 4);
  if ((int)*(short *)(param_2 + 0x1a) == 0xffffffff) {
    *(undefined *)(puVar4 + 2) = 0;
  }
  else {
    uVar3 = FUN_80020078((int)*(short *)(param_2 + 0x1a));
    *(char *)(puVar4 + 2) = (char)uVar3;
  }
  *(undefined *)(puVar4 + 3) = 0;
  uVar3 = FUN_80020078((int)*(short *)(param_2 + 0x18));
  if (uVar3 != 0) {
    *(byte *)(puVar4 + 3) = *(byte *)(puVar4 + 3) | 1;
  }
  uVar3 = FUN_80020078((int)*(short *)(param_2 + 0x22));
  if (uVar3 != 0) {
    *(byte *)(puVar4 + 3) = *(byte *)(puVar4 + 3) | 2;
  }
  sVar2 = param_1[0x23];
  if (sVar2 != 0x44d) {
    if (0x44c < sVar2) {
      return;
    }
    if (sVar2 != 0x166) {
      return;
    }
    *puVar4 = 0x113;
    puVar4[1] = 0x1f8;
    return;
  }
  cVar1 = *(char *)(param_1 + 0x56);
  if (cVar1 < '(') {
    if ((cVar1 < '#') && ('\x1e' < cVar1)) {
LAB_8017c084:
      *puVar4 = 0x340;
      puVar4[1] = 0x341;
      return;
    }
  }
  else if (cVar1 < '+') goto LAB_8017c084;
  *puVar4 = 0x482;
  puVar4[1] = 0x483;
  return;
}

