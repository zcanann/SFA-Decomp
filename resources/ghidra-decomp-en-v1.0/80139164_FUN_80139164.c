// Function: FUN_80139164
// Entry: 80139164
// Size: 252 bytes

void FUN_80139164(undefined2 *param_1,int param_2)

{
  bool bVar1;
  char cVar2;
  undefined2 local_28;
  undefined2 local_26;
  undefined2 local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  cVar2 = '\x14';
  if ((*(uint *)(param_2 + 0x54) & 0x1800) != 0) {
    local_1c = *(float *)(param_2 + 0x408) - *(float *)(param_1 + 0xc);
    local_18 = *(float *)(param_2 + 0x40c) - *(float *)(param_1 + 0xe);
    local_14 = *(float *)(param_2 + 0x410) - *(float *)(param_1 + 0x10);
    local_20 = FLOAT_803e23e8;
    local_28 = *param_1;
    local_26 = param_1[1];
    local_24 = param_1[2];
    if ((*(uint *)(param_2 + 0x54) & 0x800) == 0) {
      while (bVar1 = cVar2 != '\0', cVar2 = cVar2 + -1, bVar1) {
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x533,&local_28,2,0xffffffff,0);
      }
      *(uint *)(param_2 + 0x54) = *(uint *)(param_2 + 0x54) & 0xffffefff;
    }
  }
  return;
}

