// Function: FUN_80234d5c
// Entry: 80234d5c
// Size: 100 bytes

void FUN_80234d5c(int param_1,int param_2)

{
  char cVar1;
  undefined2 *puVar2;
  
  puVar2 = *(undefined2 **)(param_1 + 0xb8);
  *puVar2 = *(undefined2 *)(param_2 + 0x1e);
  *(float *)(puVar2 + 2) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
              DOUBLE_803e7280);
  cVar1 = (char)*(byte *)(param_2 + 0x19) >> 7;
  *(byte *)(puVar2 + 4) = (*(byte *)(param_2 + 0x19) & 1 ^ -cVar1) + cVar1;
  *(undefined *)((int)puVar2 + 9) = 0xff;
  return;
}

