// Function: FUN_80297a14
// Entry: 80297a14
// Size: 484 bytes

void FUN_80297a14(int param_1,uint *param_2,undefined4 *param_3,undefined4 *param_4,
                 undefined4 *param_5,undefined2 *param_6)

{
  char cVar1;
  float fVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  *param_2 = 0;
  fVar2 = FLOAT_803e8b3c;
  *param_3 = FLOAT_803e8b3c;
  *param_4 = fVar2;
  *param_5 = fVar2;
  if (*(short *)(iVar3 + 0x274) == 0x26) {
    *param_2 = *param_2 | 1;
    if (*(char *)(iVar3 + 0x8ce) != -1) {
      *param_2 = *param_2 |
                 *(uint *)(*(int *)(iVar3 + 0x3dc) + (uint)*(byte *)(iVar3 + 0x8a9) * 0xb0 +
                           *(char *)(iVar3 + 0x8ce) * 4 + 8);
      *param_4 = *(undefined4 *)
                  (*(int *)(iVar3 + 0x3dc) + (uint)*(byte *)(iVar3 + 0x8a9) * 0xb0 +
                   *(char *)(iVar3 + 0x8ce) * 4 + 0x70);
      *param_5 = *(undefined4 *)
                  (*(int *)(iVar3 + 0x3dc) + (uint)*(byte *)(iVar3 + 0x8a9) * 0xb0 +
                   *(char *)(iVar3 + 0x8ce) * 4 + 0x7c);
      *param_3 = *(undefined4 *)
                  (*(int *)(iVar3 + 0x3dc) + (uint)*(byte *)(iVar3 + 0x8a9) * 0xb0 +
                   *(char *)(iVar3 + 0x8ce) * 4 + 0x94);
    }
    fVar2 = FLOAT_803e8b3c;
    if (((*(byte *)(*(int *)(iVar3 + 0x3dc) + (uint)*(byte *)(iVar3 + 0x8a9) * 0xb0 + 0x88) & 2) !=
         0) && (*(byte *)(iVar3 + 0x8ab) < *(byte *)(iVar3 + 0x8ac))) {
      *param_4 = FLOAT_803e8b3c;
      *param_5 = fVar2;
    }
    if ((*(byte *)(*(int *)(iVar3 + 0x3dc) + (uint)*(byte *)(iVar3 + 0x8a9) * 0xb0 + 0x88) & 1) != 0
       ) {
      if (FLOAT_803e8b88 <= *(float *)(iVar3 + 0x820)) {
        *param_2 = *param_2 | 0x80;
      }
    }
  }
  cVar1 = *(char *)(iVar3 + 0x8c1);
  if (cVar1 == '\0') {
    *param_2 = *param_2 | 0x100;
  }
  else if (cVar1 == '\x01') {
    *param_2 = *param_2 | 0x200;
  }
  else if (cVar1 == '\x02') {
    *param_2 = *param_2 | 0x400;
  }
  if ((*(short *)(iVar3 + 0x274) == 0x2e) || (*(short *)(iVar3 + 0x274) == 0x2f)) {
    *param_2 = *param_2 & 0x7d;
    *param_2 = *param_2 | 2;
  }
  *param_6 = 0x78;
  return;
}

