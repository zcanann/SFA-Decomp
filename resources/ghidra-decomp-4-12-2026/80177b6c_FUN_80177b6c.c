// Function: FUN_80177b6c
// Entry: 80177b6c
// Size: 220 bytes

void FUN_80177b6c(short *param_1,int param_2)

{
  undefined2 *puVar1;
  
  puVar1 = *(undefined2 **)(param_1 + 0x5c);
  *(code **)(param_1 + 0x5e) = FUN_80177470;
  *param_1 = (ushort)*(byte *)(param_2 + 0x18) << 8;
  *puVar1 = 0x1e;
  *(float *)(puVar1 + 4) =
       (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x1e) << 2 ^ 0x80000000) -
              DOUBLE_803e4278);
  puVar1[1] = *(undefined2 *)(param_2 + 0x20);
  puVar1[2] = (short)*(char *)(param_2 + 0x1b);
  if (*(char *)(param_2 + 0x1c) == '\0') {
    *(undefined *)(puVar1 + 6) = 1;
  }
  else {
    *(undefined *)(puVar1 + 6) = 0;
  }
  if (*(char *)(param_2 + 0x1d) == '\x02') {
    *puVar1 = 0;
  }
  if ((*(int *)(param_2 + 0x14) == 0x4b675) || (*(int *)(param_2 + 0x14) == 0x46882)) {
    *(undefined *)(param_2 + 0x1f) = 1;
  }
  else {
    *(undefined *)(param_2 + 0x1f) = 0;
  }
  return;
}

