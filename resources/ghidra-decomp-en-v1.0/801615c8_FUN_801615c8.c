// Function: FUN_801615c8
// Entry: 801615c8
// Size: 228 bytes

bool FUN_801615c8(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(undefined *)(param_2 + 0x34d) = 0;
  *(float *)(param_2 + 0x2a0) = FLOAT_803e2ee0;
  fVar1 = FLOAT_803e2eb8;
  *(float *)(param_2 + 0x280) = FLOAT_803e2eb8;
  *(float *)(param_2 + 0x284) = fVar1;
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_8000bb18(param_1,0x27c);
    if (*(char *)(param_2 + 0x27a) != '\0') {
      FUN_80030334((double)FLOAT_803e2eb8,param_1,2,0);
      *(undefined *)(param_2 + 0x346) = 0;
    }
    *(float *)(param_2 + 0x2a0) = FLOAT_803e2ee4;
    *(undefined *)(param_2 + 0x346) = 0;
    *(undefined *)(param_1 + 0x36) = 0xff;
    *(ushort *)(iVar2 + 0x400) = *(ushort *)(iVar2 + 0x400) | 0x100;
  }
  return *(char *)(param_2 + 0x346) != '\0';
}

