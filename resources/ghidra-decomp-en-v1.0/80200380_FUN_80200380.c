// Function: FUN_80200380
// Entry: 80200380
// Size: 144 bytes

undefined4 FUN_80200380(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  
  fVar1 = FLOAT_803e62a8;
  if (*(char *)(param_2 + 0x27b) == '\0') {
    if (((*(char *)(param_2 + 0x346) != '\0') && (*(char *)(param_1 + 0x36) == '\0')) &&
       (*(char *)(param_2 + 0x346) != '\0')) {
      return 7;
    }
  }
  else {
    iVar2 = *(int *)(*(int *)(param_1 + 0xb8) + 0x40c);
    *(float *)(iVar2 + 0xc) = FLOAT_803e62a8;
    *(float *)(iVar2 + 0x10) = fVar1;
    *(float *)(iVar2 + 4) = fVar1;
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,6);
  }
  return 0;
}

