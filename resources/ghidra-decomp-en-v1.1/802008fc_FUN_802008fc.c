// Function: FUN_802008fc
// Entry: 802008fc
// Size: 104 bytes

undefined4 FUN_802008fc(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,1);
    fVar1 = FLOAT_803e6f40;
    iVar2 = *(int *)(iVar2 + 0x40c);
    *(float *)(iVar2 + 0xc) = FLOAT_803e6f40;
    *(float *)(iVar2 + 0x10) = fVar1;
    *(float *)(iVar2 + 4) = fVar1;
  }
  return 0;
}

