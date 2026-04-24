// Function: FUN_802bde54
// Entry: 802bde54
// Size: 60 bytes

void FUN_802bde54(int param_1,float *param_2,int *param_3)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *param_2 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar1 + 0x102c) ^ 0x80000000) -
                    DOUBLE_803e82e0);
  *param_3 = (int)*(short *)(iVar1 + 0x102e);
  return;
}

