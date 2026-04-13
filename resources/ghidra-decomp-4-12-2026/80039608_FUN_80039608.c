// Function: FUN_80039608
// Entry: 80039608
// Size: 200 bytes

void FUN_80039608(int param_1,uint param_2,float *param_3)

{
  uint uVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  uint unaff_r31;
  
  iVar3 = *(int *)(param_1 + 0x50);
  iVar4 = 0;
  uVar1 = (uint)*(byte *)(iVar3 + 0x5a);
  do {
    if (uVar1 == 0) {
LAB_80039674:
      piVar2 = (int *)FUN_8002b660(param_1);
      iVar4 = FUN_80028630(piVar2,unaff_r31);
      *param_3 = *(float *)(iVar4 + 0xc);
      param_3[1] = *(float *)(iVar4 + 0x1c);
      param_3[2] = *(float *)(iVar4 + 0x2c);
      *param_3 = *param_3 + FLOAT_803dda58;
      param_3[2] = param_3[2] + FLOAT_803dda5c;
      return;
    }
    if (param_2 == *(byte *)(*(int *)(iVar3 + 0x10) + iVar4)) {
      unaff_r31 = (uint)*(byte *)(*(int *)(iVar3 + 0x10) + iVar4 + (int)*(char *)(param_1 + 0xad) +
                                 1);
      goto LAB_80039674;
    }
    iVar4 = *(char *)(iVar3 + 0x55) + iVar4 + 1;
    uVar1 = uVar1 - 1;
  } while( true );
}

