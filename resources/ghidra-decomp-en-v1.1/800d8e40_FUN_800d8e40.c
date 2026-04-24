// Function: FUN_800d8e40
// Entry: 800d8e40
// Size: 168 bytes

/* WARNING: Removing unreachable block (ram,0x800d8ec8) */
/* WARNING: Removing unreachable block (ram,0x800d8e50) */

void FUN_800d8e40(double param_1,int param_2,uint *param_3)

{
  int iVar1;
  
  if (param_3[0xcf] == 0xffffffff) {
    param_3[0xaf] = (uint)FLOAT_803e11f0;
  }
  else {
    iVar1 = (**(code **)(*DAT_803dd71c + 0x1c))();
    if (iVar1 == 0) {
      param_3[0xaf] = (uint)FLOAT_803e11f0;
    }
    else {
      FUN_800d83f8((double)*(float *)(iVar1 + 8),(double)*(float *)(iVar1 + 0x10),param_1,param_2,
                   param_3);
    }
  }
  return;
}

