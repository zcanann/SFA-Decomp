// Function: FUN_80216b48
// Entry: 80216b48
// Size: 336 bytes

/* WARNING: Removing unreachable block (ram,0x80216c74) */
/* WARNING: Removing unreachable block (ram,0x80216b58) */

void FUN_80216b48(double param_1,ushort *param_2,uint param_3)

{
  undefined4 uVar1;
  int iVar2;
  float local_48;
  float local_44;
  float local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  
  iVar2 = *(int *)(param_2 + 0x5c);
  if (*(uint *)(iVar2 + 0x10) != 0) {
    FUN_800238c4(*(uint *)(iVar2 + 0x10));
    *(undefined4 *)(iVar2 + 0x10) = 0;
  }
  local_3c = *(undefined4 *)(param_2 + 6);
  local_38 = *(undefined4 *)(param_2 + 8);
  local_34 = *(undefined4 *)(param_2 + 10);
  local_48 = FLOAT_803e7530;
  uStack_2c = param_3 ^ 0x80000000;
  local_30 = 0x43300000;
  local_44 = -((float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e7540) *
               *(float *)(iVar2 + 0xc) * FLOAT_803e7534);
  local_40 = (float)param_1;
  FUN_80021b8c(param_2,&local_48);
  local_48 = local_48 + *(float *)(param_2 + 6);
  local_44 = local_44 + *(float *)(param_2 + 8);
  local_40 = local_40 + *(float *)(param_2 + 10);
  uStack_24 = FUN_80022264(10,param_3);
  uStack_24 = uStack_24 ^ 0x80000000;
  local_28 = 0x43300000;
  *(float *)(iVar2 + 8) = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e7540);
  uVar1 = FUN_8008fdac((double)FLOAT_803e7538,(double)FLOAT_803e753c,&local_3c,&local_48,
                       (short)param_3,0x60,0);
  *(undefined4 *)(iVar2 + 0x10) = uVar1;
  return;
}

