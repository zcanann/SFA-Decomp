// Function: FUN_80226a98
// Entry: 80226a98
// Size: 236 bytes

/* WARNING: Removing unreachable block (ram,0x80226b5c) */
/* WARNING: Removing unreachable block (ram,0x80226b64) */

void FUN_80226a98(double param_1,double param_2,int param_3,short *param_4,short *param_5)

{
  int iVar1;
  undefined4 uVar2;
  undefined8 in_f30;
  undefined8 in_f31;
  float local_48;
  float local_44 [7];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  FUN_8005b0a8((double)*(float *)(param_3 + 0xc),(double)*(float *)(param_3 + 0x10),
               (double)*(float *)(param_3 + 0x14),local_44,&local_48);
  iVar1 = (int)(short)(int)((float)(param_1 - (double)local_44[0]) - FLOAT_803e6dd0);
  iVar1 = iVar1 / 0x30 + (iVar1 >> 0x1f);
  *param_4 = (short)iVar1 - (short)(iVar1 >> 0x1f);
  iVar1 = (int)(short)(int)((float)(param_2 - (double)local_48) - FLOAT_803e6dd4);
  iVar1 = iVar1 / 0x30 + (iVar1 >> 0x1f);
  *param_5 = (short)iVar1 - (short)(iVar1 >> 0x1f);
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  __psq_l0(auStack24,uVar2);
  __psq_l1(auStack24,uVar2);
  return;
}

