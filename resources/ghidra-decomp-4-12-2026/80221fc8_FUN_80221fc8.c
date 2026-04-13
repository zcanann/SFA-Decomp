// Function: FUN_80221fc8
// Entry: 80221fc8
// Size: 672 bytes

/* WARNING: Removing unreachable block (ram,0x80222248) */
/* WARNING: Removing unreachable block (ram,0x80221fd8) */

void FUN_80221fc8(undefined4 param_1,undefined4 param_2,int param_3,uint *param_4)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  uint *puVar4;
  int iVar5;
  double extraout_f1;
  double in_f31;
  double dVar6;
  double in_ps31_1;
  undefined8 uVar7;
  float local_58;
  float local_54;
  float local_50;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  longlong local_30;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar7 = FUN_8028683c();
  iVar3 = (int)((ulonglong)uVar7 >> 0x20);
  puVar4 = (uint *)uVar7;
  bVar1 = false;
  if ((double)FLOAT_803e78d0 == extraout_f1) {
    for (iVar3 = 0; iVar3 < param_3; iVar3 = iVar3 + 1) {
      if (*puVar4 != 0) {
        FUN_8008ff08(*puVar4);
        *puVar4 = 0;
      }
      puVar4 = puVar4 + 1;
    }
    if (*param_4 != 0) {
      FUN_8001cc00(param_4);
    }
  }
  else {
    dVar6 = extraout_f1;
    for (iVar5 = 0; iVar5 < param_3; iVar5 = iVar5 + 1) {
      if ((float *)*puVar4 == (float *)0x0) {
        if (!bVar1) {
          local_58 = *(float *)(iVar3 + 0xc);
          local_54 = *(float *)(iVar3 + 0x10);
          local_50 = *(float *)(iVar3 + 0x14);
          uVar2 = FUN_80022264(0,2000);
          uStack_44 = uVar2 - 1000 ^ 0x80000000;
          local_48 = 0x43300000;
          local_58 = FLOAT_803e78d4 *
                     (float)(dVar6 * (double)(float)((double)CONCAT44(0x43300000,uStack_44) -
                                                    DOUBLE_803e78e8)) + local_58;
          uVar2 = FUN_80022264(0,2000);
          uStack_3c = uVar2 - 1000 ^ 0x80000000;
          local_40 = 0x43300000;
          local_54 = FLOAT_803e78d4 *
                     (float)(dVar6 * (double)(float)((double)CONCAT44(0x43300000,uStack_3c) -
                                                    DOUBLE_803e78e8)) + local_54;
          uVar2 = FUN_80022264(0,2000);
          uStack_34 = uVar2 - 1000 ^ 0x80000000;
          local_38 = 0x43300000;
          local_50 = FLOAT_803e78d4 *
                     (float)(dVar6 * (double)(float)((double)CONCAT44(0x43300000,uStack_34) -
                                                    DOUBLE_803e78e8)) + local_50;
          local_30 = (longlong)(int)FLOAT_803dd010;
          uVar2 = FUN_8008fdac((double)FLOAT_803dd008,(double)FLOAT_803dd00c,iVar3 + 0xc,&local_58,
                               (short)(int)FLOAT_803dd010,(char)DAT_803dd014,0);
          *puVar4 = uVar2;
          bVar1 = true;
        }
      }
      else {
        FUN_8008fb90((float *)*puVar4);
        *(ushort *)(*puVar4 + 0x20) = *(short *)(*puVar4 + 0x20) + (ushort)DAT_803dc070;
        uStack_44 = (uint)*(ushort *)(*puVar4 + 0x20);
        local_48 = 0x43300000;
        if (FLOAT_803dd010 < (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e78e0)) {
          FUN_8008ff08(*puVar4);
          *puVar4 = 0;
        }
      }
      puVar4 = puVar4 + 1;
    }
    if (*param_4 == 0) {
      uVar2 = FUN_8001cd60(iVar3,0x80,0x80,0xff,0);
      *param_4 = uVar2;
      if ((int *)*param_4 != (int *)0x0) {
        FUN_8001de4c((double)FLOAT_803e78d0,(double)(float)(dVar6 * (double)FLOAT_803e78d8),
                     (double)FLOAT_803e78d0,(int *)*param_4);
        FUN_8001dcfc(dVar6,(double)(float)((double)FLOAT_803e78dc + dVar6),*param_4);
      }
    }
  }
  FUN_80286888();
  return;
}

