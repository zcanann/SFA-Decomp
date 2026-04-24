// Function: FUN_80209a78
// Entry: 80209a78
// Size: 888 bytes

/* WARNING: Removing unreachable block (ram,0x80209dc0) */
/* WARNING: Removing unreachable block (ram,0x80209dc8) */

void FUN_80209a78(int param_1)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  undefined4 uVar4;
  double dVar5;
  undefined8 in_f30;
  double dVar6;
  undefined8 in_f31;
  double dVar7;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  undefined4 local_58;
  float local_54;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  if (param_1 != 0) {
    piVar3 = *(int **)(param_1 + 0xb8);
    iVar1 = FUN_8002b9ec();
    if (iVar1 != 0) {
      piVar3[1] = (int)((float)piVar3[1] + FLOAT_803db414);
      iVar2 = FUN_8001ffb4(piVar3[6]);
      if ((iVar2 != 0) && ((float)piVar3[1] < FLOAT_803e64e0)) {
        piVar3[1] = (int)FLOAT_803e64f8;
      }
      if (((float)piVar3[2] < (float)piVar3[1]) && ((float)piVar3[1] < FLOAT_803e64e0)) {
        local_5c = *(float *)(param_1 + 0xc);
        local_58 = *(undefined4 *)(param_1 + 0x10);
        local_54 = *(float *)(param_1 + 0x14);
        if (iVar2 == 0) {
          uStack60 = FUN_800221a0(0xffffff38,200);
          uStack60 = uStack60 ^ 0x80000000;
          local_40 = 0x43300000;
          local_68 = FLOAT_803e64fc *
                     (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e64f0) + local_5c;
          uStack68 = FUN_800221a0(100,300);
          uStack68 = uStack68 ^ 0x80000000;
          local_48 = 0x43300000;
          local_64 = FLOAT_803e64fc *
                     (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e64f0) +
                     *(float *)(param_1 + 0x10);
          uStack76 = FUN_800221a0(0xffffff38,200);
          uStack76 = uStack76 ^ 0x80000000;
          local_50 = 0x43300000;
          local_60 = FLOAT_803e64fc *
                     (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e64f0) + local_54;
        }
        else {
          uStack76 = FUN_800221a0(0xffffff38,200);
          uStack76 = uStack76 ^ 0x80000000;
          local_50 = 0x43300000;
          local_68 = FLOAT_803e64fc *
                     (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e64f0) +
                     *(float *)(iVar1 + 0xc);
          uStack68 = FUN_800221a0(100,300);
          uStack68 = uStack68 ^ 0x80000000;
          local_48 = 0x43300000;
          local_64 = FLOAT_803e64fc *
                     (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e64f0) +
                     *(float *)(iVar1 + 0x10);
          uStack60 = FUN_800221a0(0xffffff38,200);
          uStack60 = uStack60 ^ 0x80000000;
          local_40 = 0x43300000;
          local_60 = FLOAT_803e64fc *
                     (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e64f0) +
                     *(float *)(iVar1 + 0x14);
        }
        if (*piVar3 != 0) {
          FUN_80023800();
          *piVar3 = 0;
        }
        dVar7 = (double)(float)piVar3[3];
        dVar6 = (double)(float)piVar3[4];
        iVar1 = FUN_8001ffb4(0xe57);
        if (iVar1 == 0) {
          FUN_8000b4d0(param_1,0x4c3,2);
          if (iVar2 == 0) {
            dVar5 = (double)FLOAT_803e6500;
            if ((dVar5 <= dVar6) && (dVar5 = dVar6, (double)FLOAT_803e6504 < dVar6)) {
              dVar5 = (double)FLOAT_803e6504;
            }
            dVar6 = (double)FLOAT_803e6500;
            if ((dVar6 <= dVar7) && (dVar6 = dVar7, (double)FLOAT_803e6504 < dVar7)) {
              dVar6 = (double)FLOAT_803e6504;
            }
            iVar1 = FUN_8008fb20(dVar6,dVar5,&local_5c,&local_68,*(undefined2 *)((int)piVar3 + 0x16)
                                 ,*(short *)(piVar3 + 5) * 0xc & 0xff,0);
            *piVar3 = iVar1;
          }
          else {
            dVar5 = (double)FLOAT_803e6500;
            if ((dVar5 <= dVar6) && (dVar5 = dVar6, (double)FLOAT_803e6504 < dVar6)) {
              dVar5 = (double)FLOAT_803e6504;
            }
            dVar6 = (double)FLOAT_803e6500;
            if ((dVar6 <= dVar7) && (dVar6 = dVar7, (double)FLOAT_803e6504 < dVar7)) {
              dVar6 = (double)FLOAT_803e6504;
            }
            iVar1 = FUN_8008fb20(dVar6,dVar5,&local_5c,&local_68,10,
                                 *(short *)(piVar3 + 5) * 0xc & 0xff,0);
            *piVar3 = iVar1;
          }
        }
        piVar3[1] = (int)FLOAT_803e64e0;
      }
    }
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  return;
}

