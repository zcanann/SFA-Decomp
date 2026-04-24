// Function: FUN_801bc0f8
// Entry: 801bc0f8
// Size: 1940 bytes

/* WARNING: Removing unreachable block (ram,0x801bc86c) */
/* WARNING: Removing unreachable block (ram,0x801bc864) */
/* WARNING: Removing unreachable block (ram,0x801bc85c) */
/* WARNING: Removing unreachable block (ram,0x801bc118) */
/* WARNING: Removing unreachable block (ram,0x801bc110) */
/* WARNING: Removing unreachable block (ram,0x801bc108) */

void FUN_801bc0f8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 extraout_f1;
  double dVar6;
  double in_f29;
  double in_f30;
  double dVar7;
  double in_f31;
  double dVar8;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar9;
  float local_78;
  float local_74;
  float local_70;
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  uVar9 = FUN_80286840();
  uVar1 = (uint)((ulonglong)uVar9 >> 0x20);
  iVar4 = (int)uVar9;
  iVar5 = *(int *)(iVar4 + 0x40c);
  if ((*(int *)(iVar5 + 0xb0) == 0) ||
     (*(int *)(iVar5 + 0xb0) = *(int *)(iVar5 + 0xb0) + -1, 0 < *(int *)(iVar5 + 0xb0))) {
    if (*(char *)(iVar5 + 0xb6) < '\0') {
      uVar9 = FUN_80008cbc(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,
                           0xdb,0,param_13,param_14,param_15,param_16);
      FUN_80008cbc(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0xdc,0,param_13
                   ,param_14,param_15,param_16);
      FUN_8008999c(7,1,0);
      FUN_80089734((double)FLOAT_803e58e4,(double)FLOAT_803e58e8,(double)FLOAT_803e58ec,7);
      FUN_8008986c(7,0xa0,0xa0,0xff,0x7f,0x28);
      *(byte *)(iVar5 + 0xb6) = *(byte *)(iVar5 + 0xb6) & 0x7f;
    }
    if ((*(uint *)(iVar4 + 0x314) & 4) != 0) {
      *(uint *)(iVar4 + 0x314) = *(uint *)(iVar4 + 0x314) & 0xfffffffb;
      FUN_8000bb38(uVar1,(ushort)DAT_803266f8);
      DAT_803de800 = DAT_803de800 | 0x204;
      FUN_80014acc((double)FLOAT_803e5890);
    }
    if ((*(uint *)(iVar4 + 0x314) & 2) != 0) {
      *(uint *)(iVar4 + 0x314) = *(uint *)(iVar4 + 0x314) & 0xfffffffd;
      FUN_8000bb38(uVar1,(ushort)DAT_803266fc);
      DAT_803de800 = DAT_803de800 | 0x404;
      FUN_80014acc((double)FLOAT_803e5890);
    }
    if ((*(uint *)(iVar4 + 0x314) & 0x10) != 0) {
      *(uint *)(iVar4 + 0x314) = *(uint *)(iVar4 + 0x314) & 0xffffffef;
      FUN_8000bb38(uVar1,(ushort)DAT_80326700);
      DAT_803de800 = DAT_803de800 | 0x804;
      FUN_80014acc((double)FLOAT_803e5890);
    }
    if ((*(uint *)(iVar4 + 0x314) & 8) != 0) {
      *(uint *)(iVar4 + 0x314) = *(uint *)(iVar4 + 0x314) & 0xfffffff7;
      FUN_8000bb38(uVar1,(ushort)DAT_80326704);
      DAT_803de800 = DAT_803de800 | 0x1004;
      FUN_80014acc((double)FLOAT_803e5890);
    }
    if ((DAT_803de800 & 0x2000) != 0) {
      iVar3 = 0;
      do {
        (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b1,iVar5 + 0x4c,0x200001,0xffffffff,0);
        iVar3 = iVar3 + 1;
      } while (iVar3 < 0x32);
      (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b2,iVar5 + 0x4c,0x200001,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b3,iVar5 + 0x4c,0x200001,0xffffffff,0);
    }
    if ((DAT_803de800 & 0x80000) != 0) {
      (**(code **)(*DAT_803dd734 + 0xc))(uVar1,0x800,0,1,0);
    }
    if (((DAT_803de800 & 0x8020) != 0) || (*(char *)(iVar4 + 0x354) < '\x02')) {
      if ((DAT_803de800 & 0x20) == 0) {
        uVar2 = FUN_80022264(0,(int)*(char *)(iVar4 + 0x354));
        if ((uVar2 == 0) && (*(short *)(iVar4 + 0x402) == 2)) {
          (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b4,iVar5 + 0x34,0x200001,0xffffffff,0);
        }
      }
      else {
        iVar4 = 0;
        do {
          (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b4,iVar5 + 0x34,0x200001,0xffffffff,0);
          iVar4 = iVar4 + 1;
        } while (iVar4 < 7);
      }
      if ((DAT_803de800 & 0x8000) != 0) {
        (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b2,iVar5 + 0x34,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b3,iVar5 + 0x34,0x200001,0xffffffff,0);
      }
    }
    if ((DAT_803de800 & 0x101c0) != 0) {
      if ((DAT_803de800 & 0x40) != 0) {
        iVar4 = 0;
        dVar7 = (double)FLOAT_803e58f0;
        dVar8 = (double)FLOAT_803e58f4;
        dVar6 = DOUBLE_803e5878;
        do {
          uStack_64 = FUN_80022264(0xfffffffb,5);
          uStack_64 = uStack_64 ^ 0x80000000;
          local_68 = 0x43300000;
          local_78 = (float)(dVar7 * (double)(float)((double)CONCAT44(0x43300000,uStack_64) - dVar6)
                            );
          uStack_5c = FUN_80022264(0xfffffffb,5);
          uStack_5c = uStack_5c ^ 0x80000000;
          local_60 = 0x43300000;
          local_74 = (float)(dVar7 * (double)(float)((double)CONCAT44(0x43300000,uStack_5c) - dVar6)
                            );
          uStack_54 = FUN_80022264(2,8);
          uStack_54 = uStack_54 ^ 0x80000000;
          local_58 = 0x43300000;
          local_70 = (float)(dVar8 * (double)(float)((double)CONCAT44(0x43300000,uStack_54) - dVar6)
                            );
          FUN_80247bf8((float *)(iVar5 + 100),&local_78,&local_78);
          (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b5,iVar5 + 0x1c,0x200001,0xffffffff,&local_78);
          iVar4 = iVar4 + 1;
        } while (iVar4 < 5);
      }
      if ((DAT_803de800 & 0x80) != 0) {
        (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b5,iVar5 + 4,0x200001,0xffffffff,0);
      }
      if ((DAT_803de800 & 0x100) != 0) {
        local_78 = FLOAT_803e58f0;
        local_74 = FLOAT_803e58f8;
        uStack_54 = FUN_80022264(4,8);
        uStack_54 = uStack_54 ^ 0x80000000;
        local_58 = 0x43300000;
        local_70 = FLOAT_803e58fc *
                   (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e5878);
        FUN_80247bf8((float *)(iVar5 + 100),&local_78,&local_78);
        (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b6,iVar5 + 4,0x200001,0xffffffff,&local_78);
      }
      if ((DAT_803de800 & 0x10000) != 0) {
        local_78 = FLOAT_803e5870;
        local_74 = FLOAT_803e58f8;
        local_70 = FLOAT_803e5900;
        FUN_80247bf8((float *)(iVar5 + 100),&local_78,&local_78);
        FUN_80003494(iVar5 + 0x94,(uint)&local_78,0xc);
        DAT_803de800 = DAT_803de800 | 0x20000;
      }
    }
    if ((DAT_803de800 & 0x4000) != 0) {
      iVar4 = 0;
      do {
        (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b7,0,1,0xffffffff,0);
        iVar4 = iVar4 + 1;
      } while (iVar4 < 0x32);
    }
    if ((DAT_803de800 & 1) != 0) {
      FUN_8000faf8();
      FUN_80014acc((double)FLOAT_803e5890);
      FUN_8000e670((double)FLOAT_803e585c,(double)FLOAT_803e5860,(double)FLOAT_803e5864);
    }
    if ((DAT_803de800 & 0x40000) != 0) {
      FUN_8000faf8();
      FUN_80014acc((double)FLOAT_803e5904);
      FUN_8000e670((double)FLOAT_803e5860,(double)FLOAT_803e588c,(double)FLOAT_803e5890);
    }
    if ((DAT_803de800 & 2) != 0) {
      FUN_8000faf8();
      dVar6 = (double)FLOAT_803e5870;
      FUN_8000e670(dVar6,dVar6,dVar6);
      FUN_8000e69c((double)FLOAT_803e5870);
    }
    if ((DAT_803de800 & 4) == 0) {
      FUN_800201ac(0x25e,0);
    }
    else {
      FUN_800201ac(0x25e,1);
    }
    DAT_803de800 = DAT_803de800 & 0xa1ff0;
  }
  else {
    *(undefined4 *)(iVar5 + 0xb0) = 0;
    uVar9 = FUN_8012e0b8('\0');
    FUN_80055464(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x77,'\x01',param_11,
                 param_12,param_13,param_14,param_15,param_16);
  }
  FUN_8028688c();
  return;
}

