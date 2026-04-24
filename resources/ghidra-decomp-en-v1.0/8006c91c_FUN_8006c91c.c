// Function: FUN_8006c91c
// Entry: 8006c91c
// Size: 416 bytes

/* WARNING: Removing unreachable block (ram,0x8006caa4) */

void FUN_8006c91c(void)

{
  uint uVar1;
  int iVar2;
  char cVar3;
  undefined4 uVar4;
  double dVar5;
  undefined8 in_f31;
  double dVar6;
  float local_28;
  float local_24;
  double local_20;
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar2 = FUN_8002073c();
  if (iVar2 == 0) {
    FLOAT_803dcfac = FLOAT_803ded94 * FLOAT_803db414 + FLOAT_803dcfac;
    FLOAT_803dcfa8 = FLOAT_803ded98 * FLOAT_803db414 + FLOAT_803dcfa8;
    if (FLOAT_803ded9c < FLOAT_803dcfac) {
      FLOAT_803dcfac = FLOAT_803dcfac - FLOAT_803ded9c;
    }
    if (FLOAT_803ded9c < FLOAT_803dcfa8) {
      FLOAT_803dcfa8 = FLOAT_803dcfa8 - FLOAT_803ded9c;
    }
  }
  DAT_803dcf78 = 0;
  DAT_803dcfe8 = FUN_8000faac();
  uVar1 = (uint)DAT_803dcfa0 + (uint)DAT_803db410 * 0x28a & 0xffff;
  DAT_803dcfa0 = (ushort)uVar1;
  local_20 = (double)CONCAT44(0x43300000,uVar1);
  dVar5 = (double)FUN_80294098((double)((FLOAT_803deda4 * (float)(local_20 - DOUBLE_803ded88)) /
                                       FLOAT_803deda8));
  FLOAT_803dcfa4 = (float)((double)FLOAT_803deda0 * dVar5);
  FUN_80060bb0();
  DAT_803dcf8c = (char)(DAT_803dcf8c + 1) + (char)((DAT_803dcf8c + 1) / 3) * -3;
  cVar3 = FUN_8004c248();
  if (cVar3 != '\0') {
    iVar2 = FUN_8000f558();
    dVar6 = (double)*(float *)(iVar2 + 0x1c);
    FUN_8004c234(&local_24,&local_28);
    dVar5 = (double)local_24;
    if (dVar6 < dVar5) {
      if ((double)local_28 < dVar6) {
        uVar1 = (uint)((FLOAT_803ded1c * (float)(dVar5 - dVar6)) / (float)(dVar5 - (double)local_28)
                      );
        local_20 = (double)(longlong)(int)uVar1;
      }
      else {
        uVar1 = 0x40;
      }
    }
    else {
      uVar1 = 0;
    }
    if ((uVar1 & 0xff) != (uint)DAT_803dcf80) {
      FUN_80069eb8();
    }
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  return;
}

