// Function: FUN_802aa2b0
// Entry: 802aa2b0
// Size: 512 bytes

/* WARNING: Removing unreachable block (ram,0x802aa488) */
/* WARNING: Removing unreachable block (ram,0x802aa480) */
/* WARNING: Removing unreachable block (ram,0x802aa490) */

void FUN_802aa2b0(undefined8 param_1,double param_2)

{
  char cVar5;
  int iVar1;
  undefined2 *puVar2;
  undefined2 uVar3;
  short sVar4;
  undefined4 uVar6;
  double dVar7;
  undefined8 uVar8;
  undefined8 in_f29;
  double dVar9;
  undefined8 in_f30;
  double dVar10;
  undefined8 in_f31;
  double dVar11;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44 [3];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  FUN_8000faac();
  cVar5 = FUN_8002e04c();
  if (cVar5 != '\0') {
    FUN_8000bb18(0,0x20b);
    iVar1 = FUN_8002bdf4(0x24,0x655);
    *(undefined *)(iVar1 + 4) = 2;
    *(undefined *)(iVar1 + 5) = 1;
    *(undefined *)(iVar1 + 6) = 0xff;
    *(undefined *)(iVar1 + 7) = 0xff;
    FUN_8003842c(DAT_803de44c,0,&local_50,&local_54,&local_58,0);
    *(float *)(iVar1 + 8) = (float)((double)local_50 + param_2);
    *(float *)(iVar1 + 0xc) = (float)((double)local_54 + param_2);
    *(float *)(iVar1 + 0x10) = (float)((double)local_58 + param_2);
    puVar2 = (undefined2 *)FUN_8002df90(iVar1,5,0xffffffff,0xffffffff,0);
    if (puVar2 != (undefined2 *)0x0) {
      FUN_8003842c(DAT_803de44c,0,&local_50,&local_54,&local_58,0);
      FUN_8003842c(DAT_803de44c,1,local_44,&local_48,&local_4c,0);
      dVar11 = (double)(local_50 - local_44[0]);
      dVar10 = (double)(local_54 - local_48);
      dVar9 = (double)(local_58 - local_4c);
      dVar7 = (double)FUN_802931a0((double)(float)(dVar9 * dVar9 +
                                                  (double)(float)(dVar11 * dVar11 +
                                                                 (double)(float)(dVar10 * dVar10))))
      ;
      dVar11 = (double)(float)(dVar11 / dVar7);
      dVar10 = (double)(float)(dVar10 / dVar7);
      dVar7 = (double)(float)(dVar9 / dVar7);
      uVar3 = FUN_800217c0(dVar11,dVar7);
      *puVar2 = uVar3;
      uVar8 = FUN_802931a0((double)(float)(dVar11 * dVar11 + (double)(float)(dVar7 * dVar7)));
      sVar4 = FUN_800217c0(dVar10,uVar8);
      puVar2[1] = -sVar4;
      *(float *)(puVar2 + 4) = *(float *)(puVar2 + 4) * FLOAT_803e7ef0;
      FUN_8022e54c((double)FLOAT_803e7ed8,puVar2);
      FUN_8022e600(puVar2,0x32);
      FUN_8022e418(puVar2,1);
    }
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  __psq_l0(auStack40,uVar6);
  __psq_l1(auStack40,uVar6);
  return;
}

