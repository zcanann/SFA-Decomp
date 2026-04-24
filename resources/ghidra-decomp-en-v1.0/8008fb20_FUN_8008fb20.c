// Function: FUN_8008fb20
// Entry: 8008fb20
// Size: 224 bytes

/* WARNING: Removing unreachable block (ram,0x8008fbd8) */
/* WARNING: Removing unreachable block (ram,0x8008fbe0) */

void FUN_8008fb20(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 undefined2 param_5,undefined param_6,undefined param_7)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  double extraout_f1;
  undefined8 in_f30;
  double dVar5;
  undefined8 in_f31;
  undefined8 uVar6;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar6 = FUN_802860dc();
  puVar1 = (undefined4 *)((ulonglong)uVar6 >> 0x20);
  puVar3 = (undefined4 *)uVar6;
  dVar5 = extraout_f1;
  puVar2 = (undefined4 *)FUN_80023cc8(0x28,0x17,0);
  if (puVar2 == (undefined4 *)0x0) {
    puVar2 = (undefined4 *)0x0;
  }
  else {
    *puVar2 = *puVar1;
    puVar2[1] = puVar1[1];
    puVar2[2] = puVar1[2];
    puVar2[3] = *puVar3;
    puVar2[4] = puVar3[1];
    puVar2[5] = puVar3[2];
    puVar2[6] = (float)dVar5;
    puVar2[7] = (float)param_2;
    *(undefined2 *)((int)puVar2 + 0x22) = param_5;
    *(undefined *)((int)puVar2 + 0x26) = param_6;
    *(undefined2 *)(puVar2 + 8) = 0;
    *(undefined2 *)(puVar2 + 9) = 0xffff;
    *(undefined *)((int)puVar2 + 0x27) = param_7;
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  FUN_80286128(puVar2);
  return;
}

