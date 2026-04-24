// Function: FUN_801b25a8
// Entry: 801b25a8
// Size: 592 bytes

/* WARNING: Removing unreachable block (ram,0x801b27d8) */
/* WARNING: Removing unreachable block (ram,0x801b27d0) */
/* WARNING: Removing unreachable block (ram,0x801b25c0) */
/* WARNING: Removing unreachable block (ram,0x801b25b8) */

void FUN_801b25a8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  short *psVar1;
  uint uVar2;
  int iVar3;
  undefined2 *puVar4;
  short *psVar5;
  undefined4 *puVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar9;
  int iVar10;
  undefined8 extraout_f1;
  undefined8 uVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  ulonglong uVar15;
  
  uVar15 = FUN_8028683c();
  psVar1 = (short *)(uVar15 >> 0x20);
  iVar10 = *(int *)(psVar1 + 0x26);
  uVar11 = extraout_f1;
  uVar2 = FUN_8002e144();
  if ((((uVar2 & 0xff) != 0) && (iVar9 = *(int *)(psVar1 + 0x5c), *(char *)(iVar9 + 0xad) != '\0'))
     && (*(short *)(iVar9 + 0xa4) < 1)) {
    iVar3 = FUN_800396d0((int)psVar1,0);
    puVar4 = FUN_8002becc(0x24,0x1d6);
    *(undefined *)(puVar4 + 2) = *(undefined *)(iVar10 + 4);
    *(undefined *)(puVar4 + 3) = *(undefined *)(iVar10 + 6);
    *(undefined *)((int)puVar4 + 5) = *(undefined *)(iVar10 + 5);
    *(undefined *)((int)puVar4 + 7) = *(undefined *)(iVar10 + 7);
    *(undefined4 *)(puVar4 + 4) = *(undefined4 *)(iVar9 + 0x8c);
    *(undefined4 *)(puVar4 + 6) = *(undefined4 *)(iVar9 + 0x90);
    *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(iVar9 + 0x94);
    uVar7 = 0xffffffff;
    uVar8 = 0;
    psVar5 = (short *)FUN_8002e088(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                   puVar4,5,*(undefined *)(psVar1 + 0x56),0xffffffff,(uint *)0x0,
                                   in_r8,in_r9,in_r10);
    puVar6 = *(undefined4 **)(psVar5 + 0x5c);
    *puVar6 = psVar1;
    *(char *)(puVar6 + 1) = (char)uVar15;
    if ((uVar15 & 0xff) == 0) {
      *(undefined *)((int)puVar6 + 5) = 0x14;
      *(undefined *)((int)puVar6 + 6) = 1;
    }
    else {
      if (*(char *)(psVar1 + 0x56) == '\x1b') {
        *(undefined *)((int)puVar6 + 5) = 100;
      }
      else {
        *(undefined *)((int)puVar6 + 5) = 0x3c;
      }
      *(undefined *)((int)puVar6 + 6) = 100;
    }
    dVar14 = (double)*(float *)(iVar9 + 0x98);
    dVar13 = (double)(float)((double)FLOAT_803e5544 * dVar14);
    *psVar5 = *psVar1 + *(short *)(iVar3 + 2);
    dVar12 = (double)FUN_802945e0();
    *(float *)(psVar5 + 0x12) = (float)(dVar13 * -dVar12);
    *(float *)(psVar5 + 0x14) = (float)dVar14;
    dVar14 = (double)FLOAT_803e5548;
    dVar12 = (double)FUN_80294964();
    *(float *)(psVar5 + 0x16) = (float)(dVar13 * -dVar12);
    *(undefined *)(iVar9 + 0xad) = 0;
    *(undefined2 *)(iVar9 + 0xa6) = 0x32;
    if (*(char *)(iVar9 + 0xac) == '\x03') {
      *(undefined2 *)(iVar9 + 0xa4) = 0x32;
    }
    else {
      uVar2 = FUN_80022264((uint)*(byte *)(iVar10 + 0x29),(uint)*(byte *)(iVar10 + 0x2a));
      *(short *)(iVar9 + 0xa4) = (short)(uVar2 << 2);
    }
    FUN_8003042c((double)FLOAT_803e5550,dVar14,param_3,param_4,param_5,param_6,param_7,param_8,
                 psVar1,0,0,uVar7,uVar8,in_r8,in_r9,in_r10);
    FUN_8000bb38((uint)psVar1,0x1fd);
  }
  FUN_80286888();
  return;
}

