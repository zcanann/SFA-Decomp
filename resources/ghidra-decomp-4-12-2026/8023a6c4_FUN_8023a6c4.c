// Function: FUN_8023a6c4
// Entry: 8023a6c4
// Size: 412 bytes

/* WARNING: Removing unreachable block (ram,0x8023a840) */
/* WARNING: Removing unreachable block (ram,0x8023a6d4) */

void FUN_8023a6c4(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  short *psVar2;
  uint uVar3;
  undefined2 *puVar4;
  ushort *puVar5;
  int *piVar6;
  int iVar7;
  double dVar8;
  double dVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_8028683c();
  psVar2 = (short *)((ulonglong)uVar10 >> 0x20);
  piVar6 = (int *)uVar10;
  uVar3 = FUN_8002e144();
  if ((uVar3 & 0xff) != 0) {
    iVar7 = (int)DAT_803dea44;
    DAT_803dea40 = (int)DAT_803dea46;
    FUN_80022264(0xffff8000,0x7fff);
    uVar3 = FUN_80022264(100,300);
    puVar4 = FUN_8002becc(0x20,0x859);
    dVar8 = (double)FUN_802945e0();
    *(float *)(puVar4 + 4) =
         (float)((double)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e8130)
                 * dVar8 + (double)*(float *)(*piVar6 + 0xc));
    dVar8 = (double)FUN_80294964();
    dVar9 = (double)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e8130);
    *(float *)(puVar4 + 6) = (float)(dVar9 * dVar8 + (double)*(float *)(*piVar6 + 0x10));
    fVar1 = (float)piVar6[0x32];
    *(float *)(puVar4 + 8) = (float)((double)fVar1 - (double)FLOAT_803e8140);
    *(char *)(puVar4 + 0xd) = (char)((uint)(*psVar2 + iVar7) >> 8);
    *(char *)((int)puVar4 + 0x19) = (char)DAT_803dea40;
    *(undefined *)(puVar4 + 0xc) = 0;
    *(undefined *)(puVar4 + 2) = 1;
    *(undefined *)((int)puVar4 + 5) = 1;
    puVar5 = (ushort *)
             FUN_8002b678((double)fVar1,dVar9,param_3,param_4,param_5,param_6,param_7,param_8,
                          (int)psVar2,puVar4);
    if (puVar5 != (ushort *)0x0) {
      *(float *)(puVar5 + 4) = FLOAT_803dd14c;
      FUN_8022ecc4((int)puVar5,DAT_803dd148);
      FUN_8022ec10((double)FLOAT_803e8144,puVar5);
    }
  }
  FUN_80286888();
  return;
}

