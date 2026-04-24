// Function: FUN_8009adfc
// Entry: 8009adfc
// Size: 468 bytes

/* WARNING: Removing unreachable block (ram,0x8009afb0) */
/* WARNING: Removing unreachable block (ram,0x8009ae0c) */

void FUN_8009adfc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,uint param_12,uint param_13,
                 uint param_14,uint param_15,undefined4 param_16)

{
  int iVar1;
  uint uVar2;
  undefined2 *puVar3;
  int iVar4;
  undefined extraout_r4;
  uint uVar5;
  uint uVar6;
  undefined4 uVar7;
  double extraout_f1;
  double dVar8;
  double dVar9;
  
  iVar1 = FUN_80286830();
  uVar5 = param_14;
  uVar6 = param_15;
  uVar7 = param_16;
  dVar8 = extraout_f1;
  dVar9 = extraout_f1;
  uVar2 = FUN_8002e144();
  if ((uVar2 & 0xff) != 0) {
    puVar3 = FUN_8002becc(0x24,0x253);
    *(undefined *)(puVar3 + 2) = 2;
    *(undefined *)((int)puVar3 + 5) = 1;
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(iVar1 + 0x18);
    *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(iVar1 + 0x1c);
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(iVar1 + 0x20);
    *(undefined *)((int)puVar3 + 0x19) = extraout_r4;
    puVar3[0xd] = (short)(int)((double)FLOAT_803e002c * dVar9);
    puVar3[0xe] = (ushort)param_16 & 0xff;
    if ((param_11 & 0xff) != 0) {
      puVar3[0xe] = puVar3[0xe] | 4;
    }
    if ((param_12 & 0xff) != 0) {
      puVar3[0xe] = puVar3[0xe] | 8;
    }
    if ((param_13 & 0xff) != 0) {
      puVar3[0xe] = puVar3[0xe] | 0x10;
    }
    if ((param_15 & 0xff) != 0) {
      puVar3[0xe] = puVar3[0xe] | 0x20;
    }
    if ((((param_14 & 0xff) != 0) && (iVar4 = FUN_8002bac4(), iVar4 != 0)) &&
       ((*(ushort *)(iVar4 + 0xb0) & 0x1000) == 0)) {
      param_2 = (double)*(float *)(iVar1 + 0x1c);
      param_3 = (double)*(float *)(iVar1 + 0x20);
      dVar8 = (double)FUN_8000f4a0((double)*(float *)(iVar1 + 0x18),param_2,param_3);
      if (dVar8 <= (double)FLOAT_803e0030) {
        dVar8 = (double)(FLOAT_803dffd4 - (float)(dVar8 / (double)FLOAT_803e0030));
        param_2 = (double)(float)((double)FLOAT_803e0004 * dVar8);
        param_3 = (double)FLOAT_803e0024;
        FUN_8000e670((double)(float)((double)FLOAT_803e0020 * dVar8),param_2,param_3);
        dVar8 = (double)FUN_80014acc((double)(float)((double)FLOAT_803e0028 * dVar8));
      }
    }
    FUN_8002e088(dVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,
                 *(undefined *)(iVar1 + 0xac),0xffffffff,(uint *)0x0,uVar5,uVar6,uVar7);
  }
  FUN_8028687c();
  return;
}

