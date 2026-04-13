// Function: FUN_802aaa10
// Entry: 802aaa10
// Size: 512 bytes

/* WARNING: Removing unreachable block (ram,0x802aabf0) */
/* WARNING: Removing unreachable block (ram,0x802aabe8) */
/* WARNING: Removing unreachable block (ram,0x802aabe0) */
/* WARNING: Removing unreachable block (ram,0x802aaa30) */
/* WARNING: Removing unreachable block (ram,0x802aaa28) */
/* WARNING: Removing unreachable block (ram,0x802aaa20) */

void FUN_802aaa10(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  undefined2 *puVar2;
  ushort *puVar3;
  int iVar4;
  undefined4 uVar5;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44 [3];
  
  dVar7 = param_2;
  FUN_8000facc();
  uVar1 = FUN_8002e144();
  if ((uVar1 & 0xff) != 0) {
    FUN_8000bb38(0,0x20b);
    puVar2 = FUN_8002becc(0x24,0x655);
    *(undefined *)(puVar2 + 2) = 2;
    *(undefined *)((int)puVar2 + 5) = 1;
    *(undefined *)(puVar2 + 3) = 0xff;
    *(undefined *)((int)puVar2 + 7) = 0xff;
    uVar5 = 0;
    uVar6 = FUN_80038524(DAT_803df0cc,0,&local_50,&local_54,&local_58,0);
    *(float *)(puVar2 + 4) = (float)((double)local_50 + dVar7);
    *(float *)(puVar2 + 6) = (float)((double)local_54 + dVar7);
    *(float *)(puVar2 + 8) = (float)((double)local_58 + dVar7);
    puVar3 = (ushort *)
             FUN_8002e088(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,
                          0xff,0xffffffff,(uint *)0x0,uVar5,in_r9,in_r10);
    if (puVar3 != (ushort *)0x0) {
      FUN_80038524(DAT_803df0cc,0,&local_50,&local_54,&local_58,0);
      FUN_80038524(DAT_803df0cc,1,local_44,&local_48,&local_4c,0);
      dVar9 = (double)(local_50 - local_44[0]);
      dVar8 = (double)(local_58 - local_4c);
      dVar7 = FUN_80293900((double)(float)(dVar8 * dVar8 +
                                          (double)(float)(dVar9 * dVar9 +
                                                         (double)((local_54 - local_48) *
                                                                 (local_54 - local_48)))));
      dVar9 = (double)(float)(dVar9 / dVar7);
      dVar7 = (double)(float)(dVar8 / dVar7);
      iVar4 = FUN_80021884();
      *puVar3 = (ushort)iVar4;
      FUN_80293900((double)(float)(dVar9 * dVar9 + (double)(float)(dVar7 * dVar7)));
      iVar4 = FUN_80021884();
      puVar3[1] = -(short)iVar4;
      *(float *)(puVar3 + 4) = *(float *)(puVar3 + 4) * FLOAT_803e8b88;
      FUN_8022ec10((double)FLOAT_803e8b70,puVar3);
      FUN_8022ecc4((int)puVar3,0x32);
      FUN_8022eadc((int)puVar3,'\x01');
    }
  }
  return;
}

