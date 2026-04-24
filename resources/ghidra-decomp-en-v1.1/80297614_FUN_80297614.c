// Function: FUN_80297614
// Entry: 80297614
// Size: 928 bytes

void FUN_80297614(void)

{
  short *psVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  short *psVar8;
  short *psVar9;
  int iVar10;
  undefined8 uVar11;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float fStack_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c [11];
  
  uVar11 = FUN_8028682c();
  psVar1 = (short *)((ulonglong)uVar11 >> 0x20);
  psVar8 = (short *)uVar11;
  psVar9 = *(short **)(psVar1 + 0x18);
  iVar10 = *(int *)(psVar1 + 0x5c);
  if (psVar9 != psVar8) {
    if (psVar9 == (short *)0x0) {
      local_34 = *(float *)(psVar1 + 6);
      local_30 = *(float *)(psVar1 + 8);
      local_2c[0] = *(float *)(psVar1 + 10);
      local_40 = *(float *)(psVar1 + 0x40);
      local_3c = *(float *)(psVar1 + 0x42);
      local_38 = *(float *)(psVar1 + 0x44);
      local_4c = *(float *)(psVar1 + 0x12);
      local_44 = *(float *)(psVar1 + 0x16);
      iVar2 = (int)*psVar1;
      iVar3 = (int)*(short *)(iVar10 + 0x478);
      iVar4 = (int)*(short *)(iVar10 + 0x484);
      iVar5 = (int)*(short *)(iVar10 + 0x492);
      iVar6 = (int)*(short *)(iVar10 + 0x490);
      iVar7 = *(int *)(iVar10 + 0x494);
      local_58 = *(float *)(iVar10 + 0x118);
      local_54 = *(float *)(iVar10 + 0x11c);
      local_50 = *(float *)(iVar10 + 0x120);
    }
    else {
      FUN_8000e0c0((double)*(float *)(psVar1 + 6),(double)*(float *)(psVar1 + 8),
                   (double)*(float *)(psVar1 + 10),&local_34,&local_30,local_2c,(int)psVar9);
      FUN_8000e0c0((double)*(float *)(psVar1 + 0x40),(double)*(float *)(psVar1 + 0x42),
                   (double)*(float *)(psVar1 + 0x44),&local_40,&local_3c,&local_38,(int)psVar9);
      FUN_8000df3c((double)*(float *)(psVar1 + 0x12),(double)FLOAT_803e8b3c,
                   (double)*(float *)(psVar1 + 0x16),&local_4c,&fStack_48,&local_44,(int)psVar9);
      iVar2 = FUN_8000ded4((int)*psVar1,psVar9);
      iVar3 = FUN_8000ded4((int)*(short *)(iVar10 + 0x478),psVar9);
      iVar4 = FUN_8000ded4((int)*(short *)(iVar10 + 0x484),psVar9);
      iVar5 = FUN_8000ded4((int)*(short *)(iVar10 + 0x492),psVar9);
      iVar6 = FUN_8000ded4((int)*(short *)(iVar10 + 0x490),psVar9);
      iVar7 = FUN_8000ded4(*(int *)(iVar10 + 0x494),psVar9);
      FUN_8000e0c0((double)*(float *)(iVar10 + 0x118),(double)*(float *)(iVar10 + 0x11c),
                   (double)*(float *)(iVar10 + 0x120),&local_58,&local_54,&local_50,(int)psVar9);
    }
    if (psVar8 == (short *)0x0) {
      *(float *)(psVar1 + 6) = local_34;
      *(float *)(psVar1 + 8) = local_30;
      *(float *)(psVar1 + 10) = local_2c[0];
      *(float *)(psVar1 + 0x40) = local_40;
      *(float *)(psVar1 + 0x42) = local_3c;
      *(float *)(psVar1 + 0x44) = local_38;
      *(float *)(psVar1 + 0x12) = local_4c;
      *(float *)(psVar1 + 0x16) = local_44;
      *psVar1 = (short)iVar2;
      *(short *)(iVar10 + 0x478) = (short)iVar3;
      *(short *)(iVar10 + 0x484) = (short)iVar4;
      *(short *)(iVar10 + 0x492) = (short)iVar5;
      *(short *)(iVar10 + 0x490) = (short)iVar6;
      *(int *)(iVar10 + 0x494) = iVar7;
      *(float *)(iVar10 + 0x118) = local_58;
      *(float *)(iVar10 + 0x11c) = local_54;
      *(float *)(iVar10 + 0x120) = local_50;
    }
    else {
      FUN_8000e054((double)local_34,(double)local_30,(double)local_2c[0],(float *)(psVar1 + 6),
                   (float *)(psVar1 + 8),(float *)(psVar1 + 10),(int)psVar8);
      FUN_8000e054((double)local_40,(double)local_3c,(double)local_38,(float *)(psVar1 + 0x40),
                   (float *)(psVar1 + 0x42),(float *)(psVar1 + 0x44),(int)psVar8);
      FUN_8000dfc8((double)local_4c,(double)FLOAT_803e8b3c,(double)local_44,(float *)(psVar1 + 0x12)
                   ,&fStack_48,(float *)(psVar1 + 0x16),(int)psVar8);
      iVar2 = FUN_8000df08(iVar2,psVar8);
      *psVar1 = (short)iVar2;
      iVar2 = FUN_8000df08(iVar3,psVar8);
      *(short *)(iVar10 + 0x478) = (short)iVar2;
      iVar2 = FUN_8000df08(iVar4,psVar8);
      *(short *)(iVar10 + 0x484) = (short)iVar2;
      iVar2 = FUN_8000df08(iVar5,psVar8);
      *(short *)(iVar10 + 0x492) = (short)iVar2;
      iVar2 = FUN_8000df08(iVar6,psVar8);
      *(short *)(iVar10 + 0x490) = (short)iVar2;
      iVar2 = FUN_8000df08(iVar7,psVar8);
      *(int *)(iVar10 + 0x494) = iVar2;
      FUN_8000e054((double)local_58,(double)local_54,(double)local_50,(float *)(iVar10 + 0x118),
                   (float *)(iVar10 + 0x11c),(float *)(iVar10 + 0x120),(int)psVar8);
    }
    *(float *)(psVar1 + 0xc) = local_34;
    *(float *)(psVar1 + 0xe) = local_30;
    *(float *)(psVar1 + 0x10) = local_2c[0];
    *(float *)(psVar1 + 0x46) = local_40;
    *(float *)(psVar1 + 0x48) = local_3c;
    *(float *)(psVar1 + 0x4a) = local_38;
    *(undefined4 *)(*(int *)(psVar1 + 0x2a) + 0x10) = *(undefined4 *)(psVar1 + 6);
    *(undefined4 *)(*(int *)(psVar1 + 0x2a) + 0x14) = *(undefined4 *)(psVar1 + 8);
    *(undefined4 *)(*(int *)(psVar1 + 0x2a) + 0x18) = *(undefined4 *)(psVar1 + 10);
    *(undefined4 *)(*(int *)(psVar1 + 0x2a) + 0x1c) = *(undefined4 *)(psVar1 + 0xc);
    *(undefined4 *)(*(int *)(psVar1 + 0x2a) + 0x20) = *(undefined4 *)(psVar1 + 0xe);
    *(undefined4 *)(*(int *)(psVar1 + 0x2a) + 0x24) = *(undefined4 *)(psVar1 + 0x10);
    *(short **)(psVar1 + 0x18) = psVar8;
  }
  FUN_80286878();
  return;
}

